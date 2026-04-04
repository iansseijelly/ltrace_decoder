use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use rusqlite::Connection;

/// Per-BB aggregation: (count, sum_delta, min_delta)
struct BbAgg {
    count: u64,
    sum: u64,
    min: u64,
}

/// Flattened result row: (count, mean, netvar, total, bb_start, bb_end)
type BbRow = (u64, f64, u64, u64, u64, u64);

fn write_csv(path: &Path, rows: &[BbRow]) -> Result<()> {
    let mut f = File::create(path)
        .with_context(|| format!("Failed to create: {}", path.display()))?;
    writeln!(f, "count,mean,netvar,total,bb")?;
    for &(count, mean, netvar, total, bb_start, bb_end) in rows {
        writeln!(f, "{count},{mean:.1},{netvar},{total},{bb_start:#x}-{bb_end:#x}")?;
    }
    Ok(())
}

pub fn run(db_path: &str, outdir: &str, prv: Option<i64>, ctx: Option<i64>, limit: Option<usize>) -> Result<()> {
    fs::create_dir_all(outdir)
        .with_context(|| format!("Failed to create output directory: {outdir}"))?;
    let outdir = Path::new(outdir);

    let conn = Connection::open(db_path)
        .with_context(|| format!("Failed to open database: {db_path}"))?;

    let sql_where = "event_type NOT IN ('SYNC_START', 'SYNC_END')";

    // Get total row count for progress bar
    let total_rows: u64 = conn
        .query_row(&format!("SELECT COUNT(*) FROM events WHERE {sql_where}"), [], |r| r.get(0))?;

    let pb = ProgressBar::new(total_rows);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40}] {pos}/{len} ({per_sec}, ETA {eta})")?
            .progress_chars("=> "),
    );

    let query = format!(
        "SELECT timestamp, from_addr, to_addr, prv, ctx FROM events WHERE {sql_where} ORDER BY id"
    );
    let mut stmt = conn.prepare(&query)?;

    let mut bb_agg: HashMap<(u64, u64), BbAgg> = HashMap::new();
    let mut prev_ts: Option<i64> = None;
    let mut prev_to: u64 = 0;
    let mut prev_matches = false;
    let mut row_idx: u64 = 0;
    let pb_step = (total_rows / 100).max(1);

    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let timestamp: i64 = row.get(0)?;
        let from_addr = row.get::<_, i64>(1)? as u64;
        let to_addr = row.get::<_, i64>(2)? as u64;
        let row_prv: i64 = row.get(3)?;
        let row_ctx: i64 = row.get(4)?;

        let curr_matches =
            prv.map_or(true, |p| row_prv == p) && ctx.map_or(true, |c| row_ctx == c);

        if let Some(pt) = prev_ts {
            if prev_matches && curr_matches {
                let delta = (timestamp - pt) as u64;
                let key = (prev_to, from_addr);
                let agg = bb_agg.entry(key).or_insert(BbAgg {
                    count: 0,
                    sum: 0,
                    min: u64::MAX,
                });
                agg.count += 1;
                agg.sum += delta;
                if delta < agg.min {
                    agg.min = delta;
                }
            }
        }

        prev_ts = Some(timestamp);
        prev_to = to_addr;
        prev_matches = curr_matches;

        row_idx += 1;
        if row_idx % pb_step == 0 {
            pb.set_position(row_idx);
        }
    }
    pb.finish_and_clear();

    // Build full results: (count, mean, netvar, total, bb_start, bb_end)
    let mut results: Vec<BbRow> = bb_agg
        .iter()
        .map(|(&(bb_start, bb_end), agg)| {
            let mean = agg.sum as f64 / agg.count as f64;
            let netvar = agg.sum - agg.min * agg.count;
            (agg.count, mean, netvar, agg.sum, bb_start, bb_end)
        })
        .collect();

    // Summary stats (computed from all BBs, before limit)
    let total_cycles: u64 = results.iter().map(|r| r.3).sum();
    let total_netvar: u64 = results.iter().map(|r| r.2).sum();
    let total_events: u64 = results.iter().map(|r| r.0).sum();
    let unique_bbs = results.len();

    // 1. Top by netvar
    results.sort_by(|a, b| b.2.cmp(&a.2));
    let top_by_netvar: Vec<BbRow> = results.iter().copied().take(limit.unwrap_or(results.len())).collect();
    let netvar_path = outdir.join("top_by_netvar.csv");
    write_csv(&netvar_path, &top_by_netvar)?;
    eprintln!("Written {} rows to {}", top_by_netvar.len(), netvar_path.display());

    // 2. Top by total time
    results.sort_by(|a, b| b.3.cmp(&a.3));
    let top_by_total: Vec<BbRow> = results.iter().copied().take(limit.unwrap_or(results.len())).collect();
    let total_path = outdir.join("top_by_total.csv");
    write_csv(&total_path, &top_by_total)?;
    eprintln!("Written {} rows to {}", top_by_total.len(), total_path.display());

    // 3. Summary txt
    let summary_path = outdir.join("summary.txt");
    let mut sf = File::create(&summary_path)
        .with_context(|| format!("Failed to create: {}", summary_path.display()))?;

    writeln!(sf, "{}", "=".repeat(60))?;
    writeln!(sf, "BB Stats Summary")?;
    writeln!(sf, "{}", "=".repeat(60))?;
    writeln!(sf, "  Database:         {db_path}")?;
    writeln!(sf, "  Filters:          prv={} ctx={}",
        prv.map_or("any".to_string(), |v| v.to_string()),
        ctx.map_or("any".to_string(), |v| v.to_string()),
    )?;
    writeln!(sf, "  Events scanned:   {total_rows}")?;
    writeln!(sf, "  Unique BBs:       {unique_bbs}")?;
    writeln!(sf, "  Matched events:   {total_events}")?;
    writeln!(sf, "  Total cycles:     {total_cycles}")?;
    writeln!(sf, "  Total netvar:     {total_netvar}")?;
    if let Some(top) = top_by_netvar.first() {
        writeln!(sf,
            "  Top BB by netvar: {:#x}-{:#x} (netvar={}, count={}, mean={:.1})",
            top.4, top.5, top.2, top.0, top.1
        )?;
        let top10_netvar: u64 = top_by_netvar.iter().take(10).map(|r| r.2).sum();
        if total_netvar > 0 {
            writeln!(sf,
                "  Top 10 netvar:    {top10_netvar} ({:.1}% of total netvar, {:.1}% of total cycles)",
                top10_netvar as f64 / total_netvar as f64 * 100.0,
                top10_netvar as f64 / total_cycles as f64 * 100.0
            )?;
        }
    }
    if let Some(top) = top_by_total.first() {
        writeln!(sf,
            "  Top BB by total:  {:#x}-{:#x} (total={}, count={}, mean={:.1})",
            top.4, top.5, top.3, top.0, top.1
        )?;
        let top10_total: u64 = top_by_total.iter().take(10).map(|r| r.3).sum();
        if total_cycles > 0 {
            writeln!(sf,
                "  Top 10 total:     {top10_total} ({:.1}% of total)",
                top10_total as f64 / total_cycles as f64 * 100.0
            )?;
        }
    }
    writeln!(sf, "{}", "=".repeat(60))?;

    // Also print summary to stderr
    let summary = std::fs::read_to_string(&summary_path)?;
    eprint!("{summary}");
    eprintln!("Written summary to {}", summary_path.display());

    Ok(())
}
