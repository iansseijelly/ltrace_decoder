use std::collections::HashMap;

use anyhow::{Context, Result};
use rusqlite::Connection;

pub fn run(db_path: &str) -> Result<()> {
    let conn = Connection::open(db_path)
        .with_context(|| format!("Failed to open database: {db_path}"))?;

    let total_rows: u64 = conn
        .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
    eprintln!("Total events: {total_rows}");

    let mut errors = 0u64;

    // 1. Check for duplicate SYNC_START (sign of appended data from re-runs)
    {
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, from_addr, ctx FROM events WHERE event_type = 'SYNC_START' ORDER BY id"
        )?;
        let sync_starts: Vec<(i64, i64, i64, i64)> = stmt
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        eprintln!("\n[check] SYNC_START events: {}", sync_starts.len());
        if sync_starts.len() > 1 {
            // Look for duplicates (same timestamp + from_addr + ctx)
            let mut seen: HashMap<(i64, i64, i64), Vec<i64>> = HashMap::new();
            for &(id, ts, addr, ctx) in &sync_starts {
                seen.entry((ts, addr, ctx)).or_default().push(id);
            }
            for ((ts, addr, ctx), ids) in &seen {
                if ids.len() > 1 {
                    eprintln!(
                        "  ERROR: duplicate SYNC_START (timestamp={ts}, pc={:#x}, ctx={ctx}) at ids: {ids:?}",
                        *addr as u64
                    );
                    eprintln!("    -> likely caused by appending to an existing DB without clearing it first");
                    errors += 1;
                }
            }
        }
        for &(id, ts, addr, ctx) in &sync_starts {
            eprintln!("  id={id} timestamp={ts} pc={:#x} ctx={ctx}", addr as u64);
        }
    }

    // 2. Check for non-monotonic timestamps within the same context
    {
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, ctx FROM events \
             WHERE event_type NOT IN ('SYNC_START', 'SYNC_END') \
             ORDER BY id"
        )?;
        let mut rows = stmt.query([])?;

        // Track prev timestamp per context
        let mut prev_ts_by_ctx: HashMap<i64, (i64, i64)> = HashMap::new(); // ctx -> (prev_id, prev_ts)
        let mut non_mono_count = 0u64;
        let mut non_mono_examples: Vec<String> = Vec::new();

        while let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?;
            let ts: i64 = row.get(1)?;
            let ctx: i64 = row.get(2)?;

            if let Some(&(prev_id, prev_ts)) = prev_ts_by_ctx.get(&ctx) {
                if ts < prev_ts {
                    non_mono_count += 1;
                    if non_mono_examples.len() < 5 {
                        non_mono_examples.push(format!(
                            "ctx={ctx}: id {prev_id} (ts={prev_ts}) -> id {id} (ts={ts}), delta={}",
                            ts - prev_ts
                        ));
                    }
                }
            }
            prev_ts_by_ctx.insert(ctx, (id, ts));
        }

        eprintln!("\n[check] Non-monotonic timestamps (per context): {non_mono_count}");
        if non_mono_count > 0 {
            errors += non_mono_count;
            for ex in &non_mono_examples {
                eprintln!("  ERROR: {ex}");
            }
            if non_mono_count > non_mono_examples.len() as u64 {
                eprintln!("  ... and {} more", non_mono_count - non_mono_examples.len() as u64);
            }
        }
    }

    // 3. Summary of contexts
    {
        let mut stmt = conn.prepare(
            "SELECT ctx, COUNT(*) FROM events \
             WHERE event_type NOT IN ('SYNC_START', 'SYNC_END') \
             GROUP BY ctx ORDER BY COUNT(*) DESC"
        )?;
        let ctx_counts: Vec<(i64, u64)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        eprintln!("\n[check] Contexts ({} total):", ctx_counts.len());
        for &(ctx, count) in &ctx_counts {
            eprintln!("  ctx={ctx}: {count} events");
        }
    }

    // Final verdict
    eprintln!();
    if errors == 0 {
        eprintln!("OK: no issues found in {db_path}");
    } else {
        eprintln!("FAIL: {errors} issue(s) found in {db_path}");
    }

    Ok(())
}
