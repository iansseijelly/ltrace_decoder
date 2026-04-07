mod bb_stats;
mod check;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "trace_db_tools", about = "Tools for analysing SQLite trace DBs")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compute basic-block latency statistics from a trace DB
    BbStats {
        /// Path to SQLite trace DB
        #[arg(long, default_value = "trace.db")]
        db: String,
        /// Output directory for CSVs and summary
        #[arg(long, default_value = "bb_stats_out")]
        outdir: String,
        /// Filter by privilege level (0=user, 1=supervisor, 3=machine)
        #[arg(long)]
        prv: Option<i64>,
        /// Filter by ASID context
        #[arg(long)]
        ctx: Option<i64>,
        /// Limit number of output rows per CSV
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Sanity-check a trace DB for common issues
    Check {
        /// Path to SQLite trace DB
        #[arg(long, default_value = "trace.db")]
        db: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::BbStats {
            db,
            outdir,
            prv,
            ctx,
            limit,
        } => bb_stats::run(&db, &outdir, prv, ctx, limit),
        Commands::Check { db } => check::run(&db),
    }
}
