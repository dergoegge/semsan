use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(ValueEnum, Debug, Clone)]
pub enum Comparator {
    NotEqual,
    Equal,
    LessThan,
    LessThanOrEqual,
    GreaterThan,
    GreaterThanOrEqual,
}
// TODO: Allow custom comparators

#[derive(Subcommand)]
pub enum Command {
    /// Differentially fuzz the primary and secondary harness
    Fuzz(FuzzOptions),
    /// Minimize a solution
    Minimize(MinimizeOptions),
}

#[derive(Args)]
pub struct FuzzOptions {
    #[arg(
        long = "ignore-solutions",
        help = "Keep fuzzing even if a solution has already been found"
    )]
    pub ignore_solutions: bool,

    #[arg(
        long = "foreign-corpus",
        help = "Foreign fuzzer corpus to pull in inputs from"
    )]
    pub foreign_corpus: Option<String>,
    #[arg(
        long = "foreign-sync-interval",
        help = "Interval for syncing the foreign fuzzer corpus (in seconds)",
        default_value_t = 10
    )]
    pub foreign_sync_interval: u64,
    #[arg(
        long = "no-secondary-coverage",
        help = "Don't collect coverage feedback for the secondary executor",
        default_value_t = false
    )]
    pub no_secondary_coverage: bool,
    #[arg(
        long = "run-seeds-once",
        help = "Run through the seeds once and quit",
        default_value_t = false
    )]
    pub run_seeds_once: bool,

    #[arg(long = "seeds", help = "Seed corpus directory", required = true)]
    pub seeds: String,

    #[arg(
        long = "solutions",
        help = "Directory in which solutions (differential finds) will be stored",
        required = true
    )]
    pub solutions: String,
}

#[derive(Args)]
pub struct MinimizeOptions {
    #[arg(help = "Path to the solution to minimize")]
    pub solution: String,
    #[arg(help = "Directory storing minimized solutions")]
    pub solutions: String,
    #[arg(
        long = "iterations",
        help = "Number of iterations to attempt minimization for",
        default_value_t = 128
    )]
    pub iterations: usize,
}

#[derive(Parser)]
pub struct Options {
    #[arg(
        long = "debug-children",
        help = "Redirect the executors' std{out,err} to SemSan's std{out,err}. Useful for debugging solutions and harnesses."
    )]
    pub debug: bool,
    #[arg(
        long = "timeout",
        help = "Maximum amount of time a single input is allowed to run (in milliseconds per executor).",
        default_value_t = 1000
    )]
    pub timeout: u64,
    #[arg(
        long = "comparator",
        help = "Choose differential value comparator function",
        value_enum,
        default_value_t = Comparator::Equal
    )]
    pub comparator: Comparator,
    #[arg(
        long = "solution-exit-code",
        help = "Exit code for solutions",
        default_value_t = 71
    )]
    pub solution_exit_code: u8,
    #[command(subcommand)]
    pub command: Command,
    #[arg(
        help = "Path to the binary of the primary harness to fuzz",
        required = true
    )]
    pub primary: String,
    #[arg(
        help = "Path to the binary of the secondary harness to fuzz",
        required = true
    )]
    pub secondary: String,
}
