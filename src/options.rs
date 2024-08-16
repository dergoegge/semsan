use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(ValueEnum, Debug, Clone)]
pub enum Comparator {
    NotEqual,
    Equal,
    LessThan,
    LessThanOrEqual,
    GreaterThan,
    GreaterThanOrEqual,
    Custom,
}

#[derive(ValueEnum, Debug, Clone)]
pub enum Feedback {
    Coarse,
    Fine,
    Coverage,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Differentially fuzz the primary and secondary harness
    Fuzz(FuzzOptions),
    /// Minimize a solution
    Minimize(MinimizeOptions),
}

#[derive(Debug, Args)]
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

    #[arg(
        long = "feedback",
        help = "Choose feedback mechanism",
        value_enum,
        default_value_t = Feedback::Coverage
    )]
    pub feedback: Feedback,

    #[arg(long = "seeds", help = "Seed corpus directory", required = true)]
    pub seeds: String,

    #[arg(
        long = "solutions",
        help = "Directory in which solutions (differential finds) will be stored",
        required = true
    )]
    pub solutions: String,
}

#[derive(Debug, Args)]
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

#[derive(Parser, Debug)]
pub struct Options {
    #[arg(
        long = "debug",
        help = "Print various things that help with debugging SemSan itself."
    )]
    pub debug: bool,
    #[arg(
        long = "debug-children",
        help = "Redirect the executors' std{out,err} to SemSan's std{out,err}. Useful for debugging solutions and harnesses."
    )]
    pub debug_children: bool,
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
    #[cfg(feature = "qemu")]
    #[arg(
        long = "qemu-entry",
        help = "Symbol for the qemu entry breakpoint",
        default_value = "LLVMFuzzerTestOneInput"
    )]
    pub qemu_entry: String,

    // TODO: ' ' as delimiter won't work for all programs, e.g. "--foobar="bla bla" --opt" should
    // be parsed as ["--foobar="bla bla", "--opt"] but with only space as the delim it'll be parsed
    // as ["--foobar=\"bla", "bla\"", "--opt"].
    #[arg(
        long = "primary-args",
        help = "Arguments to pass to the primary harness",
        value_delimiter = ' '
    )]
    pub primary_args: Vec<String>,
    #[arg(
        long = "secondary-args",
        help = "Arguments to pass to the secondary harness",
        value_delimiter = ' '
    )]
    pub secondary_args: Vec<String>,
    #[arg(
        long = "args",
        help = "Arguments to pass to both harnesses",
        value_delimiter = ' '
    )]
    pub shared_args: Vec<String>,

    #[arg(
        long = "ignore-exit-kind",
        help = "Don't report differences in exit kind (e.g. crashes or timeouts) as behavioral differences",
        default_value_t = false
    )]
    pub ignore_exit_kind: bool,

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
