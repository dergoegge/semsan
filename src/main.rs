mod corpus_syncer;
mod observers;
mod options;

use clap::Parser;

use std::path::PathBuf;
use std::time::Duration;

use libafl::{
    corpus::{Corpus, HasTestcase, InMemoryCorpus, OnDiskCorpus, Testcase},
    events::{ProgressReporter, SimpleEventManager},
    executors::{DiffExecutor, ForkserverExecutor},
    feedbacks::{
        differential::{DiffFeedback, DiffResult},
        MaxMapFeedback,
    },
    inputs::{BytesInput, HasMutatorBytes, Input},
    monitors::SimplePrintingMonitor,
    mutators::{
        havoc_mutations, havoc_mutations_no_crossover, StdMOptMutator, StdScheduledMutator,
    },
    observers::{CanTrack, HitcountsIterableMapObserver, MultiMapObserver, StdMapObserver},
    schedulers::{
        powersched::{PowerQueueScheduler, PowerSchedule},
        IndexesLenTimeMinimizerScheduler, QueueScheduler,
    },
    stages::{CalibrationStage, StdPowerMutationalStage, StdTMinMutationalStage},
    state::{HasCorpus, HasSolutions, StdState},
    Fuzzer, StdFuzzer,
};
use libafl_bolts::{
    ownedref::OwnedMutSlice,
    rands::StdRand,
    shmem::{ShMem, ShMemProvider, UnixShMemProvider},
    tuples::tuple_list,
};

use corpus_syncer::CorpusSyncer;
use observers::ShMemDifferentialValueObserver;
use options::{Command, Comparator, Options};

const CHARATERIZATION_SHMEM_ID_ENV: &str = "SEMSAN_CHARATERIZATION_SHMEM_ID";
const MAX_CHARATERIZATION_SHMEM_SIZE: usize = 32;

fn main() -> std::process::ExitCode {
    let opts = Options::parse();

    const MAX_MAP_SIZE: usize = 2_621_440;
    std::env::set_var("AFL_MAP_SIZE", format!("{}", MAX_MAP_SIZE));

    let mut shmem_provider = UnixShMemProvider::new().unwrap();

    // Create the shared memory that the fuzz harnesses write their execution output to. The output
    // is used as "differential value" to compare program semantics.
    let mut diff_value_shmem = shmem_provider
        .new_shmem(MAX_CHARATERIZATION_SHMEM_SIZE)
        .unwrap();
    diff_value_shmem
        .write_to_env(CHARATERIZATION_SHMEM_ID_ENV)
        .unwrap();

    // Create a differential value observer for each executor.
    let primary_diff_value_observer =
        ShMemDifferentialValueObserver::new("diff-observer-1", unsafe {
            OwnedMutSlice::from_raw_parts_mut(
                diff_value_shmem.as_mut_ptr_of().unwrap(),
                MAX_CHARATERIZATION_SHMEM_SIZE,
            )
        });
    let secondary_diff_value_observer =
        ShMemDifferentialValueObserver::new("diff-observer-2", unsafe {
            OwnedMutSlice::from_raw_parts_mut(
                diff_value_shmem.as_mut_ptr_of().unwrap(),
                MAX_CHARATERIZATION_SHMEM_SIZE,
            )
        });

    let compare_fn = match opts.comparator {
        // Targets behave the same if the outputs are not equal
        Comparator::NotEqual => |output1: &[u8], output2: &[u8]| output1 != output2,
        // Targets behave the same if the outputs are equal
        Comparator::Equal => |output1: &[u8], output2: &[u8]| output1 == output2,
        // Targets behave the same if the primary output is less than the secondary output
        Comparator::LessThan => |output1: &[u8], output2: &[u8]| output1 < output2,
        // Targets behave the same if the primary output is less than or equal to the secondary output
        Comparator::LessThanOrEqual => |output1: &[u8], output2: &[u8]| output1 <= output2,
        // Targets behave the same if the primary output is greater than the secondary output
        Comparator::GreaterThan => |output1: &[u8], output2: &[u8]| output1 > output2,
        // Targets behave the same if the primary output is greater than or equal to the secondary output
        Comparator::GreaterThanOrEqual => |output1: &[u8], output2: &[u8]| output1 >= output2,
    };

    // Both observers are combined into a `DiffFeedback` that compares the retrieved values from
    // the two observers described above.
    let mut objective = DiffFeedback::new(
        "diff-value-feedback",
        &primary_diff_value_observer,
        &secondary_diff_value_observer,
        |o1, o2| {
            if compare_fn(o1.last_value(), o2.last_value()) {
                DiffResult::Equal
            } else {
                eprintln!("== ERROR: Semantic Difference");
                eprintln!("primary  : {:?}", o1.last_value());
                eprintln!("secondary: {:?}", o2.last_value());

                DiffResult::Diff
            }
        },
    )
    .unwrap();

    let mut primary_coverage_shmem = shmem_provider.new_shmem(MAX_MAP_SIZE).unwrap();
    let mut secondary_coverage_shmem = shmem_provider.new_shmem(MAX_MAP_SIZE).unwrap();
    let mut coverage_maps: Vec<OwnedMutSlice<'_, u8>> = unsafe {
        vec![
            OwnedMutSlice::from_raw_parts_mut(
                primary_coverage_shmem.as_mut_ptr_of().unwrap(),
                primary_coverage_shmem.len(),
            ),
            OwnedMutSlice::from_raw_parts_mut(
                secondary_coverage_shmem.as_mut_ptr_of().unwrap(),
                secondary_coverage_shmem.len(),
            ),
        ]
    };

    // Create a coverage map observer for each executor
    let primary_map_observer =
        StdMapObserver::from_mut_slice("cov-observer-1", coverage_maps[0].clone());
    let secondary_map_observer =
        StdMapObserver::from_mut_slice("cov-observer-2", coverage_maps[1].clone());

    let primary_executor = ForkserverExecutor::builder()
        .program(PathBuf::from(&opts.primary))
        .debug_child(opts.debug)
        .shmem_provider(&mut shmem_provider)
        .coverage_map_size(MAX_MAP_SIZE)
        .timeout(Duration::from_millis(opts.timeout))
        .env("__AFL_SHM_ID", primary_coverage_shmem.id().to_string())
        .env(
            "__AFL_SHM_ID_SIZE",
            primary_coverage_shmem.len().to_string(),
        )
        .env(
            "LD_PRELOAD",
            std::env::var("SEMSAN_PRIMARY_LD_PRELOAD").unwrap_or(String::new()),
        )
        .is_persistent(true)
        .build_dynamic_map(
            primary_map_observer,
            tuple_list!(primary_diff_value_observer),
        )
        .unwrap();

    let secondary_executor = ForkserverExecutor::builder()
        .program(PathBuf::from(&opts.secondary))
        .debug_child(opts.debug)
        .shmem_provider(&mut shmem_provider)
        .coverage_map_size(MAX_MAP_SIZE)
        .timeout(Duration::from_millis(opts.timeout))
        .env("__AFL_SHM_ID", secondary_coverage_shmem.id().to_string())
        .env(
            "__AFL_SHM_ID_SIZE",
            secondary_coverage_shmem.len().to_string(),
        )
        .env(
            "LD_PRELOAD",
            std::env::var("SEMSAN_SECONDARY_LD_PRELOAD").unwrap_or(String::new()),
        )
        .is_persistent(true)
        .build_dynamic_map(
            secondary_map_observer,
            tuple_list!(secondary_diff_value_observer),
        )
        .unwrap();

    match &opts.command {
        Command::Fuzz(fuzz_opts) => {
            // Resize the coverage maps according to the dynamic map size determined by the executors
            coverage_maps[0].truncate(primary_executor.coverage_map_size().unwrap());

            let secondary_map_size = if fuzz_opts.no_secondary_coverage {
                0
            } else {
                secondary_executor.coverage_map_size().unwrap()
            };
            coverage_maps[1].truncate(secondary_map_size);

            // Combine both coverage maps as feedback
            let diff_map_observer = HitcountsIterableMapObserver::new(
                MultiMapObserver::differential("combined-coverage", coverage_maps),
            )
            .track_indices();
            let mut coverage_feedback = MaxMapFeedback::new(&diff_map_observer);

            let calibration_stage = CalibrationStage::new(&coverage_feedback);

            let mut state = StdState::new(
                StdRand::with_seed(libafl_bolts::current_nanos()),
                InMemoryCorpus::<BytesInput>::new(),
                OnDiskCorpus::new(PathBuf::from(&fuzz_opts.solutions)).unwrap(),
                &mut coverage_feedback,
                &mut objective,
            )
            .unwrap();

            let scheduler = IndexesLenTimeMinimizerScheduler::new(
                &diff_map_observer,
                PowerQueueScheduler::new(&mut state, &diff_map_observer, PowerSchedule::FAST),
            );
            let mut fuzzer = StdFuzzer::new(scheduler, coverage_feedback, objective);

            // Combine the primary and secondary executor into a `DiffExecutor`.
            let mut executor = DiffExecutor::new(
                primary_executor,
                secondary_executor,
                tuple_list!(diff_map_observer),
            );

            let mut corpus_syncer =
                CorpusSyncer::new(Duration::from_secs(fuzz_opts.foreign_sync_interval));

            let mut mgr = SimpleEventManager::new(SimplePrintingMonitor::new());
            corpus_syncer.sync(
                &mut state,
                &mut fuzzer,
                &mut executor,
                &mut mgr,
                &[PathBuf::from(&fuzz_opts.seeds)],
            );

            println!("Loaded {} initial inputs", state.corpus().count());

            let mutator = StdMOptMutator::new(&mut state, havoc_mutations(), 7, 5).unwrap();

            let mut stages = tuple_list!(calibration_stage, StdPowerMutationalStage::new(mutator));

            loop {
                mgr.maybe_report_progress(&mut state, std::time::Duration::from_secs(15))
                    .unwrap();
                fuzzer
                    .fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)
                    .expect("Error in the fuzzing loop");

                if let Some(foreign_corpus) = fuzz_opts.foreign_corpus.as_ref() {
                    corpus_syncer.sync(
                        &mut state,
                        &mut fuzzer,
                        &mut executor,
                        &mut mgr,
                        &[PathBuf::from(foreign_corpus)],
                    );
                }

                if !fuzz_opts.ignore_solutions && state.solutions().count() != 0 {
                    return std::process::ExitCode::from(opts.solution_exit_code);
                }
            }
        }

        Command::Minimize(min_opts) => {
            let mut state = StdState::new(
                StdRand::with_seed(libafl_bolts::current_nanos()),
                InMemoryCorpus::<BytesInput>::new(),
                // Only supplied to make rust's type system happy, ideally this would just be a
                // in-memory corpus. Minimized test cases are written to disk manually, see below.
                OnDiskCorpus::new(PathBuf::from(&min_opts.solutions)).unwrap(),
                &mut (),
                &mut (),
            )
            .unwrap();

            // Combine the primary and secondary executor into a `DiffExecutor`.
            let mut executor =
                DiffExecutor::new(primary_executor, secondary_executor, tuple_list!());

            let mut fuzzer = StdFuzzer::new(QueueScheduler::new(), (), ());

            let mut mgr = SimpleEventManager::new(SimplePrintingMonitor::new());

            let input = BytesInput::from_file(PathBuf::from(&min_opts.solution)).unwrap();
            let size = input.bytes().len();
            let readable_id = input.generate_name(0);

            let id = state.corpus_mut().add(Testcase::new(input)).unwrap();

            let mutator = StdScheduledMutator::new(havoc_mutations_no_crossover());
            let tmin = StdTMinMutationalStage::new(mutator, objective, min_opts.iterations);

            let mut stages = tuple_list!(tmin);
            fuzzer
                .fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)
                .unwrap();

            let mut testcase = state.testcase_mut(id).unwrap();
            let input = testcase
                .load_input(state.corpus())
                .unwrap()
                .bytes()
                .to_vec();
            drop(testcase);

            if input.len() >= size {
                eprintln!("Unable to reduce {}", min_opts.solution.as_str());
            } else {
                let dest = PathBuf::from(&min_opts.solutions)
                    .join(format!("minimized-from-{}", readable_id));

                std::fs::write(&dest, input).unwrap();
                println!(
                    "Wrote minimized input to {}",
                    dest.file_name().unwrap().to_str().unwrap()
                );
            }

            std::process::ExitCode::SUCCESS
        }
    }
}
