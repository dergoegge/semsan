mod corpus_syncer;
#[macro_use]
mod dlsym;
mod observers;
mod options;

use clap::Parser;

use std::collections::HashMap;
use std::path::PathBuf;
use std::ptr::NonNull;
use std::time::Duration;

use libafl::{
    corpus::{Corpus, HasTestcase, InMemoryCorpus, OnDiskCorpus, Testcase},
    events::{ProgressReporter, SimpleEventManager},
    executors::{DiffExecutor, ExitKind, ForkserverExecutor},
    feedback_and, feedback_and_fast, feedback_not, feedback_or,
    feedbacks::{
        differential::{DiffFeedback, DiffResult},
        ConstFeedback, DiffExitKindFeedback, MaxMapFeedback,
    },
    inputs::{BytesInput, HasMutatorBytes, HasTargetBytes, Input},
    monitors::SimplePrintingMonitor,
    mutators::{
        havoc_mutations, havoc_mutations_no_crossover, StdMOptMutator, StdScheduledMutator,
    },
    observers::{
        CanTrack, ConstMapObserver, HitcountsIterableMapObserver, MultiMapObserver, StdMapObserver,
    },
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
    AsSlice,
};
#[cfg(feature = "qemu")]
use libafl_qemu::{
    elf::EasyElf, modules::edges::StdEdgeCoverageClassicModule, ArchExtras, CallingConvention,
    Emulator, GuestAddr, GuestReg, MmapPerms, Qemu, QemuForkExecutor, Regs,
};
#[cfg(feature = "qemu")]
use libafl_targets::EDGES_MAP_PTR;

use corpus_syncer::CorpusSyncer;
use dlsym::DlSym;
use observers::ShMemDifferentialValueObserver;
use options::{Command, Comparator, Options};

const CHARACTERIZATION_SHMEM_ID_ENV: &str = "SEMSAN_CHARACTERIZATION_SHMEM_ID";
const MAX_CHARACTERIZATION_SHMEM_SIZE: usize = 32;
const MAX_INPUT_SIZE: usize = 1_048_576;

#[cfg(feature = "qemu")]
fn setup_qemu(entry: &str, emu: &Qemu) -> (GuestReg, GuestAddr, GuestAddr, GuestAddr) {
    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(emu.binary_path(), &mut elf_buffer).unwrap();

    let test_one_input_ptr = elf
        .resolve_symbol(entry, emu.load_addr())
        .expect(&format!("Symbol {} not found", entry));

    // Emulate until `LLVMFuzzerTestOneInput` is hit
    emu.entry_break(test_one_input_ptr);

    let pc: GuestReg = emu.read_reg(Regs::Pc).unwrap();
    let stack_ptr: GuestAddr = emu.read_reg(Regs::Sp).unwrap();
    let ret_addr: GuestAddr = emu.read_return_address().unwrap();

    emu.set_breakpoint(ret_addr);

    let input_addr = emu
        .map_private(0, MAX_INPUT_SIZE, MmapPerms::ReadWrite)
        .unwrap();

    (pc, stack_ptr, ret_addr, input_addr)
}

fn main() -> std::process::ExitCode {
    let opts = Options::parse();

    const MAX_MAP_SIZE: usize = 2_621_440;
    #[cfg(feature = "qemu")]
    const QEMU_MAP_SIZE: usize = 65_535;

    std::env::set_var("AFL_MAP_SIZE", format!("{}", MAX_MAP_SIZE));

    let mut shmem_provider = UnixShMemProvider::new().unwrap();

    // Create the shared memory that the fuzz harnesses write their execution output to. The output
    // is used as "differential value" to compare program semantics.
    let mut diff_value_shmem = shmem_provider
        .new_shmem(MAX_CHARACTERIZATION_SHMEM_SIZE)
        .unwrap();
    diff_value_shmem
        .write_to_env(CHARACTERIZATION_SHMEM_ID_ENV)
        .unwrap();

    // Create a differential value observer for each executor.
    let primary_diff_value_observer =
        ShMemDifferentialValueObserver::new("diff-observer-1", unsafe {
            OwnedMutSlice::from_raw_parts_mut(
                diff_value_shmem.as_mut_ptr_of().unwrap(),
                MAX_CHARACTERIZATION_SHMEM_SIZE,
            )
        });
    let secondary_diff_value_observer =
        ShMemDifferentialValueObserver::new("diff-observer-2", unsafe {
            OwnedMutSlice::from_raw_parts_mut(
                diff_value_shmem.as_mut_ptr_of().unwrap(),
                MAX_CHARACTERIZATION_SHMEM_SIZE,
            )
        });

    let mut primary_args = opts.primary_args.clone();
    let mut secondary_args = opts.secondary_args.clone();

    primary_args.extend(opts.shared_args.clone());
    secondary_args.extend(opts.shared_args.clone());

    dlsym! { fn semsan_custom_comparator(*const u8, usize, *const u8, usize) -> bool }
    let custom_comparator = semsan_custom_comparator.get();

    let compare_fn: Box<dyn Fn(&[u8], &[u8]) -> bool> = match opts.comparator {
        // Targets behave the same if the outputs are not equal
        Comparator::NotEqual => Box::new(|output1: &[u8], output2: &[u8]| output1 != output2),
        // Targets behave the same if the outputs are equal
        Comparator::Equal => Box::new(|output1: &[u8], output2: &[u8]| output1 == output2),
        // Targets behave the same if the primary output is less than the secondary output
        Comparator::LessThan => Box::new(|output1: &[u8], output2: &[u8]| output1 < output2),
        // Targets behave the same if the primary output is less than or equal to the secondary output
        Comparator::LessThanOrEqual => {
            Box::new(|output1: &[u8], output2: &[u8]| output1 <= output2)
        }
        // Targets behave the same if the primary output is greater than the secondary output
        Comparator::GreaterThan => Box::new(|output1: &[u8], output2: &[u8]| output1 > output2),
        // Targets behave the same if the primary output is greater than or equal to the secondary output
        Comparator::GreaterThanOrEqual => {
            Box::new(|output1: &[u8], output2: &[u8]| output1 >= output2)
        }
        // Call out to the user defined custom comparator
        Comparator::Custom => Box::new(|output1: &[u8], output2: &[u8]| unsafe {
            custom_comparator
                .as_ref()
                .expect("Custom comparator needs to LD_PRELOADed!")(
                output1.as_ptr(),
                output1.len(),
                output2.as_ptr(),
                output2.len(),
            )
        }),
    };

    // Both observers are combined into a `DiffFeedback` that compares the retrieved values from
    // the two observers described above.
    let compare_characterization_values =
        |o1: &ShMemDifferentialValueObserver, o2: &ShMemDifferentialValueObserver| {
            if opts.debug {
                println!(
                    "Observed characterization values: v1={:?} v2={:?}",
                    o1.last_value(),
                    o2.last_value()
                );
            }

            if compare_fn(o1.last_value(), o2.last_value()) {
                DiffResult::Equal
            } else {
                eprintln!("== ERROR: Semantic Difference");
                eprintln!("primary  : {:?}", o1.last_value());
                eprintln!("secondary: {:?}", o2.last_value());

                use std::env::consts::{ARCH, FAMILY, OS};
                eprintln!("Host: {}-{}-{}", OS, FAMILY, ARCH);

                #[cfg(feature = "qemu")]
                eprintln!(
                    "Executed '{}' against '{}' (emulated)",
                    &opts.primary, &opts.secondary
                );
                #[cfg(not(feature = "qemu"))]
                eprintln!("Executed '{}' against '{}'", &opts.primary, &opts.secondary);

                DiffResult::Diff
            }
        };

    let mut objective = feedback_or!(
        feedback_and_fast!(
            ConstFeedback::new(opts.ignore_exit_kind),
            // Only report differences in the characterization value as behavioral differences.
            feedback_and!(
                feedback_not!(DiffExitKindFeedback::new()),
                DiffFeedback::new(
                    "diff-value-feedback-0",
                    &primary_diff_value_observer,
                    &secondary_diff_value_observer,
                    compare_characterization_values,
                )
                .unwrap()
            )
        ),
        feedback_and_fast!(
            ConstFeedback::new(!opts.ignore_exit_kind),
            // Report differences in exit kind or differences in the characterization value as
            // behavioral differences.
            feedback_or!(
                DiffExitKindFeedback::new(),
                DiffFeedback::new(
                    "diff-value-feedback-1",
                    &primary_diff_value_observer,
                    &secondary_diff_value_observer,
                    compare_characterization_values,
                )
                .unwrap()
            )
        )
    );

    let mut primary_coverage_shmem = shmem_provider.new_shmem(MAX_MAP_SIZE).unwrap();
    let mut secondary_coverage_shmem = shmem_provider.new_shmem(MAX_MAP_SIZE).unwrap();
    let (primary_edges, secondary_edges) = {
        (
            (
                primary_coverage_shmem.as_mut_ptr_of().unwrap(),
                primary_coverage_shmem.len(),
            ),
            (
                secondary_coverage_shmem.as_mut_ptr_of().unwrap(),
                secondary_coverage_shmem.len(),
            ),
        )
    };

    // Create a coverage map observer for each executor
    let primary_map_observer =
        unsafe { StdMapObserver::from_mut_ptr("cov-observer-1", primary_edges.0, primary_edges.1) };
    #[cfg(not(feature = "qemu"))]
    let secondary_map_observer = unsafe {
        StdMapObserver::from_mut_ptr("cov-observer-2", secondary_edges.0, secondary_edges.1)
    };
    #[cfg(feature = "qemu")]
    let mut secondary_map_observer = unsafe {
        ConstMapObserver::from_mut_ptr(
            "cov-observer-2",
            NonNull::new(secondary_edges.0)
                .expect("secondary map ptr is null.")
                .cast::<[u8; QEMU_MAP_SIZE]>(),
        )
    };

    #[cfg(feature = "qemu")]
    unsafe {
        EDGES_MAP_PTR = secondary_edges.0
    };

    let primary_executor = ForkserverExecutor::builder()
        .program(PathBuf::from(&opts.primary))
        .args(&primary_args)
        .debug_child(opts.debug_children)
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

    #[cfg(not(feature = "qemu"))]
    let secondary_executor = ForkserverExecutor::builder()
        .program(PathBuf::from(&opts.secondary))
        .args(&secondary_args)
        .debug_child(opts.debug_children)
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

    #[cfg(feature = "qemu")]
    let (emulator, qemu) = {
        let modules = tuple_list!(StdEdgeCoverageClassicModule::builder()
            .const_map_observer(secondary_map_observer.as_mut())
            .build()
            .unwrap(),);

        std::env::remove_var("LD_LIBRARY_PATH");
        let mut qemu_args = vec![String::from("semsan"), String::from(&opts.secondary)];
        qemu_args.extend(secondary_args);

        let emu = Emulator::empty()
            .qemu_parameters(qemu_args)
            .modules(modules)
            .build()
            .unwrap();
        let qemu = emu.qemu();

        (emu, qemu)
    };

    #[cfg(feature = "qemu")]
    let (pc, stack_ptr, ret_addr, input_addr) = setup_qemu(&opts.qemu_entry, &qemu);

    #[cfg(feature = "qemu")]
    if opts.debug {
        println!(
            "Successfully setup qemu: pc={:?} stack_ptr={:?} ret_addr={:?} input_addr={:?}",
            pc, stack_ptr, ret_addr, input_addr
        );
    }

    #[cfg(feature = "qemu")]
    let mut secondary_qemu_harness = |_emulator: &mut Emulator<_, _, _, _, _, _, _>,
                                      input: &BytesInput| {
        let target = input.target_bytes();
        let mut buf = target.as_slice();
        let mut len = buf.len();
        if len > MAX_INPUT_SIZE {
            buf = &buf[0..MAX_INPUT_SIZE];
            len = MAX_INPUT_SIZE;
        }

        let len = len as GuestReg;

        qemu.write_mem(input_addr, buf).unwrap();
        qemu.write_reg(Regs::Pc, pc).unwrap();
        qemu.write_reg(Regs::Sp, stack_ptr).unwrap();
        qemu.write_return_address(ret_addr).unwrap();
        qemu.write_function_argument(CallingConvention::Cdecl, 0, input_addr)
            .unwrap();
        qemu.write_function_argument(CallingConvention::Cdecl, 1, len)
            .unwrap();

        unsafe {
            let _ = qemu.run();
        }

        ExitKind::Ok
    };

    match &opts.command {
        Command::Fuzz(fuzz_opts) => {
            let mut coverage_maps: Vec<OwnedMutSlice<'_, u8>> = unsafe {
                vec![
                    OwnedMutSlice::from_raw_parts_mut(primary_edges.0, primary_edges.1),
                    OwnedMutSlice::from_raw_parts_mut(secondary_edges.0, secondary_edges.1),
                ]
            };

            // Resize the coverage maps according to the dynamic map size determined by the executors
            coverage_maps[0].truncate(primary_executor.coverage_map_size().unwrap());
            println!(
                "Truncated primary coverage map to {} bytes",
                coverage_maps[0].len()
            );

            #[cfg(feature = "qemu")]
            if !fuzz_opts.no_secondary_coverage {
                coverage_maps[1].truncate(QEMU_MAP_SIZE);
            };
            #[cfg(not(feature = "qemu"))]
            if !fuzz_opts.no_secondary_coverage {
                coverage_maps[1].truncate(secondary_executor.coverage_map_size().unwrap());
            };

            if fuzz_opts.no_secondary_coverage {
                println!("Ignoring coverage feedback for the secondary executor!");
                coverage_maps[1].truncate(0);
            } else {
                println!(
                    "Truncated secondary coverage map to {} bytes",
                    coverage_maps[1].len()
                );
            }

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
                PowerQueueScheduler::new(&mut state, &diff_map_observer, PowerSchedule::fast()),
            );
            let mut fuzzer = StdFuzzer::new(scheduler, coverage_feedback, objective);

            let mut mgr = SimpleEventManager::new(SimplePrintingMonitor::new());

            #[cfg(feature = "qemu")]
            let secondary_executor = QemuForkExecutor::new(
                emulator,
                &mut secondary_qemu_harness,
                tuple_list!(secondary_map_observer, secondary_diff_value_observer),
                &mut fuzzer,
                &mut state,
                &mut mgr,
                shmem_provider,
                Duration::from_millis(opts.timeout),
            )
            .unwrap();

            // Combine the primary and secondary executor into a `DiffExecutor`.
            let mut executor = DiffExecutor::new(
                primary_executor,
                secondary_executor,
                tuple_list!(diff_map_observer),
            );

            let mut corpus_syncer =
                CorpusSyncer::new(Duration::from_secs(fuzz_opts.foreign_sync_interval));

            corpus_syncer.sync(
                &mut state,
                &mut fuzzer,
                &mut executor,
                &mut mgr,
                &[PathBuf::from(&fuzz_opts.seeds)],
            );

            println!("Loaded {} initial inputs", state.corpus().count());

            if !fuzz_opts.ignore_solutions && state.solutions().count() != 0 {
                // Solution found during initial loading of the seed corpus.
                return std::process::ExitCode::from(opts.solution_exit_code);
            }
            if fuzz_opts.run_seeds_once {
                return std::process::ExitCode::SUCCESS;
            }

            let mutator = StdMOptMutator::new(&mut state, havoc_mutations(), 7, 5).unwrap();

            let power_mut_stage: StdPowerMutationalStage<_, _, BytesInput, _, _, _> =
                StdPowerMutationalStage::new(mutator);
            let mut stages = tuple_list!(calibration_stage, power_mut_stage);

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
                    eprintln!("EXIT: semantic difference found");
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

            let mut fuzzer = StdFuzzer::new(QueueScheduler::new(), (), ());

            let mut mgr = SimpleEventManager::new(SimplePrintingMonitor::new());

            #[cfg(feature = "qemu")]
            let secondary_executor = QemuForkExecutor::new(
                emulator,
                &mut secondary_qemu_harness,
                tuple_list!(secondary_map_observer, secondary_diff_value_observer),
                &mut fuzzer,
                &mut state,
                &mut mgr,
                shmem_provider,
                Duration::from_millis(opts.timeout),
            )
            .unwrap();

            // Combine the primary and secondary executor into a `DiffExecutor`.
            let mut executor =
                DiffExecutor::new(primary_executor, secondary_executor, tuple_list!());

            let input = BytesInput::from_file(PathBuf::from(&min_opts.solution)).unwrap();
            let size = input.target_bytes().len();
            let readable_id = input.generate_name(None);

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
                .target_bytes()
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
