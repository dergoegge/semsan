use std::collections::HashSet;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use libafl::{
    corpus::Corpus, fuzzer::Evaluator, fuzzer::ExecuteInputResult, inputs::Input, state::HasCorpus,
};

pub struct CorpusSyncer<I, E, EM, Z, S> {
    evaluated: HashSet<String>,
    last_evaluated: Option<Instant>,
    interval: Duration,

    phantom: PhantomData<(I, E, EM, Z, S)>,
}

impl<I, E, EM, Z, S> CorpusSyncer<I, E, EM, Z, S>
where
    I: Input,
    S: HasCorpus<I>,
    Z: Evaluator<E, EM, I, S>,
{
    pub fn new(interval: Duration) -> Self {
        Self {
            evaluated: HashSet::new(),
            last_evaluated: None,
            interval,
            phantom: PhantomData::default(),
        }
    }

    pub fn sync(
        &mut self,
        state: &mut S,
        evaluator: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        from: &[PathBuf],
    ) {
        for dir in from {
            self.sync_dir(state, evaluator, executor, manager, dir);
        }
    }

    fn sync_dir(
        &mut self,
        state: &mut S,
        evaluator: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        dir: &PathBuf,
    ) {
        if self
            .last_evaluated
            .map_or(false, |t| Instant::now().duration_since(t) < self.interval)
        {
            return;
        }

        let corpus_size = state.corpus().count();

        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };

        for entry in entries {
            let entry = entry.unwrap();
            let path = entry.path();
            if entry.metadata().map_or(true, |m| !m.is_file())
                || path.file_name().unwrap().to_string_lossy().starts_with(".")
            {
                // Skip if the entry is not a file or if the file name starts with a ".".
                continue;
            }

            if let Ok(input) = I::from_file(&path) {
                if !self.evaluated.insert(input.generate_name(None)) {
                    // Only evaulate new inputs
                    continue;
                }

                // Evaluate the input for corpus inclusion
                match evaluator.evaluate_input(state, executor, manager, &input) {
                    Ok((ExecuteInputResult::None, _)) => {
                        // The input was not interesting but we'll add it to the corpus as "disabled"
                        // anyway, which will prompt libafl to still use it for splice mutations.
                        if self.last_evaluated.is_none() {
                            let _ = evaluator.add_disabled_input(state, input);
                        }
                    }
                    // Stop syncing corpus if solution is found.
                    Ok((ExecuteInputResult::Solution, _)) => break,
                    _ => {}
                }
            }
        }

        let new_inputs = state.corpus().count() - corpus_size;
        if new_inputs > 0 {
            println!("Loaded {} new inputs from corpus dir", new_inputs);
        }

        self.last_evaluated = Some(Instant::now());
    }
}
