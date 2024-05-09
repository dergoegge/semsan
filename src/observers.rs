use libafl::{executors::ExitKind, inputs::UsesInput, observers::Observer};
use libafl_bolts::{ownedref::OwnedMutSlice, AsMutSlice, AsSlice, Named};

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ShMemDifferentialValueObserver<'a> {
    name: String,
    last_value: Vec<u8>,
    #[serde(skip_serializing, skip_deserializing)]
    shmem: Option<OwnedMutSlice<'a, u8>>,
}

impl<'a> ShMemDifferentialValueObserver<'a> {
    pub fn new(name: &str, shmem: OwnedMutSlice<'a, u8>) -> Self {
        Self {
            name: String::from(name),
            last_value: vec![0u8; shmem.as_slice().len()],
            shmem: Some(shmem),
        }
    }

    pub fn last_value(&self) -> &[u8] {
        &self.last_value
    }
}

impl Named for ShMemDifferentialValueObserver<'_> {
    fn name(&self) -> &str {
        &self.name
    }
}

impl<S> Observer<S> for ShMemDifferentialValueObserver<'_>
where
    S: UsesInput,
{
    fn pre_exec(
        &mut self,
        _state: &mut S,
        _input: &<S as UsesInput>::Input,
    ) -> Result<(), libafl::prelude::Error> {
        // Reset the differential value before executing the harness
        self.shmem.as_mut().unwrap().as_mut_slice().fill(0);
        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), libafl_bolts::Error> {
        // Record the differential value after executing the harness
        self.last_value
            .copy_from_slice(self.shmem.as_ref().unwrap().as_slice());

        Ok(())
    }
}
