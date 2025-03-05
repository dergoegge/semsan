use std::borrow::Cow;

use libafl::{executors::ExitKind, observers::Observer};
use libafl_bolts::{ownedref::OwnedMutSlice, AsSlice, AsSliceMut, Named};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ShMemDifferentialValueObserver<'a> {
    name: Cow<'static, str>,
    last_value: Vec<u8>,
    #[serde(skip_serializing, skip_deserializing)]
    shmem: Option<OwnedMutSlice<'a, u8>>,
}

impl<'a> ShMemDifferentialValueObserver<'a> {
    pub fn new(name: &'static str, shmem: OwnedMutSlice<'a, u8>) -> Self {
        Self {
            name: Cow::Borrowed(name),
            last_value: vec![0u8; shmem.as_slice().len()],
            shmem: Some(shmem),
        }
    }

    pub fn last_value(&self) -> &[u8] {
        &self.last_value
    }
}

impl Named for ShMemDifferentialValueObserver<'_> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<I, S> Observer<I, S> for ShMemDifferentialValueObserver<'_> {
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), libafl_bolts::Error> {
        // Reset the differential value before executing the harness
        self.shmem.as_mut().unwrap().as_slice_mut().fill(0);
        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &I,
        _exit_kind: &ExitKind,
    ) -> Result<(), libafl_bolts::Error> {
        // Record the differential value after executing the harness
        self.last_value
            .copy_from_slice(self.shmem.as_ref().unwrap().as_slice());

        Ok(())
    }
}
