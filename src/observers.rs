use std::borrow::Cow;

use libafl::{
    executors::ExitKind,
    inputs::UsesInput,
    observers::{DifferentialObserver, Observer, ObserversTuple},
};
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
        self.shmem.as_mut().unwrap().as_slice_mut().fill(0);
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

pub trait TupleObserver {
    fn last_tuple(&self) -> (u64, u64);
}

/// CoarsePathDiversityObserver implements the coarse path diversity metric for differential
/// fuzzing outlined in https://www.cs.columbia.edu/~suman/docs/nezha.pdf.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct CoarsePathDiversityObserver<'a> {
    name: Cow<'static, str>,
    // Tuple holding the number of reached edges for each program (last observed tuple)
    last_tuple: (u64, u64),
    #[serde(skip_serializing, skip_deserializing)]
    edge_maps: Vec<OwnedMutSlice<'a, u8>>,
}

impl<'a> CoarsePathDiversityObserver<'a> {
    pub fn new(name: &'static str, edge_maps: Vec<OwnedMutSlice<'a, u8>>) -> Self {
        Self {
            name: Cow::Borrowed(name),
            last_tuple: (0, 0),
            edge_maps,
        }
    }
}

impl Named for CoarsePathDiversityObserver<'_> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S> Observer<S> for CoarsePathDiversityObserver<'_>
where
    S: UsesInput,
{
    fn pre_exec(
        &mut self,
        _state: &mut S,
        _input: &<S as UsesInput>::Input,
    ) -> Result<(), libafl::prelude::Error> {
        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), libafl_bolts::Error> {
        // TODO does the sum of the edge counters make a difference compared to sum of seen edges?
        self.last_tuple = (
            self.edge_maps[0].as_slice().iter().map(|&c| c as u64).sum(),
            self.edge_maps[1].as_slice().iter().map(|&c| c as u64).sum(),
        );
        Ok(())
    }
}

impl TupleObserver for CoarsePathDiversityObserver<'_> {
    fn last_tuple(&self) -> (u64, u64) {
        self.last_tuple.clone()
    }
}

impl<OTA, OTB, S> DifferentialObserver<OTA, OTB, S> for CoarsePathDiversityObserver<'_>
where
    OTA: ObserversTuple<S>,
    OTB: ObserversTuple<S>,
    S: UsesInput,
{
}

/// FinePathDiversityObserver implements the coarse fine path diversity metric for differential
/// fuzzing outlined in https://www.cs.columbia.edu/~suman/docs/nezha.pdf.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct FinePathDiversityObserver<'a> {
    name: Cow<'static, str>,
    // Tuple holding a hash of all edges reached for each program (last observed tuple)
    last_tuple: (u64, u64),
    #[serde(skip_serializing, skip_deserializing)]
    edge_maps: Vec<OwnedMutSlice<'a, u8>>,
}

impl<'a> FinePathDiversityObserver<'a> {
    pub fn new(name: &'static str, edge_maps: Vec<OwnedMutSlice<'a, u8>>) -> Self {
        Self {
            name: Cow::Borrowed(name),
            last_tuple: (0, 0),
            edge_maps,
        }
    }
}

impl Named for FinePathDiversityObserver<'_> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S> Observer<S> for FinePathDiversityObserver<'_>
where
    S: UsesInput,
{
    fn pre_exec(
        &mut self,
        _state: &mut S,
        _input: &<S as UsesInput>::Input,
    ) -> Result<(), libafl::prelude::Error> {
        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), libafl_bolts::Error> {
        // TODO does the sum of the edge counters make a difference compared to sum of seen edges?
        self.last_tuple = (
            libafl_bolts::hash_std(self.edge_maps[0].as_slice()),
            libafl_bolts::hash_std(self.edge_maps[1].as_slice()),
        );
        Ok(())
    }
}

impl TupleObserver for FinePathDiversityObserver<'_> {
    fn last_tuple(&self) -> (u64, u64) {
        self.last_tuple.clone()
    }
}

impl<OTA, OTB, S> DifferentialObserver<OTA, OTB, S> for FinePathDiversityObserver<'_>
where
    OTA: ObserversTuple<S>,
    OTB: ObserversTuple<S>,
    S: UsesInput,
{
}
