use std::borrow::Cow;
use std::collections::HashSet;

use libafl::{
    events::EventFirer, executors::ExitKind, feedbacks::Feedback, observers::ObserversTuple,
    state::State, Error,
};
use libafl_bolts::Named;

use crate::observers::TupleObserver;

pub struct UniqueTupleFeedback<O>
where
    O: TupleObserver,
{
    name: Cow<'static, str>,
    observed_tuples: HashSet<(u64, u64)>, // TODO this should be metadata on the state

    p: std::marker::PhantomData<O>,
}

impl<O> UniqueTupleFeedback<O>
where
    O: TupleObserver + Named,
{
    pub fn new(tuple_observer: &O) -> Self {
        Self {
            name: tuple_observer.name().clone(),
            observed_tuples: HashSet::new(),
            p: std::marker::PhantomData::default(),
        }
    }
}

impl<O> Named for UniqueTupleFeedback<O>
where
    O: TupleObserver,
{
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S, O> Feedback<S> for UniqueTupleFeedback<O>
where
    S: State,
    O: TupleObserver,
{
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        let interesting = self
            .observed_tuples
            .insert(observers.match_name::<O>(&self.name).unwrap().last_tuple());

        if interesting {
            println!(
                "{:?}",
                observers.match_name::<O>(&self.name).unwrap().last_tuple()
            );
        }

        Ok(interesting)
    }
}
