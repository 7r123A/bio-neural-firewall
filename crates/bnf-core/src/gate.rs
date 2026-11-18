//! Output-stage abstraction.
//!
//! The stimulator front-end is modelled as a gate whose **default state is
//! open-circuit**. A rejected command does not drive any current into tissue and
//! is not converted into heat: the gate simply stays (or is forced) open.
//!
//! On real hardware, `force_open_circuit` should de-assert the enable line of the
//! analog switch / current DAC *and* this firmware layer should be backed by an
//! independent analog charge limiter (see README, "Defense in depth").

use crate::shannon::ValidatedPulse;

/// Implemented by the board-support layer that drives the stimulator.
pub trait StimulationGate {
    /// Delivers a pulse train that passed every check. Only callable with a
    /// [`ValidatedPulse`], which cannot be constructed outside the limiter.
    fn deliver(&mut self, pulse: &ValidatedPulse);

    /// Puts the output stage into its safe, open-circuit state.
    /// Called at construction, after every rejected command and on session end.
    fn force_open_circuit(&mut self);
}
