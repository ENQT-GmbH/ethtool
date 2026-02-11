// SPDX-License-Identifier: MIT

mod attr;
mod get;
mod handle;
mod state;

pub(crate) use attr::parse_link_state_nlas;
pub use attr::EthtoolLinkStateAttr;
pub use get::EthtoolLinkStateGetRequest;
pub use handle::EthtoolLinkStateHandle;
pub use state::{
    EthtoolExtState, EthtoolExtSubstate, EthtoolExtSubstateAutoneg,
    EthtoolExtSubstateBadSignalIntegrity, EthtoolExtSubstateCableIssue,
    EthtoolExtSubstateLinkLogicalMismatch, EthtoolExtSubstateLinkTraining,
    EthtoolExtSubstateModule, EthtoolExtSubstateValue,
};
