// SPDX-License-Identifier: MIT

mod attr;
mod get;
mod handle;
mod mode_bit;

pub(crate) use attr::parse_link_mode_nlas;
pub use attr::{
    EthtoolLinkMode, EthtoolLinkModeAttr, EthtoolLinkModeCompact,
    EthtoolLinkModeDuplex, EthtoolLinkModeRateMatching, EthtoolLinkModeSpeed,
    EthtoolLinkModeVerbose,
};
pub use get::EthtoolLinkModeGetRequest;
pub use handle::EthtoolLinkModeHandle;
pub use mode_bit::EthtoolLinkModeBit;
