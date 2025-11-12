// SPDX-License-Identifier: MIT

mod attr;
mod get;
mod handle;
mod mode;

pub(crate) use attr::parse_link_mode_nlas;
pub use attr::{
    EthtoolLinkModeAttr, EthtoolLinkModeBitset, EthtoolLinkModeCompactBit,
    EthtoolLinkModeDuplex, EthtoolLinkModeRateMatching, EthtoolLinkModeSpeed,
    EthtoolLinkModeVerboseBit,
};
pub use get::EthtoolLinkModeGetRequest;
pub use handle::EthtoolLinkModeHandle;
pub use mode::EthtoolLinkMode;
