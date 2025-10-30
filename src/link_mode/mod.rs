// SPDX-License-Identifier: MIT

mod attr;
mod get;
mod handle;
mod mode_bit;

pub(crate) use attr::parse_link_mode_nlas;
pub use attr::{
    EthtoolLinkModeAttr, EthtoolLinkModeDuplex, EthtoolLinkModeOurs,
    EthtoolLinkModeOursCompact, EthtoolLinkModeOursVerbose,
    EthtoolLinkModeRateMatching, EthtoolLinkModeSpeed,
};
pub use get::EthtoolLinkModeGetRequest;
pub use handle::EthtoolLinkModeHandle;
pub use mode_bit::EthtoolLinkModeBit;
