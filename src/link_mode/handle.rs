// SPDX-License-Identifier: MIT

use crate::{
    header::EthtoolHeaderFlag, EthtoolHandle, EthtoolLinkModeGetRequest,
};

/// Handle for querying ethtool link mode information.
pub struct EthtoolLinkModeHandle(pub(crate) EthtoolHandle);

impl EthtoolLinkModeHandle {
    /// Creates a new `EthtoolLinkModeHandle` from an `EthtoolHandle`.
    pub fn new(handle: EthtoolHandle) -> Self {
        Self(handle)
    }

    /// Retrieves the ethtool link modes (duplex, link speed, etc.) for an
    /// interface.
    ///
    /// Returns a request containing advertised and peer modes including full
    /// mode names.
    pub fn get(
        &mut self,
        iface_name: Option<&str>,
    ) -> EthtoolLinkModeGetRequest {
        EthtoolLinkModeGetRequest::new(self.0.clone(), iface_name, &[])
    }

    /// Retrieves the ethtool link modes (duplex, link speed, etc.) for an
    /// interface in compact form.
    ///
    /// Returns a request containing supported, advertised and peer modes
    /// excluding full names.
    pub fn get_compact(
        &mut self,
        iface_name: Option<&str>,
    ) -> EthtoolLinkModeGetRequest {
        EthtoolLinkModeGetRequest::new(
            self.0.clone(),
            iface_name,
            &[EthtoolHeaderFlag::CompactBitsets],
        )
    }
}
