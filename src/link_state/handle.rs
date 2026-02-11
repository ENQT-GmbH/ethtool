// SPDX-License-Identifier: MIT

use crate::{EthtoolHandle, EthtoolLinkStateGetRequest};

pub struct EthtoolLinkStateHandle(EthtoolHandle);

impl EthtoolLinkStateHandle {
    pub fn new(handle: EthtoolHandle) -> Self {
        EthtoolLinkStateHandle(handle)
    }

    /// Retrieve the ethtool link state
    pub fn get(
        &mut self,
        iface_name: Option<&str>,
    ) -> EthtoolLinkStateGetRequest {
        EthtoolLinkStateGetRequest::new(self.0.clone(), iface_name)
    }
}
