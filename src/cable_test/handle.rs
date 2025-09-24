// SPDX-License-Identifier: MIT

use crate::{EthtoolCableTestActionRequest, EthtoolHandle};

pub struct EthtoolCableTestHandle(EthtoolHandle);

impl EthtoolCableTestHandle {
    pub fn new(handle: EthtoolHandle) -> Self {
        EthtoolCableTestHandle(handle)
    }

    pub fn action(
        &mut self,
        iface_name: &str,
    ) -> EthtoolCableTestActionRequest {
        EthtoolCableTestActionRequest::new(self.0.clone(), iface_name)
    }
}
