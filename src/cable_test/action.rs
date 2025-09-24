// SPDX-License-Identifier: MIT

use netlink_packet_core::{NetlinkMessage, NLM_F_ACK, NLM_F_REQUEST};
use netlink_packet_generic::GenlMessage;

use crate::{EthtoolError, EthtoolHandle, EthtoolMessage};

pub struct EthtoolCableTestActionRequest {
    handle: EthtoolHandle,
    message: EthtoolMessage,
}

impl EthtoolCableTestActionRequest {
    pub(crate) fn new(handle: EthtoolHandle, iface_name: &str) -> Self {
        EthtoolCableTestActionRequest {
            handle,
            message: EthtoolMessage::new_cable_test_action(iface_name),
        }
    }

    pub async fn execute(self) -> Result<(), EthtoolError> {
        let EthtoolCableTestActionRequest {
            mut handle,
            message,
        } = self;

        let mut nl_msg =
            NetlinkMessage::from(GenlMessage::from_payload(message));
        nl_msg.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        handle.notify(nl_msg).await
    }
}
