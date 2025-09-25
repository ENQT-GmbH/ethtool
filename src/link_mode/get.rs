// SPDX-License-Identifier: MIT

use futures::TryStream;
use netlink_packet_generic::GenlMessage;

use crate::{
    ethtool_execute, header::EthtoolHeaderFlags, EthtoolError, EthtoolHandle,
    EthtoolMessage,
};

pub struct EthtoolLinkModeGetRequest {
    handle: EthtoolHandle,
    iface_name: Option<String>,
    flags: Option<EthtoolHeaderFlags>,
}

impl EthtoolLinkModeGetRequest {
    pub(crate) fn new(
        handle: EthtoolHandle,
        iface_name: Option<&str>,
        flags: Option<EthtoolHeaderFlags>,
    ) -> Self {
        EthtoolLinkModeGetRequest {
            handle,
            iface_name: iface_name.map(|i| i.to_string()),
            flags,
        }
    }

    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<EthtoolMessage>, Error = EthtoolError>
    {
        let EthtoolLinkModeGetRequest {
            mut handle,
            iface_name,
            flags,
        } = self;

        let ethtool_msg =
            EthtoolMessage::new_link_mode_get(iface_name.as_deref(), flags);

        let dump = iface_name.is_none();
        ethtool_execute(&mut handle, dump, ethtool_msg).await
    }
}
