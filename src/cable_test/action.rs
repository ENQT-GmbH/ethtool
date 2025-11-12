// SPDX-License-Identifier: MIT

use futures::{future::Either, FutureExt, StreamExt, TryStream};
use netlink_packet_core::{NetlinkMessage, NLM_F_ACK, NLM_F_REQUEST};
use netlink_packet_generic::GenlMessage;

use crate::{try_ethtool, EthtoolError, EthtoolHandle, EthtoolMessage};

pub struct EthtoolCableTestActionRequest {
    handle: EthtoolHandle,
    iface_name: String,
}

impl EthtoolCableTestActionRequest {
    pub(crate) fn new(handle: EthtoolHandle, iface_name: &str) -> Self {
        EthtoolCableTestActionRequest {
            handle,
            iface_name: iface_name.to_string(),
        }
    }

    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<EthtoolMessage>, Error = EthtoolError>
    {
        let EthtoolCableTestActionRequest {
            mut handle,
            iface_name,
        } = self;

        let ethtool_msg = EthtoolMessage::new_cable_test_action(&iface_name);
        let mut nl_msg =
            NetlinkMessage::from(GenlMessage::from_payload(ethtool_msg));

        // Use NLM_F_ACK because there is no REPLY for
        // ETHTOOL_MSG_CABLE_TEST_TDR_ACT.
        nl_msg.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        match handle.request(nl_msg).await {
            Ok(response) => {
                Either::Left(response.map(move |msg| Ok(try_ethtool!(msg))))
            }
            Err(e) => {
                Either::Right(
                    futures::future::err::<
                        GenlMessage<EthtoolMessage>,
                        EthtoolError,
                    >(e)
                    .into_stream(),
                )
            }
        }
    }
}
