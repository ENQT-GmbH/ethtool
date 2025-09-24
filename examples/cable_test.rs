// SPDX-License-Identifier: MIT

use std::{env, time::Duration};

use anyhow::{Context, Result};
use ethtool::{EthtoolCmd, EthtoolMessage};
use futures::{StreamExt, TryStreamExt};
use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, ParseableParametrized, NLM_F_REQUEST,
};
use netlink_packet_generic::{
    ctrl::{
        nlas::{GenlCtrlAttrs, McastGrpAttrs},
        GenlCtrl, GenlCtrlCmd,
    },
    GenlFamily, GenlMessage,
};
use netlink_sys::AsyncSocket;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        usage();
        return Ok(());
    }
    let link_name = &args[1];
    cable_test(link_name).await?;
    Ok(())
}

async fn cable_test(iface_name: &str) -> Result<()> {
    // Obtain the multicast group ID for "monitor"
    let multicast_id = get_multicast_id().await?;
    println!("Found Monitor Multicast Group with ID: {multicast_id}");

    // Set up a new ethtool netlink connection and subscribe to the multicast
    // group
    let (mut connection, mut handle, mut messages) = ethtool::new_connection()?;
    let socket = connection.socket_mut().socket_mut();
    socket.bind_auto()?;
    socket.add_membership(multicast_id)?;
    tokio::spawn(connection);

    // Start a cable test every 5 seconds
    let iface = iface_name.to_string();
    tokio::spawn(async move {
        loop {
            let _ = handle.cable_test().action(&iface).execute().await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    // Process incoming netlink messages, filtering for cable test notifications
    while let Some((msg, _)) = messages.next().await {
        if let NetlinkPayload::InnerMessage(inner) = &msg.payload {
            let ethtool_msg =
                EthtoolMessage::parse_with_param(&inner.payload, inner.header)?;

            if ethtool_msg.cmd == EthtoolCmd::CableTestNotify {
                println!("{ethtool_msg:?}");
            }
        }
    }

    Ok(())
}

async fn get_multicast_id() -> Result<u32> {
    let (connection, mut ethtool, _) = ethtool::new_connection()?;
    let _ = tokio::spawn(connection);

    // Build netlink control message.
    let mut msg: NetlinkMessage<_> = GenlMessage::from_payload(GenlCtrl {
        cmd: GenlCtrlCmd::GetFamily,
        nlas: vec![GenlCtrlAttrs::FamilyName(
            EthtoolMessage::family_name().to_owned(),
        )],
    })
    .into();

    msg.header.message_type =
        ethtool.handle.resolve_family_id::<EthtoolMessage>().await?;
    msg.header.flags = NLM_F_REQUEST;

    // Receive response form control message request.
    let responses = ethtool.handle.request(msg).await?;

    let monitor_id = responses.try_filter_map(async move |response| {
        // Only care about generic messages with inner messages.
        let NetlinkPayload::InnerMessage(gen) = &response.payload else {
            return Ok(None);
        };

        // Check for ethtool family in the nals.
        let has_ethtool_family = gen.payload.nlas.iter().any(|nla| {
            matches!(nla, GenlCtrlAttrs::FamilyName(name) if name == EthtoolMessage::family_name())
        });

        // Only care about NewFamily announcements.
        if !has_ethtool_family || gen.payload.cmd != GenlCtrlCmd::NewFamily {
            return Ok(None);
        }

        // Extract id on groups where name is "monitor".
        let id = gen.payload.nlas.iter().find_map(|nla| {
            let GenlCtrlAttrs::McastGroups(groups) = nla else {
                return None;
            };

            groups.iter().find_map(|group| {
                let mut id: Option<u32> = None;
                let mut name: Option<&str> = None;

                for a in group {
                    match a {
                        McastGrpAttrs::Id(v) => id = Some(*v),
                        McastGrpAttrs::Name(n) => name = Some(n.as_str()),
                    }
                }

                (name == Some("monitor")).then_some(id?).or(None)
            })
        });

        Ok(id)
    })
    .try_collect::<Vec<_>>()
    .await?
    .into_iter()
    .next()
    .context("ethtool multicast monitor id not found")?;

    Ok(monitor_id)
}

fn usage() {
    eprintln!(
        "Usage:
    cargo run --example cable_test -- <link_name>

Note: This program requires root privileges. It is recommended to build the example first:

    cd ethtool
    cargo build --example cable_test

Then run the binary with sudo:

    cd target/debug/examples
    sudo ./cable_test <link_name>"
    );
}
