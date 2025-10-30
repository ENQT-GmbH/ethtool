// SPDX-License-Identifier: MIT

use anyhow::Result;
use ethtool::{EthtoolAttr, EthtoolExtSubstate, EthtoolLinkStateAttr};
use futures::stream::TryStreamExt;
use tokio_util::task::AbortOnDropHandle;

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();
    let _ = rt.block_on(get_link_state(None));
}

async fn get_link_state(iface_name: Option<&str>) -> Result<()> {
    let (connection, mut handle, _) = ethtool::new_connection()?;
    let _task = AbortOnDropHandle::new(tokio::spawn(connection));

    let mut link_state_handle =
        handle.link_state().get(iface_name).execute().await;

    while let Some(msg) = link_state_handle.try_next().await? {
        let mut ext_state = None;
        let mut ext_substate = None;

        for nla in msg.payload.nlas {
            if let EthtoolAttr::LinkState(state) = nla {
                match state {
                    EthtoolLinkStateAttr::Header(v) => {
                        println!("Header: {v:?}")
                    }
                    EthtoolLinkStateAttr::Link(v) => {
                        println!("Link: {v}")
                    }
                    EthtoolLinkStateAttr::Sqi(v) => {
                        println!("SQI: {v}")
                    }
                    EthtoolLinkStateAttr::SqiMax(v) => {
                        println!("SQI Max: {v}")
                    }
                    EthtoolLinkStateAttr::ExtDownCounter(v) => {
                        println!("Down Counter: {v}")
                    }
                    EthtoolLinkStateAttr::ExtState(v) => ext_state = Some(v),
                    EthtoolLinkStateAttr::ExtSubstate(v) => {
                        ext_substate = Some(v)
                    }
                    _ => {}
                }
            }
        }

        // Print extended state and substate if available.
        if let Some(state) = ext_state {
            println!("State: {state:?}");
            if let Some(sub) = ext_substate {
                println!(
                    "Substate: {:?}",
                    EthtoolExtSubstate::from_state_pair(state, sub)
                );
            }
        }

        println!();
    }

    Ok(())
}
