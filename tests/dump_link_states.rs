// SPDX-License-Identifier: MIT

use futures::stream::TryStreamExt;

#[test]
fn test_dump_link_states() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();
    rt.block_on(dump_link_states());
}

async fn dump_link_states() {
    let (connection, mut handle, _) = ethtool::new_connection().unwrap();
    tokio::spawn(connection);

    let mut link_states_handle = handle.link_state().get(None).execute().await;

    let mut msgs = Vec::new();
    while let Some(msg) = link_states_handle.try_next().await.unwrap() {
        msgs.push(msg);
    }
    assert!(!msgs.is_empty());
    let ethtool_msg = &msgs[0].payload;
    println!("ethtool_msg {:?}", &ethtool_msg);

    assert!(ethtool_msg.cmd == ethtool::EthtoolCmd::LinkStateGetReply);
    assert!(ethtool_msg.nlas.len() > 1);
}
