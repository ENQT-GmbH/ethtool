// SPDX-License-Identifier: MIT

use futures::stream::TryStreamExt;

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();
    rt.block_on(get_link_state(None));
}

async fn get_link_state(iface_name: Option<&str>) {
    let (connection, mut handle, _) = ethtool::new_connection().unwrap();
    tokio::spawn(connection);

    let mut link_state_handle =
        handle.link_state().get(iface_name).execute().await;

    let mut msgs = Vec::new();
    while let Some(msg) = link_state_handle.try_next().await.unwrap() {
        msgs.push(msg);
    }
    assert!(!msgs.is_empty());
    for msg in msgs {
        println!("{msg:?}");
    }
}
