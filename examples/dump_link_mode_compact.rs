// SPDX-License-Identifier: MIT

use anyhow::Result;
use futures::stream::TryStreamExt;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    get_link_mode_compact(None).await?;
    Ok(())
}

async fn get_link_mode_compact(iface_name: Option<&str>) -> Result<()> {
    let (connection, mut handle, _) = ethtool::new_connection()?;
    tokio::spawn(connection);

    let mut stream = handle.link_mode().get_compact(iface_name).execute().await;

    let mut msgs = Vec::new();
    while let Some(msg) = stream.try_next().await.unwrap() {
        msgs.push(msg);
    }
    assert!(!msgs.is_empty());
    for msg in msgs {
        println!("{msg:#?}")
    }

    Ok(())
}
