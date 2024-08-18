use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{ReadHalf, WriteHalf},
        TcpListener, TcpStream,
    },
};

use crate::{auth::Authorization, protocal::EnlinkProtocal};

pub async fn launch_tcp_server(
    authorization: impl Authorization + Clone + Send + Sync + 'static,
    port: usize,
) -> tokio::io::Result<()> {
    let proxy = EnlinkProtocal::connect(authorization).await?;
    let listener = TcpListener::bind(format!("127.0.0.1:{port}")).await?;
    proxy.authorize().await?;
    loop {
        if let Ok((client, addr)) = listener.accept().await {
            println!("Connect from {addr}.");
            tokio::spawn(forward(proxy.clone(), client));
        }
    }
}

async fn send_client_proxy<'a, A: Authorization + Clone>(
    proxy: EnlinkProtocal<A>,
    mut reader: ReadHalf<'a>,
) -> tokio::io::Result<()> {
    loop {
        let mut data = [0u8; 2048];
        let offset = reader.read(&mut data).await?;

        if offset > 0 {
            println!("Read {offset} Length from client, send to proxy...");
            proxy.write_tcp_offset(&data, offset).await?;
        }
    }
}

async fn send_proxy_client<'a, A: Authorization + Clone>(
    proxy: EnlinkProtocal<A>,
    mut writer: WriteHalf<'a>,
) -> tokio::io::Result<()> {
    loop {
        let mut data = [0u8; 8];

        let mut guard = proxy.reader.lock().await;

        let offset = guard.read(&mut data).await?;
        if offset > 0 {
            println!("Read {offset} Length from proxy, send to client...");
            writer.write(&data.split_at(offset).0).await.unwrap();
        }
    }
}
async fn forward<A: Authorization + Clone>(proxy: EnlinkProtocal<A>, mut client: TcpStream) {
    let (reader, writer) = client.split();

    let (a, b) = tokio::join!(
        send_client_proxy(proxy.clone(), reader),
        send_proxy_client(proxy, writer)
    );
    a.unwrap();
    b.unwrap();
}
