use std::sync::Arc;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{ReadHalf, WriteHalf},
        TcpListener, TcpStream,
    },
    sync::Mutex,
};
use tokio_rustls::client::TlsStream;

use crate::{auth::Authorization, protocal::EnlinkProtocal};

pub async fn launch_http_server(
    authorization: impl Authorization + Clone,
    port: usize,
) -> tokio::io::Result<()> {
    let proxy = EnlinkProtocal::connect(authorization).await?;
    let listener = TcpListener::bind(format!("127.0.0.1:{port}")).await?;
    proxy.authorize().await?;
    loop {
        if let Ok((client, _)) = listener.accept().await {
            tokio::spawn(forward(proxy.stream.clone(), client));
        }
    }
}
async fn send_client_proxy<'a>(proxy: Arc<Mutex<TlsStream<TcpStream>>>, mut reader: ReadHalf<'a>) {
    loop {
        let mut data = [0u8; 2048];

        if reader.read(&mut data).await.unwrap() > 0 {
            let mut guard = proxy.lock().await;
            // May panic, so drop Mutex here
            // ! TODO Need Complete
            guard.write(&data).await.map_err(|_| drop(guard)).unwrap();
        }
    }
}

async fn send_proxy_client<'a>(proxy: Arc<Mutex<TlsStream<TcpStream>>>, mut writer: WriteHalf<'a>) {
    loop {
        let mut data = [0u8; 8];

        let mut guard = proxy.lock().await;
        if guard
            .read(&mut data)
            .await
            .map_err(|_| drop(guard))
            .unwrap()
            > 0
        {
            // ! TODO Need Complete
            writer.write(&data).await.unwrap();
        }
    }
}
async fn forward(proxy: Arc<Mutex<TlsStream<TcpStream>>>, mut client: TcpStream) {
    let (reader, writer) = client.split();

    tokio::join!(
        send_client_proxy(proxy.clone(), reader),
        send_proxy_client(proxy, writer)
    );
}
