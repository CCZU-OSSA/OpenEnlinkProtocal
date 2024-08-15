use std::sync::Arc;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};
use tokio_rustls::{client::TlsStream, rustls::ClientConfig, TlsConnector};

use crate::{auth::Authorization, trust::NoVerification};

#[derive(Debug, Clone)]
pub struct EnlinkVpn<A: Authorization> {
    pub authorization: A,
    pub stream: Arc<Mutex<TlsStream<TcpStream>>>,
}

impl<A: Authorization> EnlinkVpn<A> {
    // Write
    pub async fn connect(authorization: A) -> tokio::io::Result<Self> {
        let config = Arc::new(
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerification {}))
                .with_no_client_auth(),
        );
        let addr = format!("{}:{}", authorization.host(), authorization.port());

        let connector = TlsConnector::from(config);
        let tcpstream = TcpStream::connect(addr).await?;
        let stream = connector
            .connect(authorization.host().try_into().unwrap(), tcpstream)
            .await?;

        Ok(Self {
            authorization,
            stream: Arc::new(Mutex::new(stream)),
        })
    }

    pub async fn authorize(&self) -> tokio::io::Result<()> {
        let mut stream = self.stream.lock().await;
        let token = self.authorization.token();
        let bytes_token = token.as_bytes();
        let user = self.authorization.user();
        let bytes_user = user.as_bytes();
        // Version
        stream.write_u8(1).await?;
        // Protocal
        stream.write_u8(1).await?;
        // Length
        stream
            .write_u16(19 + bytes_user.len() as u16 + bytes_token.len() as u16)
            .await?;
        stream
            .write(&[
                0, 0, 0, 0, // Zero
                1, 0, 0, 0, // ELK_METHOD_STUN
                1, 0, // ELK_OPT_USERNAME
            ])
            .await?;
        // User
        stream.write_u8(bytes_user.len() as u8).await?;
        stream.write(bytes_user).await?;
        // ELK_OPT_SESSID
        stream.write(&[2, 0]).await?;

        // Token
        stream.write_u8(bytes_token.len() as u8).await?;
        stream.write(bytes_token).await?;
        // -1 & 0xff

        stream.write_u8(255).await?;

        stream.flush().await?;
        Ok(())
    }

    pub async fn heartbeat(&self) -> tokio::io::Result<()> {
        let mut stream = self.stream.lock().await;

        stream.write(&[1, 1, 0, 12, 0, 0, 0, 0, 3, 0, 0, 0]).await?;
        stream.flush().await?;
        Ok(())
    }

    pub async fn write_tcp(&self, data: &[u8], read: i16) -> tokio::io::Result<()> {
        let mut stream = self.stream.lock().await;
        // Custom header
        stream.write(&[1, 4]).await?;
        // Length
        stream.write_i16(read + 12).await?;
        // XID
        stream.write(&[0, 0, 0, 0]).await?;
        stream.write_i32(1).await?;
        // Data
        stream.write(data).await?;
        stream.write_u8(0).await?;
        stream.write_i16(read).await?;
        stream.flush().await?;
        Ok(())
    }

    // Read
    pub async fn is_authorize_ok(&self) -> tokio::io::Result<bool> {
        let mut stream = self.stream.lock().await;
        // Skip 10
        stream.read_exact(&mut [0u8; 10]).await?;

        let mut status = vec![0, 0];
        stream.read_exact(&mut status).await?;
        Ok(status[0] == 0 && status[1] == 0)
    }

    pub async fn virtual_address(&self) -> tokio::io::Result<Vec<u32>> {
        let mut status = [0u8; 3];
        self.stream.lock().await.read_exact(&mut status).await?;
        println!("{:?}", status);

        if status[0] == 11 && status[1] == 0 && status[2] == 4 {
            let mut virtual_address = [0u8; 16];
            self.stream
                .lock()
                .await
                .read_exact(&mut virtual_address)
                .await?;
            println!("{:?}", virtual_address);
            return Ok((0..4)
                .map(|index| {
                    u32::from_le_bytes([
                        virtual_address[index],
                        virtual_address[index + 1],
                        virtual_address[index + 2],
                        virtual_address[index + 3],
                    ])
                })
                .collect());
        }
        Err(tokio::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid Received Data",
        ))
    }
}
