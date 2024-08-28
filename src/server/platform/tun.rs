use crate::{auth::Authorization, protocal::EnlinkProtocal};
use packet::ip::{v4::Packet, Protocol};
use std::{
    io::{stdin, BufRead},
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::{
    io::{split, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::TcpStream,
    sync::Mutex,
};
use tokio_rustls::client::TlsStream;
use tun::{create_as_async, AsyncDevice, Configuration};

static RUNNING: AtomicBool = AtomicBool::new(true);

pub async fn launch_tun_service(
    authorization: impl Authorization + Clone + Send + Sync + 'static,
) -> tokio::io::Result<()> {
    println!("Waiting for Launching Service...");
    let mut configure = Configuration::default();

    let proxy = EnlinkProtocal::connect(authorization.clone()).await?;
    let server = proxy.authorize().await?;
    println!("Server: {:?}", server);
    println!("Set Network Addresses");
    configure
        .address::<Ipv4Addr>(server.address.into())
        .netmask::<Ipv4Addr>(server.mask.into())
        .destination::<Ipv4Addr>(server.gateway.into())
        .up();

    let adapter = create_as_async(&configure).expect("Create Device Failed");

    // Fallback
    // dns_list.push(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    //TODO Add Route here
    //TODO! YOU MUST SET THE DNS SERVER BY YOURSELF
    let (session_read, session_write) = split(adapter);
    // Start Session
    println!("Start Session");
    let writer = proxy.writer.clone();
    let reader = proxy.reader.clone();
    tokio::spawn(forward_writeout(session_write, reader));
    tokio::spawn(forward_readin(session_read, writer));
    println!("Press `Enter` to Stop Service");
    let _ = stdin().lock().read_line(&mut String::new());
    RUNNING.store(false, Ordering::Relaxed);

    Ok(())
}

async fn forward_readin(
    mut session: ReadHalf<AsyncDevice>,
    writer: Arc<Mutex<WriteHalf<TlsStream<TcpStream>>>>,
) {
    while RUNNING.load(Ordering::Relaxed) {
        let mut buf = [0u8; 2048];
        let incoming = session.read(&mut buf).await;

        if let Ok(length) = incoming {
            if let Ok(parsed) = Packet::new(buf) {
                if parsed.protocol() == Protocol::Tcp {
                    println!("Received {}", length);
                    let mut data = vec![];
                    // TCP
                    data.write(&[1, 4]).await.unwrap();

                    // Length
                    data.write_u16((length + 12) as u16).await.unwrap();

                    // XID
                    data.write(&[0, 0, 0, 0]).await.unwrap();
                    // APP ID
                    data.write_i32(1).await.unwrap();
                    data.write(&buf).await.unwrap();
                    let mut guard = writer.lock().await;
                    guard.write(&data).await.unwrap();
                    guard.flush().await.unwrap();
                }
            }
        } else if let Err(msg) = incoming {
            println!("{}", msg);
        }
    }
}

async fn forward_writeout(
    mut session: WriteHalf<AsyncDevice>,
    reader: Arc<Mutex<ReadHalf<TlsStream<TcpStream>>>>,
) {
    while RUNNING.load(Ordering::Relaxed) {
        let mut buf = [0u8; 8];
        let mut guard = reader.lock().await;
        let incoming = guard.read(&mut buf).await;
        if let Ok(offset) = incoming {
            drop(guard);
            if offset > 0 {
                println!("Read {offset} in Proxy");

                session.write(buf.split_at(offset).0).await.unwrap();
            }
        } else if let Err(_) = incoming {
            drop(guard)
        }
    }
}
