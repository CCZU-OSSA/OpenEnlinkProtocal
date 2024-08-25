use std::{
    io::{stdin, BufRead},
    net::IpAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use packet::ip::{v4::Packet, Protocol};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::TcpStream,
    sync::Mutex,
};
use tokio_rustls::client::TlsStream;
use wintun::{load_from_path, Session, MAX_RING_CAPACITY};

use crate::{auth::Authorization, protocal::EnlinkProtocal};

static RUNNING: AtomicBool = AtomicBool::new(true);

pub async fn launch_tun_service(
    authorization: impl Authorization + Clone + Send + Sync + 'static,
    dylib: impl AsRef<std::ffi::OsStr>,
) -> tokio::io::Result<()> {
    println!("Waiting for Launching Service...");
    let tun =
        unsafe { load_from_path(dylib).expect(&format!("Failed to load wintun dynamic lib!")) };
    let adapter = match wintun::Adapter::open(&tun, "EnlinkVPN") {
        Ok(a) => a,
        Err(_) => wintun::Adapter::create(&tun, "EnlinkVPN", "Wintun", None)
            .expect("Failed to create Adapter! Need Permission?"),
    };

    let proxy = EnlinkProtocal::connect(authorization.clone()).await?;
    let server = proxy.authorize().await?;
    println!("Server: {:?}", server);
    println!("Set Network Addresses");
    adapter.set_network_addresses_tuple(
        server.address.into(),
        server.mask.into(),
        Some(server.gateway.into()),
    )?;

    let dns_list: Vec<IpAddr> = authorization
        .dns()
        .into_iter()
        .map(|e| {
            let addr: IpAddr = e.into();
            addr
        })
        .collect();
    // Fallback
    // dns_list.push(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));

    println!("Set DNS Servers");
    adapter.set_dns_servers(&dns_list)?;

    // Start Session
    println!("Start Session");
    let session = Arc::new(adapter.start_session(MAX_RING_CAPACITY)?);
    let writer = proxy.writer.clone();
    let reader = proxy.reader.clone();
    tokio::spawn(forward_writeout(session.clone(), reader));
    tokio::spawn(forward_readin(session.clone(), writer));
    println!("Press `Enter` to Stop Service");
    let _ = stdin().lock().read_line(&mut String::new());
    RUNNING.store(false, Ordering::Relaxed);

    session.shutdown()?;
    Ok(())
}

async fn forward_readin(
    session: Arc<Session>,
    writer: Arc<Mutex<WriteHalf<TlsStream<TcpStream>>>>,
) {
    while RUNNING.load(Ordering::Relaxed) {
        let incoming = session.receive_blocking();

        if let Ok(packet) = incoming {
            if let Ok(parsed) = Packet::new(packet.bytes()) {
                if parsed.protocol() == Protocol::Tcp {
                    println!("Received {parsed:?}");
                    let mut data = vec![];
                    // TCP
                    data.write(&[1, 4]).await.unwrap();

                    // Length
                    data.write_u16((packet.bytes().len() + 12) as u16)
                        .await
                        .unwrap();

                    // XID
                    data.write(&[0, 0, 0, 0]).await.unwrap();

                    // APP ID
                    data.write_i32(1).await.unwrap();
                    data.write(packet.bytes()).await.unwrap();
                    writer.lock().await.write(&data).await.unwrap();
                }
            }
        } else if let Err(msg) = incoming {
            println!("{}", msg);
        }
    }
}

async fn forward_writeout(
    session: Arc<Session>,
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
                let mut packet = session.allocate_send_packet(offset as u16).unwrap();
                packet
                    .bytes_mut()
                    .clone_from_slice(&mut buf.split_at(offset).0);
                session.send_packet(packet);
            }
        } else if let Err(msg) = incoming {
            println!("Failed: {msg}");
            drop(guard)
        }
    }
}
