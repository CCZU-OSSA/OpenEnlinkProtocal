use std::{
    io::{stdin, BufRead},
    net::IpAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

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
    println!("Set DNS Servers");
    adapter.set_dns_servers(&dns_list)?;

    // Start Session
    println!("Start Session");
    let session = Arc::new(adapter.start_session(MAX_RING_CAPACITY)?);

    tokio::spawn(forward(session.clone()));

    println!("Press `Enter` to Stop Service");
    let _ = stdin().lock().read_line(&mut String::new());
    RUNNING.store(false, Ordering::Relaxed);

    session.shutdown()?;
    Ok(())
}

async fn forward(session: Arc<Session>) {
    while RUNNING.load(Ordering::Relaxed) {
        let incoming = session.receive_blocking();

        if let Ok(packet) = incoming {
            println!("Recv Packet Length {}", packet.bytes().len());

            let mut spacket = session
                .allocate_send_packet(packet.bytes().len() as u16)
                .unwrap();

            spacket.bytes_mut().clone_from_slice(packet.bytes());
            session.send_packet(spacket);
        } else if let Err(msg) = incoming {
            println!("{}", msg);
        }
    }
}
