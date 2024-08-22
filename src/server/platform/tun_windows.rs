use std::{
    io::{stdin, BufRead},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use wintun::{load_from_path, Session, MAX_RING_CAPACITY};

use crate::{auth::Authorization, protocal::EnlinkProtocal};

static RUNNING: AtomicBool = AtomicBool::new(false);

pub async fn launch_tun_service(
    authorization: impl Authorization + Clone + Send + Sync + 'static,
    dylib: impl AsRef<std::ffi::OsStr>,
) -> tokio::io::Result<()> {
    let tun =
        unsafe { load_from_path(dylib).expect(&format!("Failed to load wintun dynamic lib!")) };
    let adapter = match wintun::Adapter::open(&tun, "EnlinkVPN") {
        Ok(a) => a,
        Err(_) => wintun::Adapter::create(&tun, "EnlinkVPN", "Wintun", None)
            .expect("Failed to create Adapter! Need Permission?"),
    };
    let proxy = EnlinkProtocal::connect(authorization).await?;
    let server = proxy.authorize().await?;
    adapter.set_name("EnlinkVPN")?;
    adapter.set_address(server.ip.into())?;
    adapter.set_dns_servers(&[])?;
    adapter.set_gateway(Some(server.gateway.into()))?;
    let session = Arc::new(adapter.start_session(MAX_RING_CAPACITY)?);

    tokio::spawn(forward_proxy());
    tokio::spawn(forward_client(session.clone()));

    println!("Press `Enter` to Stop Service");
    let _ = stdin().lock().read_line(&mut String::new());
    RUNNING.store(false, Ordering::Relaxed);

    session.shutdown()?;
    Ok(())
}

async fn forward_client(session: Arc<Session>) {
    while RUNNING.load(Ordering::Relaxed) {
        let _packet = session.receive_blocking();
    }
}

async fn forward_proxy() {
    while RUNNING.load(Ordering::Relaxed) {}
}
