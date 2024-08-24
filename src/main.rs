
use open_enlink_protocal::{auth::AuthorizationStore, server::platform::tun::launch_tun_service};

#[tokio::main]
async fn main() {
    launch_tun_service(
        AuthorizationStore::default(),
        "wintun.dll",
    )
    .await
    .unwrap();
}
