pub mod auth;
pub mod data;
pub mod protocal;
#[cfg(feature = "server")]
pub mod server;
pub(crate) mod trust;
#[cfg(test)]
mod test {

    use crate::{auth::AuthorizationStore, protocal::EnlinkProtocal};

    #[tokio::test]
    async fn test_vpn_stablity() {
        let auth = AuthorizationStore::default();

        let vpn = EnlinkProtocal::connect(auth).await.unwrap();
        println!("{:?}", vpn.authorize().await.unwrap());
    }
}
