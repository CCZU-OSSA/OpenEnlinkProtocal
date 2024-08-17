pub mod auth;
pub mod data;
#[cfg(feature = "packet")]
pub use zero_packet as packet;
pub mod protocal;
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
