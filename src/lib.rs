pub mod auth;
pub(crate) mod trust;
pub mod vpn;

#[cfg(test)]
mod test {

    use std::i32;

    use crate::{auth::AuthorizationStore, vpn::EnlinkVpn};

    #[tokio::test]
    async fn test_vpn_stablity() {
        let auth = AuthorizationStore::default();

        let vpn = EnlinkVpn::connect(auth).await.unwrap();
        vpn.authorize().await.unwrap();
        println!("{:?}", vpn.is_authorize_ok().await);
        println!("{:?}", vpn.virtual_address().await);
        println!("{:?}", vpn.virtual_mask().await);
    }

    #[test]
    fn bin_eva() {
        let v: i32 = 267;
        println!("{}", v);
        println!("{:?}", v.to_ne_bytes());
        println!(
            "{} {} {} {}",
            (v >> 24) & 255,
            (v >> 16) & 255,
            (v >> 8) & 255,
            v & 255
        );
    }
}
