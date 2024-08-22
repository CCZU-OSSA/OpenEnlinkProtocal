pub trait Authorization {
    fn user(&self) -> String;
    fn token(&self) -> String;
    fn host(&self) -> String;
    fn dns(&self) -> Vec<[u8; 4]>;
    fn port(&self) -> u32;
}

#[derive(Debug, Clone, Default)]
pub struct AuthorizationStore {
    pub user: String,
    pub token: String,
    pub host: String,
    pub dns: Vec<[u8; 4]>,
    pub port: u32,
}

impl AuthorizationStore {
    pub fn new(
        user: impl Into<String>,
        token: impl Into<String>,
        host: impl Into<String>,
        dns: Vec<[u8; 4]>,

        port: u32,
    ) -> Self {
        Self {
            user: user.into(),
            token: token.into(),
            host: host.into(),
            dns,
            port,
        }
    }
}

impl Authorization for AuthorizationStore {
    fn user(&self) -> String {
        self.user.clone()
    }

    fn token(&self) -> String {
        self.token.clone()
    }

    fn host(&self) -> String {
        self.host.clone()
    }

    fn port(&self) -> u32 {
        self.port
    }

    fn dns(&self) -> Vec<[u8; 4]> {
        self.dns.clone()
    }
}
