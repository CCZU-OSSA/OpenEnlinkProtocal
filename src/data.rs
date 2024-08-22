#[derive(Debug, Clone)]
pub struct ServerData {
    pub address: [u8; 4],
    pub mask: [u8; 4],
    pub gateway: [u8; 4],
    pub dns: String,
    pub wins: String,
}

#[derive(Debug, Clone)]
pub struct GDWData {
    pub gateway: [u8; 4],
    pub dns: String,
    pub wins: String,
}
