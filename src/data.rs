#[derive(Debug, Clone)]
pub struct ServerData {
    pub ip: [u8; 4],
    pub mask: usize,
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
