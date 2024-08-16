#[derive(Debug, Clone)]
pub struct ServerData {
    pub ip: [u8; 4],
    pub mask: usize,
    pub gateway: Vec<u8>,
    pub dns: String,
    pub wins: String,
}

#[derive(Debug, Clone)]
pub struct GDWData {
    pub gateway: Vec<u8>,
    pub dns: String,
    pub wins: String,
}
