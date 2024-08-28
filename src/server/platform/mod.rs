#[cfg(all(windows, feature = "server-tun"))]
pub mod tun_windows;
#[cfg(all(windows, feature = "server-tun"))]
pub use tun_windows as tun;
#[cfg(all(not(windows), feature = "server-tun"))]
pub mod tun;
