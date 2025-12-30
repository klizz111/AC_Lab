pub mod ot_receiver;
pub use ot_receiver::OtReceiver;
pub mod ot_sender;
pub use ot_sender::OtSender;
mod utils;
pub use utils::{xor_bytes};

pub(crate) mod common {
    pub use serde_json::json;
    
    pub use crate::network::{Network, tokio::net::TcpStream};
}

#[macro_export]
macro_rules! ot_debug_log {
    ($($arg:tt)*) => {
        #[cfg(any(test, debug_assertions))]
        println!("[\x1b[33mOT_DEBUG\x1b[0m] {}", format!($($arg)*));
    }
}