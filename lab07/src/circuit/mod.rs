pub mod utils;
pub mod gates;

#[macro_export]
macro_rules! circuit_debug_log {
    ($($arg:tt)*) => {
        #[cfg(any(test, debug_assertions))]
        println!("[\x1b[33mCIRCUIT_DEBUG\x1b[0m] {}", format!($($arg)*));
    }
}