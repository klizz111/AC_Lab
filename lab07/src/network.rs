pub use tokio;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use anyhow::Result;
use serde::Serialize;

pub struct Network {
    stream: TcpStream,
}

impl Network{
    pub fn new(stream: TcpStream) -> Self {
        Network { stream }
    }

    pub async fn send<T: Serialize>(&mut self, data: &T) -> Result<()> {
        let serialized = serde_json::to_string(data)?;
        let len = serialized.len() as u32;
        self.stream.write_all(&len.to_be_bytes()).await?;
        self.stream.write_all(serialized.as_bytes()).await?;
        Ok(())
    }

    pub async fn receive(&mut self) -> Result<String> {
        let mut len_buffer = [0u8; 4];
        self.stream.read_exact(&mut len_buffer).await?;
        let len = u32::from_be_bytes(len_buffer) as usize;
        let mut buffer = vec![0u8; len];
        self.stream.read_exact(&mut buffer).await?;
        let data = String::from_utf8(buffer)?;
        Ok(data)
    }
}

#[macro_export]
macro_rules! json_bind {
    ($data:expr => { $($key:ident : $type:ty),+ }) => {{
        let v: serde_json::Value = serde_json::from_str(&$data).expect("Failed to parse JSON");
        (
            $(
                serde_json::from_value::<$type>(v[stringify!($key)].clone())
                    .expect(&format!("Failed to extract field {}", stringify!($key))),
            )+
        )
    }};
}

#[macro_export]
macro_rules! receive_json {
    ($network:expr => { $($key:ident : $type:ty),+ }) => {{
        let data_str = $network.receive().await.expect("Failed to receive data");
        let trim_data_str = data_str.trim_end_matches(char::from(0));
        let v: serde_json::Value = serde_json::from_str(&trim_data_str).expect("Failed to parse JSON");
        (
            $(
                serde_json::from_value::<$type>(v[stringify!($key)].clone())
                    .expect(&format!("Failed to extract field {}", stringify!($key))),
            )+
        )
    }};
}