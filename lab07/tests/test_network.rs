use lab07::network::Network;
use tokio::{net::{TcpListener, TcpStream}};
use serde_json::{json, Value};

#[tokio::test]
async fn test_network_communication() {
    // 1. Setup a TCP Listener (Server side)
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // 2. setup client 
    let stream = TcpStream::connect(addr).await.unwrap();
    let mut client = Network::new(stream);

    let data = json!({
        "user": "test",
        "vec": [1, 2, 3, 4, 5]
    });

    // 3. setup server
    let handler = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut network = Network::new(stream);

        let data = network.receive().await.unwrap();
        println!("Server received: {}", data);

        let v: Value = serde_json::from_str(&data).unwrap();
        println!("{}, {}, {}", v["user"], v["vec"][0], v["vec"][4]);

        network.send(&v).await.unwrap();
    });

    // 4. send and receive
    client.send(&data).await.unwrap();
    let response = client.receive().await.unwrap();
    println!("Client received: {}", response);

    let res: Value = serde_json::from_str(&response).unwrap();
    assert_eq!(res["user"], data["user"]);

    handler.await.unwrap();
}