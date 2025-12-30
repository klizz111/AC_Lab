use lab07::{ot_debug_log, receive_json,simplest_ot::*};
use serde_json::{json};

#[tokio::test]
async fn test_simplest_ot() {
    // Setup a TCP Listener (Server/Sender)
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8888").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // setup client/Receiver
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut receiver = OtReceiver::new_(stream, 1); // choice = 1

    // setup server/Sender
    let handler = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut sender = OtSender::new_(stream);

        let messages = vec![b"Message 0".to_vec(), b"Message 1".to_vec()];
        ot_debug_log!(
            "Sender messages: {:?}, {:?}",
            String::from_utf8_lossy(&messages[0]),
            String::from_utf8_lossy(&messages[1])
        );

        // 1. Get Keys from Receiver
        let (k0, k1) = sender.execute().await;
        ot_debug_log!(
            "Sender derived k0: {:?}",
            String::from_utf8_lossy(&k0)
        );
        ot_debug_log!(
            "Sender derived k1: {:?}",
            String::from_utf8_lossy(&k1)
        );

        // 2. Enc messages
        let c0 = xor_bytes(&messages[0], &k0[0..messages[0].len()]);
        let c1 = xor_bytes(&messages[1], &k1[0..messages[1].len()]);

        // 3. Send Enc messages to Receiver
        let data = json!({
            "c0": c0,
            "c1": c1,
        });
        sender.network.send(&data).await.unwrap();
    });

    // execute receiver/client
    // 1. Get key form ot
    let key = receiver.execute().await;
    ot_debug_log!(
        "Receiver derived key: {:?}",
        String::from_utf8_lossy(&key)
    );

    // 2. Receive Enc messages
    let (c0, c1) = receive_json!(receiver.network => {
        c0: Vec<u8>,
        c1: Vec<u8>
    });

    ot_debug_log!("Receiver received c0: {:?}", String::from_utf8_lossy(&c0));
    ot_debug_log!("Receiver received c1: {:?}", String::from_utf8_lossy(&c1));

    // 3. Dec message
    let m1 = xor_bytes(&c1, &key[0..c1.len()]);
    ot_debug_log!("Receiver obtained message: {:?}", String::from_utf8_lossy(&m1));

    handler.await.unwrap();
}
