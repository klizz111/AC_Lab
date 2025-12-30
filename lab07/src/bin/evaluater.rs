#[allow(unused_imports, unused_variables,dead_code)]
use tokio::net::TcpStream;
use clap::Parser;
use lab07::{
    circuit::{gates::{Cipher, eval_and_gate, eval_xor_gate}, utils::Block}, network::Network, receive_json, simplest_ot::{OtReceiver, xor_bytes}
};
use anyhow::Result;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value_t = String::from("0.0.0.0"))]
    host: String,
    #[arg(short, long, default_value_t = 8888)]
    port: u16,
    #[arg(long, default_value_t = 0)]
    input_x: u8,
    #[arg(long, default_value_t = 0)]
    input_y: u8,
}

//// !Client
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let _x = args.input_x != 0;
    let _y = args.input_y != 0;
    println!("Using parameters: {:?}", args);

    let addr = format!("{}:{}", args.host, args.port);
    let stream = TcpStream::connect(addr).await?;
    let mut network = Network::new(stream);

    // 1. Receive Garbler inputs
    let (la, lb) = receive_json!(network => {
        la: Block,
        lb: Block
    });
    println!("Received garbler input a & b.");

    // 2.1 OT for x
    let choice_x = if _x { 1 as u8 } else { 0 as u8 };
    let mut ot_receiver = OtReceiver::new(network, choice_x);
    let key_x = ot_receiver.execute().await;

    let (e0, e1) = receive_json!(ot_receiver.network => {
        e0: Vec<u8>,
        e1: Vec<u8>
    });

    let lx = if _x {
        xor_bytes(&e1, &key_x[0..e1.len()])
    } else {
        xor_bytes(&e0, &key_x[0..e0.len()])
    };
    let lx: Block = lx.try_into().unwrap();
    println!("OT for x done.");

    // 2.2. OT for y
    ot_receiver = OtReceiver::new(ot_receiver.network, if _y { 1 } else { 0 });
    let key_y = ot_receiver.execute().await;

    let (e0, e1) = receive_json!(ot_receiver.network => {
        e0: Vec<u8>,
        e1: Vec<u8>
    });

    let ly = if _y {
        xor_bytes(&e1, &key_y[0..e1.len()])
    } else {
        xor_bytes(&e0, &key_y[0..e0.len()])
    };
    let ly: Block = ly.try_into().unwrap();
    println!("OT for y done.");

    // 3. Receive garbled AND gate table
    let (garbled_tables,) = receive_json!(ot_receiver.network => {
        and_ct: Cipher
    });
    let ct = (garbled_tables.tg, garbled_tables.te);
    println!("Received garbled AND gate table.");

    // 4. Evaluate garbled AND gate
    // z = a ⊕ ( (b ⊕ x) & y)

    // ! b ⊕ x
    let lw1 = eval_xor_gate(&lb, &lx);

    // ! (b ⊕ x) & y
    let gate_id = 1;
    let lw2 = eval_and_gate(&lw1, &ly, &ct, gate_id); 

    // ! a ⊕ ((b ⊕ x) & y)
    let lz = eval_xor_gate(&la, &lw2);

    // 5. Receive z0
    let (z0,) = receive_json!(ot_receiver.network => {
        z0: Block
    });
    println!("Received z0.");

    let res = if lz == z0 { 0 } else { 1 };
    println!("Computation result z = {}", res);

    Ok(())
}