use anyhow::Result;
use clap::Parser;
use lab07::{
    circuit::{gates::GarblerGate, utils::xor_block},
    network::Network,
    simplest_ot::{OtSender, xor_bytes},
};
use serde_json::json;
use tokio::net::TcpListener;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, default_value_t = 8888)]
    port: u16,
    #[arg(long, default_value_t = 0)]
    input_a: u8,
    #[arg(long, default_value_t = 0)]
    input_b: u8,
}

//// !Server
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let _a = args.input_a != 0;
    let _b = args.input_b != 0;
    println!("Using parameters: {:?}", args);

    let listener = TcpListener::bind(format!("0.0.0.0:{}", args.port)).await?;

    let (stream, _) = listener.accept().await?;
    let mut network = Network::new(stream);

    // 0. Circuit Setup
    let garbler = GarblerGate::new();
    let (a0, a1) = garbler.gen_labels();
    let (b0, b1) = garbler.gen_labels();
    let (x0, x1) = garbler.gen_labels();
    let (y0, y1) = garbler.gen_labels();

    // 1. Send Garbler inputs _a and _b
    let la = if _a { a1 } else { a0 };
    let lb = if _b { b1 } else { b0 };

    let data = json!({
        "la": la,
        "lb": lb
    });
    network.send(&data).await?;
    println!("Sent garbler input a & b.");

    // 2. OT interaction to get evaluator inputs

    // 2.1 OT x
    let mut ot_sender = OtSender::new(network);
    let (k0, k1) = ot_sender.execute().await;

    let enc_x0 = xor_bytes(&x0, &k0[0..x0.len()]);
    let enc_x1 = xor_bytes(&x1, &k1[0..x1.len()]);

    let ot_data_x = json!({
        "e0": enc_x0,
        "e1": enc_x1
    });
    ot_sender.network.send(&ot_data_x).await?;
    println!("Sent OT messages for input x.");

    // 2.2 OT y
    let mut ot_sender = OtSender::new(ot_sender.network);
    let (k0, k1) = ot_sender.execute().await;

    let enc_y0 = xor_bytes(&y0, &k0[0..y0.len()]);
    let enc_y1 = xor_bytes(&y1, &k1[0..y1.len()]);

    let ot_data_y = json!({
        "e0": enc_y0,
        "e1": enc_y1
    });
    ot_sender.network.send(&ot_data_y).await?;
    println!("Sent OT messages for input y.");

    network = ot_sender.network;

    // 3. Garble circuit send
    // z = a ⊕ ( (b ⊕ x) & y)

    // ! b ⊕ x
    let w1_0 = xor_block(&b0, &x0);
    let w1_1 = xor_block(&b0, &x1);

    // ! (b ⊕ x) & y
    let gate_id = 1;
    let (w2_0, _w2_1, ct) = garbler.garble_and(&w1_0, &w1_1, &y0, &y1, gate_id);

    // ! a ⊕ ((b ⊕ x) & y)
    let z0 = xor_block(&a0, &w2_0);

    // Send garbled tables and output labels
    let garbled_tables = json!({
        "and_ct": ct,
    });
    network.send(&garbled_tables).await?;
    println!("Sent garbled tables.");

    // 4. ----

    // 5. Send z0
    let decode_data = json!({
        "z0": z0,
    });
    network.send(&decode_data).await?;
    println!("Sent z0.");

    Ok(())
}