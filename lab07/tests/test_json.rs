#[test]
fn test_json_parsing() {
        let data = r#"{"key": "value", "number": 42}"#;     
        let obj: serde_json::Value = serde_json::from_str(data).unwrap();
        println!("{:?}", obj["number"]);
        // println!("{}", type_name::<&obj>);
}