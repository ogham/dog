use ech_config::ECHConfigList;
use serde_json;

fn main() {
    let base = "AEb+DQBCPwAgACAoJhkM1Ki3KtogKZosPZiIg3JWb8JCmnLnqs1TSGlpdwAEAAEAAQATY2xvdWRmbGFyZS1lc25pLmNvbQAA";
    let configs = ECHConfigList::from_base64(base).unwrap();
    println!("{}", serde_json::to_string_pretty(&configs).unwrap());
    let unknown_version = "AEc+DQBCPwAgACAoJhkM1Ki3KtogKZosPZiIg3JWb8JCmnLnqs1TSGlpdwAEAAEAAQATY2xvdWRmbGFyZS1lc25pLmNvbQAA";
    let configs = ECHConfigList::from_base64(unknown_version).unwrap();
    println!("{}", serde_json::to_string_pretty(&configs).unwrap());
    assert!(false);
}
