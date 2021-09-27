use ech_config::ECHConfigList;
use serde_json;

use std::io::{self, Read};

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut buf = String::new();
    stdin.lock().take(u16::MAX.into()).read_to_string(&mut buf).unwrap();
    let configs = ECHConfigList::from_base64(&buf.trim()).unwrap();
    serde_json::to_writer(stdout.lock(), &configs).unwrap();

    // println!("{}", serde_json::to_string_pretty(&configs).unwrap());
    //
    // let base = "AEb+DQBCPwAgACAoJhkM1Ki3KtogKZosPZiIg3JWb8JCmnLnqs1TSGlpdwAEAAEAAQATY2xvdWRmbGFyZS1lc25pLmNvbQAA";
    // let configs = ECHConfigList::from_base64(base).unwrap();
    // println!("{}", serde_json::to_string_pretty(&configs).unwrap());
    // let unknown_version = "AEc+DQBCPwAgACAoJhkM1Ki3KtogKZosPZiIg3JWb8JCmnLnqs1TSGlpdwAEAAEAAQATY2xvdWRmbGFyZS1lc25pLmNvbQAA";
    // let configs = ECHConfigList::from_base64(unknown_version).unwrap();
    // println!("{}", serde_json::to_string_pretty(&configs).unwrap());
    // assert!(false);
}
