use dns::Response;


#[test]
fn parse_nothing() {
    assert!(Response::from_bytes(&[]).is_err());
}
