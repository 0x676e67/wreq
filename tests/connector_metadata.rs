use wreq::connector::{Connected, Connection};

struct Transport(bool);
impl Connection for Transport {
    fn connected(&self) -> Connected {
        if self.0 {
            Connected::new().negotiated_h2()
        } else {
            Connected::new()
        }
    }
}

#[test]
fn downstream_connector_layers_can_inspect_negotiated_protocol() {
    assert!(!Transport(false).connected().is_negotiated_h2());
    assert!(Transport(true).connected().is_negotiated_h2());
}
