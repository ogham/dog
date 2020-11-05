//! Transaction ID generation.


/// A **transaction ID generator** is used to create unique ID numbers to
/// identify each packet, as part of the DNS protocol.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum TxidGenerator {

    /// Generate random transaction IDs each time.
    Random,

    /// Generate transaction IDs in a sequence, starting from the given value,
    /// wrapping around.
    Sequence(u16),
}

impl TxidGenerator {
    pub fn generate(self) -> u16 {
        match self {
            Self::Random           => rand::random(),
            Self::Sequence(start)  => start,   // todo
        }
    }
}
