//! Checking that a response answers the request it was received for.
//!
//! A message can arrive that is not the answer dog asked for: a late answer
//! to an earlier query, a reflection, or a forgery. The transaction ID and
//! the question section are how a DNS client tells them apart (RFC 5452
//! §9.1), so a response is only accepted if both match the request.

use std::fmt;

use crate::record::registry;
use crate::types::{QClass, Query, Request, Response};


/// How a response fails to answer the request it was received for.
#[derive(PartialEq, Debug)]
pub enum Mismatch {

    /// The response carries a different transaction ID from the request.
    TransactionId {

        /// The ID the request was sent with.
        expected: u16,

        /// The ID in the response.
        received: u16,
    },

    /// The message has its QR bit clear, so it is a query, not a response.
    NotAResponse,

    /// The response repeats a different question, or none at all.
    Question {

        /// The question that was asked.
        expected: String,

        /// The question the response repeats, if any.
        received: Option<String>,
    },
}

impl Request {

    /// Checks that `response` answers this request: it must carry the same
    /// transaction ID, be marked as a response, and repeat the question,
    /// with the name compared without regard to ASCII case (RFC 4343).
    ///
    /// A response with an error code may leave the question out, as real
    /// servers do when they refuse, or cannot parse, a query.
    pub fn check_response(&self, response: &Response) -> Result<(), Mismatch> {
        if response.transaction_id != self.transaction_id {
            return Err(Mismatch::TransactionId { expected: self.transaction_id, received: response.transaction_id });
        }

        if ! response.flags.response {
            return Err(Mismatch::NotAResponse);
        }

        match response.queries.first() {
            Some(query) if same_question(&self.query, query) => Ok(()),
            None if response.flags.error_code.is_some() => Ok(()),
            received => Err(Mismatch::Question { expected: describe(&self.query), received: received.map(describe) }),
        }
    }
}

fn same_question(asked: &Query, repeated: &Query) -> bool {
    asked.qname.eq_ignore_ascii_case(&repeated.qname)
        && asked.qtype.type_number() == repeated.qtype.type_number()
        && asked.qclass == repeated.qclass
}

/// A question the way dog’s users write one, such as `example.com. A IN`.
fn describe(query: &Query) -> String {
    let number = query.qtype.type_number();
    let qtype = registry::record_type_name(number).map_or_else(|| number.to_string(), str::to_owned);
    let qclass = match query.qclass {
        QClass::IN        => "IN".to_owned(),
        QClass::CH        => "CH".to_owned(),
        QClass::HS        => "HS".to_owned(),
        QClass::Other(n)  => n.to_string(),
    };
    format!("{} {} {}", query.qname, qtype, qclass)
}

impl fmt::Display for Mismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TransactionId { expected, received } => {
                write!(f, "Response ID {received:#06x} does not match request ID {expected:#06x}")
            }
            Self::NotAResponse => {
                write!(f, "Received a query, not a response")
            }
            Self::Question { expected, received: Some(received) } => {
                write!(f, "Response is for '{received}', expected '{expected}'")
            }
            Self::Question { expected, received: None } => {
                write!(f, "Response has no question, expected '{expected}'")
            }
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use crate::{ErrorCode, Flags, Labels};
    use crate::record::RecordType;
    use test_support::{fixtures, wire};

    /// The request a fixture’s response answers, rebuilt from the response’s
    /// own transaction ID.
    fn request(fixture: &str, qname: &str, qtype: u16, qclass: QClass) -> Request {
        Request {
            transaction_id: wire::txid(&fixtures::response(fixture)),
            flags: Flags::query(),
            query: Query { qname: Labels::encode(qname).unwrap(), qtype: RecordType::from(qtype), qclass },
            additional: None,
        }
    }

    fn response(bytes: &[u8]) -> Response {
        Response::from_bytes(bytes).unwrap()
    }

    #[test]
    fn a_real_response_answers_its_request() {
        let request = request("a-example", "a-example.lookup.dog", 1, QClass::IN);
        assert_eq!(request.check_response(&response(&fixtures::response("a-example"))), Ok(()));
    }

    #[test]
    fn chaos_class_questions_match() {
        let request = request("version-bind", "version.bind", 16, QClass::CH);
        assert_eq!(request.check_response(&response(&fixtures::response("version-bind"))), Ok(()));
    }

    #[test]
    fn names_are_compared_without_case() {
        let bytes = fixtures::response("a-example");
        let mut request = request("a-example", "a-example.lookup.dog", 1, QClass::IN);
        let mut answer = response(&bytes);
        answer.queries[0].qname = Labels::encode("A-Example.LOOKUP.dog").unwrap();
        request.query.qname = Labels::encode("a-example.lookup.DOG").unwrap();
        assert_eq!(request.check_response(&answer), Ok(()));
    }

    #[test]
    fn a_different_transaction_id() {
        let bytes = fixtures::response("a-example");
        let request = request("a-example", "a-example.lookup.dog", 1, QClass::IN);
        let mismatch = request.check_response(&response(&wire::with_txid(&bytes, 0xbeef))).unwrap_err();
        assert_eq!(mismatch, Mismatch::TransactionId { expected: wire::txid(&bytes), received: 0xbeef });
        assert_eq!(mismatch.to_string(), format!("Response ID 0xbeef does not match request ID {:#06x}", wire::txid(&bytes)));
    }

    #[test]
    fn a_query_instead_of_a_response() {
        let bytes = wire::without_flag(&fixtures::response("a-example"), wire::QR);
        let request = request("a-example", "a-example.lookup.dog", 1, QClass::IN);
        let mismatch = request.check_response(&response(&bytes)).unwrap_err();
        assert_eq!(mismatch, Mismatch::NotAResponse);
        assert_eq!(mismatch.to_string(), "Received a query, not a response");
    }

    #[test]
    fn a_different_question() {
        let answer = response(&fixtures::response("a-example"));
        let cases = [
            request("a-example", "other.lookup.dog", 1, QClass::IN),
            request("a-example", "a-example.lookup.dog", 28, QClass::IN),
            request("a-example", "a-example.lookup.dog", 1, QClass::CH),
        ];

        for request in cases {
            assert!(matches!(request.check_response(&answer), Err(Mismatch::Question { .. })), "{request:?}");
        }

        let mismatch = request("a-example", "other.lookup.dog", 65, QClass::Other(254)).check_response(&answer).unwrap_err();
        assert_eq!(mismatch.to_string(), "Response is for 'a-example.lookup.dog. A IN', expected 'other.lookup.dog. HTTPS 254'");
    }

    /// Google answers an unsupported opcode with NOTIMP and no question at all.
    #[test]
    fn an_error_response_may_have_no_question() {
        let answer = response(&fixtures::response("notimp-opcode-status"));
        assert!(answer.queries.is_empty());
        assert_eq!(answer.flags.error_code, Some(ErrorCode::NotImplemented));

        let request = request("notimp-opcode-status", "a-example.lookup.dog", 1, QClass::IN);
        assert_eq!(request.check_response(&answer), Ok(()));
    }

    #[test]
    fn a_successful_response_must_have_the_question() {
        let mut answer = response(&fixtures::response("a-example"));
        answer.queries.clear();

        let request = request("a-example", "a-example.lookup.dog", 1, QClass::HS);
        let mismatch = request.check_response(&answer).unwrap_err();
        assert_eq!(mismatch.to_string(), "Response has no question, expected 'a-example.lookup.dog. A HS'");
    }
}
