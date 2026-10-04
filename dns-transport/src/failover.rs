use log::*;

use dns::{Request, Response};
use super::{Transport, Error};


/// The **failover transport**, which sends each request to the first of
/// several nameservers, and on to the next whenever one fails to answer, as
/// the system’s own resolver does with the nameservers in `resolv.conf`.
///
/// Only a failure to get an answer moves on to the next nameserver. An
/// answer with an error code, such as NXDOMAIN, is still an answer.
pub struct FailoverTransport {
    transports: Vec<Box<dyn Transport>>,
}

impl FailoverTransport {

    /// Creates a new failover transport that tries each of these transports
    /// in turn.
    pub fn new(transports: Vec<Box<dyn Transport>>) -> Self {
        Self { transports }
    }
}

impl Transport for FailoverTransport {
    fn send(&self, request: &Request) -> Result<Response, Error> {
        let mut last_error = Error::InvalidNameserver("There are no nameservers to send the request to".into());

        for (number, transport) in self.transports.iter().enumerate() {
            match transport.send(request) {
                Ok(response) => return Ok(response),
                Err(e) => {
                    warn!("Nameserver {} of {} failed ({e:?}); trying the next", number + 1, self.transports.len());
                    last_error = e;
                }
            }
        }

        Err(last_error)
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;
    use std::time::Duration;
    use test_support::fixtures;
    use crate::test_util::a_example;

    /// A transport that fails, or answers with a real captured response,
    /// and counts how often it was used.
    struct Fake {
        answers: bool,
        sent: Rc<Cell<usize>>,
    }

    impl Transport for Fake {
        fn send(&self, _: &Request) -> Result<Response, Error> {
            self.sent.set(self.sent.get() + 1);
            if self.answers {
                Ok(Response::from_bytes(&fixtures::response("a-example")).expect("a captured response parses"))
            }
            else {
                Err(Error::Timeout(Duration::from_secs(5)))
            }
        }
    }

    fn fakes(answers: &[bool]) -> (FailoverTransport, Vec<Rc<Cell<usize>>>) {
        let counters = answers.iter().map(|_| Rc::new(Cell::new(0))).collect::<Vec<_>>();
        let transports = answers.iter().zip(&counters)
            .map(|(&answers, sent)| -> Box<dyn Transport> { Box::new(Fake { answers, sent: Rc::clone(sent) }) })
            .collect();
        (FailoverTransport::new(transports), counters)
    }

    fn sent(counters: &[Rc<Cell<usize>>]) -> Vec<usize> {
        counters.iter().map(|c| c.get()).collect()
    }

    #[test]
    fn the_first_answer_is_used() {
        let (transport, counters) = fakes(&[ true, true ]);
        assert!(transport.send(&a_example()).is_ok());
        assert_eq!(sent(&counters), [ 1, 0 ]);
    }

    #[test]
    fn a_nameserver_that_fails_is_skipped() {
        let (transport, counters) = fakes(&[ false, false, true ]);
        assert!(transport.send(&a_example()).is_ok());
        assert_eq!(sent(&counters), [ 1, 1, 1 ]);
    }

    #[test]
    fn when_every_nameserver_fails_the_last_failure_is_returned() {
        let (transport, counters) = fakes(&[ false, false ]);
        assert!(matches!(transport.send(&a_example()), Err(Error::Timeout(_))));
        assert_eq!(sent(&counters), [ 1, 1 ]);
    }

    #[test]
    fn no_nameservers() {
        let (transport, _) = fakes(&[]);
        assert!(matches!(transport.send(&a_example()), Err(Error::InvalidNameserver(_))));
    }
}
