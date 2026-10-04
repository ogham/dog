//! Turning a would-be infinite loop into a test failure.

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Runs `f` on its own thread and returns its result, failing the test if it
/// has not finished within `limit`.
///
/// Regression tests for hangs use this so that a regression fails the suite
/// instead of stopping it forever. A thread that is still looping is left
/// behind; the test process ends soon after anyway.
///
/// # Panics
///
/// Panics if `f` does not finish in time, or if `f` itself panics.
pub fn within<T, F>(limit: Duration, f: F) -> T
where T: Send + 'static,
      F: FnOnce() -> T + Send + 'static,
{
    let (sender, receiver) = mpsc::channel();
    let handle = thread::spawn(move || {
        // If the receiver has already given up, there is nobody to tell.
        drop(sender.send(f()));
    });

    match receiver.recv_timeout(limit) {
        Ok(value) => value,
        Err(mpsc::RecvTimeoutError::Timeout) => panic!("did not finish within {limit:?}: is it stuck in a loop?"),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            let panic = handle.join().expect_err("the thread ended without sending a result, so it panicked");
            std::panic::resume_unwind(panic)
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn returns_the_result() {
        assert_eq!(within(Duration::from_secs(5), || 6 * 7), 42);
    }

    #[test]
    #[should_panic(expected = "did not finish within")]
    fn fails_a_hang() {
        within(Duration::from_millis(50), || thread::sleep(Duration::from_secs(5)));
    }

    #[test]
    #[should_panic(expected = "boom")]
    fn propagates_a_panic() {
        within(Duration::from_secs(5), || panic!("boom"));
    }
}
