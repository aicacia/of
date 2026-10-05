use std::{future::Future, io, time::Duration};

pub(crate) async fn run<F, T>(timeout: Duration, message: &'static str, future: F) -> io::Result<T>
where
    F: Future<Output = io::Result<T>>,
{
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, message))?
}

#[cfg(test)]
mod tests {
    use std::{
        future::pending,
        io,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use super::run;

    struct DropSignal(Arc<AtomicBool>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn timeout_drops_the_pending_sync_future() {
        let dropped = Arc::new(AtomicBool::new(false));
        let signal = DropSignal(Arc::clone(&dropped));
        let result = run(Duration::from_millis(10), "sync timed out", async move {
            let _signal = signal;
            pending::<io::Result<()>>().await
        })
        .await;

        assert_eq!(
            result.expect_err("operation must time out").kind(),
            io::ErrorKind::TimedOut
        );
        assert!(dropped.load(Ordering::SeqCst));
    }
}
