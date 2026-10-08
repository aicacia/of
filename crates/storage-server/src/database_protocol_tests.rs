use std::{
    collections::VecDeque,
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use ofdb_sql::SyncTransport;

use super::AuthorizedTransport;

#[derive(Default)]
struct MemorySyncTransport {
    incoming: VecDeque<Vec<u8>>,
    outgoing: Vec<Vec<u8>>,
}
impl SyncTransport for MemorySyncTransport {
    type Error = io::Error;
    async fn receive(&mut self) -> io::Result<Vec<u8>> {
        self.incoming
            .pop_front()
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no test frame"))
    }
    async fn send(&mut self, frame: Vec<u8>) -> io::Result<()> {
        self.outgoing.push(frame);
        Ok(())
    }
}

#[tokio::test]
async fn transport_rechecks_each_send_and_after_receipt() {
    let checks = Arc::new(AtomicUsize::new(0));
    let mut transport = AuthorizedTransport {
        transport: MemorySyncTransport::default(),
        authorize: Arc::new(move || {
            let checks = checks.clone();
            Box::pin(async move { checks.fetch_add(1, Ordering::SeqCst) == 0 })
        }),
    };
    transport
        .send(vec![1])
        .await
        .expect("first operation allowed");
    assert_eq!(
        transport
            .send(vec![2])
            .await
            .expect_err("next send denied")
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(transport.transport.outgoing, [vec![1]]);
    let checks = Arc::new(AtomicUsize::new(0));
    let mut transport = AuthorizedTransport {
        transport: MemorySyncTransport {
            incoming: VecDeque::from([vec![3]]),
            outgoing: vec![],
        },
        authorize: Arc::new(move || {
            let checks = checks.clone();
            Box::pin(async move { checks.fetch_add(1, Ordering::SeqCst) == 0 })
        }),
    };
    assert_eq!(
        transport
            .receive()
            .await
            .expect_err("received bytes not authorized for use")
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    assert!(transport.transport.incoming.is_empty());
}

#[tokio::test]
async fn cancellation_releases_pending_apply_authorization_without_a_timer() {
    let cancellation = tokio_util::sync::CancellationToken::new();
    let authorize = Arc::new(
        || -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>> {
            Box::pin(std::future::pending())
        },
    );
    let task = tokio::spawn(super::check_apply(authorize, cancellation.clone()));
    cancellation.cancel();
    assert!(task.await.expect("join apply check").is_err());
}
