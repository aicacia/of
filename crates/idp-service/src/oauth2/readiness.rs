#[cfg(feature = "std")]
use std::time::{Duration, Instant};

#[derive(Default)]
pub(super) struct ReplicaReadiness {
    // No production writer until authenticated authority synchronization and signer approval exist.
    #[cfg(feature = "std")]
    synchronized_at: Option<Instant>,
}

impl ReplicaReadiness {
    pub(super) fn is_fresh(&self) -> bool {
        #[cfg(feature = "std")]
        {
            self.is_fresh_at(Instant::now())
        }
        #[cfg(not(feature = "std"))]
        {
            false
        }
    }

    #[cfg(feature = "std")]
    fn is_fresh_at(&self, now: Instant) -> bool {
        self.synchronized_at
            .and_then(|synced| now.checked_duration_since(synced))
            .is_some_and(|age| age <= Duration::from_secs(30))
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use std::time::{Duration, Instant};

    use super::ReplicaReadiness;

    #[test]
    fn replica_readiness_expires_during_partition_and_restart_is_unready() {
        let now = Instant::now();
        assert!(!ReplicaReadiness::default().is_fresh_at(now));
        // Test-only seed; production cannot establish synchronization provenance yet.
        let state = ReplicaReadiness {
            synchronized_at: Some(now),
        };
        assert!(state.is_fresh_at(now + Duration::from_secs(30)));
        assert!(!state.is_fresh_at(now + Duration::from_secs(30) + Duration::from_nanos(1)));
        assert!(!state.is_fresh_at(now + Duration::from_secs(300)));
        assert!(!state.is_fresh_at(now - Duration::from_nanos(1)));
        assert!(!ReplicaReadiness::default().is_fresh_at(now));
    }

    #[test]
    fn replica_readiness_checks_cannot_renew_stale_or_replayed_state() {
        let now = Instant::now();
        let state = ReplicaReadiness {
            synchronized_at: Some(now),
        };
        for _ in 0..3 {
            assert!(state.is_fresh_at(now + Duration::from_secs(20)));
            assert!(!state.is_fresh_at(now + Duration::from_secs(31)));
        }
        assert_eq!(state.synchronized_at, Some(now));
        // There is no response/config/record ingestion API: even a replay cannot write readiness.
        assert!(!ReplicaReadiness::default().is_fresh());
    }
}
