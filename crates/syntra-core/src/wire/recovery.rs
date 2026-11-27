//! Recovery service values. The runtime owns negotiation, admission and dispatch.

macro_rules! record {
    ($(#[$attr:meta])* $name:ident { $($field:ident: $ty:ty),* $(,)? }) => {
        $(#[$attr])*
        #[derive(Clone, Debug, Default, PartialEq, Eq)]
        pub struct $name {
            pub profile_version: u32,
            $(pub $field: $ty,)*
        }
    };
}

record!(Negotiate {
    min_version: u32,
    max_version: u32,
    capability: String,
});
record!(
    #[derive(Copy)]
    Negotiated {
        selected_version: u32,
        max_subscriptions_per_connection: u32,
        max_pending_rpcs_per_connection: u32,
        max_page_bytes: u32,
        max_snapshot_pages: u32,
    }
);
record!(Subscribe { stream_selector: Vec<u8>, start_checkpoint: Vec<u8> });
record!(SubscriptionAccepted {
    subscription_handle: Vec<u8>, generation: u64, catchup_boundary: Vec<u8>,
});
record!(Unsubscribe { subscription_handle: Vec<u8> });
record!(Unsubscribed { subscription_handle: Vec<u8>, generation: u64 });
record!(Replay {
    subscription_handle: Vec<u8>, from_checkpoint: Vec<u8>, max_batches: u32,
    max_bytes: u32, continuation_marker: Vec<u8>,
});
record!(RecoveryReplayPage {
    subscription_handle: Vec<u8>, predecessor_checkpoint: Vec<u8>, result_checkpoint: Vec<u8>,
    continuation_marker: Vec<u8>, catchup_boundary: Vec<u8>, batch_payloads: Vec<Vec<u8>>,
});
record!(RecoveryReplayComplete {
    subscription_handle: Vec<u8>, generation: u64, live_boundary_checkpoint: Vec<u8>,
});
record!(CatchUp { subscription_handle: Vec<u8> });
record!(RecoveryCatchUpAccepted {
    subscription_handle: Vec<u8>, generation: u64, catchup_boundary: Vec<u8>,
});
record!(OfferSnapshot { subscription_handle: Vec<u8>, generation: u64 });
record!(RecoverySnapshotDescriptor {
    subscription_handle: Vec<u8>, snapshot_handle: Vec<u8>, boundary_checkpoint: Vec<u8>,
    total_pages: u32, page_bytes_max: u32,
});
record!(RecoverySnapshotChunk {
    snapshot_handle: Vec<u8>, page_index: u32, page_bytes: Vec<u8>, boundary_checkpoint: Vec<u8>,
});
record!(RecoverySnapshotComplete {
    snapshot_handle: Vec<u8>, boundary_checkpoint: Vec<u8>, total_pages: u32, total_bytes: u64,
});
record!(RecoverySnapshotInstalled {
    subscription_handle: Vec<u8>, boundary_checkpoint: Vec<u8>, generation: u64,
});
record!(FetchSnapshot { snapshot_handle: Vec<u8>, page_index: u32 });
record!(Confirm { subscription_handle: Vec<u8>, generation: u64, checkpoint: Vec<u8> });
record!(ConfirmSnapshot {
    subscription_handle: Vec<u8>, generation: u64, boundary_checkpoint: Vec<u8>,
});
record!(Confirmed {
    subscription_handle: Vec<u8>, confirmed_checkpoint: Vec<u8>, generation: u64,
});
record!(RecoveryBatch {
    subscription_handle: Vec<u8>, generation: u64, predecessor_checkpoint: Vec<u8>,
    result_checkpoint: Vec<u8>, batch_payload: Vec<u8>,
});
record!(RecoveryBatchTrailer {
    subscription_handle: Vec<u8>, generation: u64, boundary_checkpoint: Vec<u8>,
    terminate_reason: Vec<u8>, outcome: Option<recovery_batch_trailer::Outcome>,
});
pub mod recovery_batch_trailer {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Outcome {
        NextGeneration(u64),
        CatchupComplete,
        SnapshotRequired,
        Terminated,
    }
}

record!(RecoveryNotification { notification: Option<recovery_notification::Notification> });
pub mod recovery_notification {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Notification {
        Batch(RecoveryBatch),
        ReplayComplete(RecoveryReplayComplete),
        Trailer(RecoveryBatchTrailer),
    }
}
