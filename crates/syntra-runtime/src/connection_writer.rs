//! Both driver boundaries use one bounded FIFO. Only the managed host channel
//! moves an operation charge along with the bytes.

use crate::host::ManagedOutput;
use tokio::sync::mpsc;

pub(crate) enum Writer {
    Raw(mpsc::Sender<Vec<u8>>),
    Managed(mpsc::Sender<ManagedOutput>),
}

impl From<mpsc::Sender<Vec<u8>>> for Writer {
    fn from(tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self::Raw(tx)
    }
}

impl From<mpsc::Sender<ManagedOutput>> for Writer {
    fn from(tx: mpsc::Sender<ManagedOutput>) -> Self {
        Self::Managed(tx)
    }
}

impl Writer {
    pub(super) async fn reserve(&self) -> Result<WriterPermit<'_>, mpsc::error::SendError<()>> {
        match self {
            Self::Raw(tx) => tx.reserve().await.map(WriterPermit::Raw),
            Self::Managed(tx) => tx.reserve().await.map(WriterPermit::Managed),
        }
    }

    pub(crate) fn capacity(&self) -> usize {
        match self {
            Self::Raw(tx) => tx.capacity(),
            Self::Managed(tx) => tx.capacity(),
        }
    }

    pub(crate) fn max_capacity(&self) -> usize {
        match self {
            Self::Raw(tx) => tx.max_capacity(),
            Self::Managed(tx) => tx.max_capacity(),
        }
    }

    pub(crate) fn try_send(&self, bytes: Vec<u8>) -> Result<(), mpsc::error::TrySendError<()>> {
        match self {
            Self::Raw(tx) => tx.try_reserve()?.send(bytes),
            Self::Managed(tx) => tx.try_reserve()?.send(bytes.into()),
        }
        Ok(())
    }
}

pub(crate) enum WriterPermit<'a> {
    Raw(mpsc::Permit<'a, Vec<u8>>),
    Managed(mpsc::Permit<'a, ManagedOutput>),
}

impl WriterPermit<'_> {
    pub(crate) fn send(self, bytes: Vec<u8>) {
        match self {
            Self::Raw(p) => p.send(bytes),
            Self::Managed(p) => p.send(bytes.into()),
        }
    }
}
