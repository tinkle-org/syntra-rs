//! Staged snapshot transfer.
//!
//! Snapshot formats stay provider-defined. This staging area enforces only
//! the transfer mechanics shared by every snapshot: bounded pages, a
//! provider-proven boundary that subsequent batches must chain from, and an
//! explicit completion gate. Pages are stored without interpretation and
//! are assembled only when every page `0..total_pages` has arrived exactly
//! once; a missing, duplicated-out-of-range, oversized, or
//! boundary-mismatched page fails the install without mutating committed
//! progress. The caller confirms the boundary through the coordinator only
//! after a successful install.

/// Snapshot staging failure. Never carries snapshot bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotError {
    /// Page index outside `0..total_pages`, conflicting bytes, or
    /// zero-length page bytes.
    InvalidPage,
    /// Snapshot handle is empty or a page handle differs from the staged handle.
    HandleMismatch,
    /// Page boundary differs from the staged boundary.
    BoundaryMismatch,
    /// Not every page has arrived; installation is incomplete.
    Incomplete,
    /// Snapshot limits violated (handle too long, too many pages, page too large).
    OverLimit,
    /// Generation is not greater than the engine's current generation.
    StaleGeneration,
    /// Coordinator did not offer the staged snapshot as committable.
    CoordinatorRejected,
}

/// Bounded staged snapshot under one provider-proven boundary.
#[derive(Debug)]
pub struct StagedSnapshot {
    snapshot_handle: Vec<u8>,
    boundary_checkpoint: Vec<u8>,
    total_pages: u32,
    page_bytes_max: u32,
    pages: Vec<Option<Vec<u8>>>,
}

impl StagedSnapshot {
    /// Begin staging `total_pages` pages under `boundary_checkpoint`.
    /// Bounds: handle length `1..=256`, `1 <= total_pages <= 256`,
    /// `1 <= page_bytes_max <= 262144`.
    pub fn new(
        snapshot_handle: Vec<u8>,
        boundary_checkpoint: Vec<u8>,
        total_pages: u32,
        page_bytes_max: u32,
    ) -> Result<Self, SnapshotError> {
        if snapshot_handle.is_empty() {
            return Err(SnapshotError::HandleMismatch);
        }
        if snapshot_handle.len() > 256 {
            return Err(SnapshotError::OverLimit);
        }
        if total_pages == 0 || total_pages > 256 {
            return Err(SnapshotError::OverLimit);
        }
        if page_bytes_max == 0 || page_bytes_max > 262_144 {
            return Err(SnapshotError::OverLimit);
        }
        if boundary_checkpoint.is_empty() {
            return Err(SnapshotError::BoundaryMismatch);
        }
        let n = total_pages as usize;
        let mut pages = Vec::with_capacity(n);
        pages.resize_with(n, || None);
        Ok(Self {
            snapshot_handle,
            boundary_checkpoint,
            total_pages,
            page_bytes_max,
            pages,
        })
    }

    /// Handle staged under.
    pub fn snapshot_handle(&self) -> &[u8] {
        &self.snapshot_handle
    }

    /// Provider-proven boundary subsequent batches chain from.
    pub fn boundary_checkpoint(&self) -> &[u8] {
        &self.boundary_checkpoint
    }

    /// Expected page count.
    pub fn total_pages(&self) -> u32 {
        self.total_pages
    }

    /// Pages received so far.
    pub fn received_pages(&self) -> usize {
        self.pages.iter().filter(|p| p.is_some()).count()
    }

    /// True when every page has arrived.
    pub fn is_complete(&self) -> bool {
        self.pages.iter().all(|p| p.is_some())
    }

    /// Stage one snapshot page. Out-of-range indexes, handle mismatches,
    /// oversized or zero-length pages, and boundary mismatches fail.
    /// Re-staging identical bytes is idempotent; different bytes for the
    /// same index fail.
    pub fn stage_page(
        &mut self,
        snapshot_handle: &[u8],
        page_index: u32,
        bytes: Vec<u8>,
        boundary_checkpoint: &[u8],
    ) -> Result<(), SnapshotError> {
        if snapshot_handle != self.snapshot_handle.as_slice() {
            return Err(SnapshotError::HandleMismatch);
        }
        if page_index >= self.total_pages {
            return Err(SnapshotError::InvalidPage);
        }
        if boundary_checkpoint != self.boundary_checkpoint.as_slice() {
            return Err(SnapshotError::BoundaryMismatch);
        }
        if bytes.is_empty() {
            return Err(SnapshotError::InvalidPage);
        }
        if bytes.len() as u64 > self.page_bytes_max as u64 {
            return Err(SnapshotError::OverLimit);
        }
        let slot = &mut self.pages[page_index as usize];
        match slot {
            Some(existing) if *existing == bytes => Ok(()),
            Some(_) => Err(SnapshotError::InvalidPage),
            None => {
                *slot = Some(bytes);
                Ok(())
            }
        }
    }

    /// Assemble staged pages in order. Fails when any page is missing.
    pub fn install(&self) -> Result<Vec<u8>, SnapshotError> {
        if !self.is_complete() {
            return Err(SnapshotError::Incomplete);
        }
        let mut out = Vec::new();
        for page in self.pages.iter().flatten() {
            out.extend_from_slice(page);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn staged() -> StagedSnapshot {
        StagedSnapshot::new(b"h1".to_vec(), b"b-100".to_vec(), 2, 1024).unwrap()
    }

    #[test]
    fn pages_assemble_in_order_only_when_complete() {
        let mut s = staged();
        assert!(!s.is_complete());
        s.stage_page(b"h1", 1, b"world".to_vec(), b"b-100").unwrap();
        assert!(s.install().is_err());
        s.stage_page(b"h1", 0, b"hello-".to_vec(), b"b-100")
            .unwrap();
        assert!(s.is_complete());
        assert_eq!(s.install().unwrap(), b"hello-world");
    }

    #[test]
    fn snapshot_failure_modes_leave_staging_intact() {
        let mut s = staged();
        assert_eq!(
            s.stage_page(b"h1", 7, b"x".to_vec(), b"b-100"),
            Err(SnapshotError::InvalidPage)
        );
        assert_eq!(
            s.stage_page(b"h1", 0, b"x".to_vec(), b"other"),
            Err(SnapshotError::BoundaryMismatch)
        );
        assert_eq!(
            s.stage_page(b"h1", 0, vec![0u8; 2048], b"b-100"),
            Err(SnapshotError::OverLimit)
        );
        assert_eq!(
            s.stage_page(b"other-handle", 0, b"x".to_vec(), b"b-100"),
            Err(SnapshotError::HandleMismatch)
        );
        assert_eq!(
            s.stage_page(b"h1", 0, Vec::new(), b"b-100"),
            Err(SnapshotError::InvalidPage)
        );
        assert_eq!(s.received_pages(), 0);
        assert_eq!(s.install(), Err(SnapshotError::Incomplete));
    }

    #[test]
    fn identical_restage_is_idempotent_conflicting_is_rejected() {
        let mut s = staged();
        s.stage_page(b"h1", 0, b"a".to_vec(), b"b-100").unwrap();
        s.stage_page(b"h1", 0, b"a".to_vec(), b"b-100").unwrap();
        assert_eq!(s.received_pages(), 1);
        assert_eq!(
            s.stage_page(b"h1", 0, b"b".to_vec(), b"b-100"),
            Err(SnapshotError::InvalidPage)
        );
    }
}
