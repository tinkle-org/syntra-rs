//! Optional diagnostic run: live Rust allocation sizes, not RSS or allocator capacity.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

#[derive(Default)]
struct Counts {
    live: AtomicUsize,
    peak: AtomicUsize,
}

impl Counts {
    fn grow(&self, bytes: usize) {
        let live = self.live.fetch_add(bytes, SeqCst) + bytes;
        self.peak.fetch_max(live, SeqCst);
    }

    fn shrink(&self, bytes: usize) {
        self.live.fetch_sub(bytes, SeqCst);
    }

    fn begin(&self) {
        self.peak.store(0, SeqCst);
        self.peak.fetch_max(self.live.load(SeqCst), SeqCst);
    }
}

#[global_allocator]
static ALLOC: Counts = Counts {
    live: AtomicUsize::new(0),
    peak: AtomicUsize::new(0),
};

// SAFETY: All requests go unchanged to System. Only nonallocating counters run
// between allocation and return; a failed realloc leaves the old block charged.
unsafe impl GlobalAlloc for Counts {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            self.grow(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            self.grow(layout.size());
        }
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let new = unsafe { System.realloc(ptr, layout, size) };
        if !new.is_null() {
            if size >= layout.size() {
                self.grow(size - layout.size());
            } else {
                self.shrink(layout.size() - size);
            }
        }
        new
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.shrink(layout.size());
        unsafe { System.dealloc(ptr, layout) };
    }
}

pub fn begin_window() {
    ALLOC.begin();
}

pub fn peak_bytes() -> usize {
    ALLOC.peak.load(SeqCst)
}

#[cfg(feature = "managed-media")]
pub fn live_bytes() -> usize {
    ALLOC.live.load(SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peak_includes_preexisting_live_bytes_but_not_previous_peak() {
        let counts = Counts::default();
        counts.grow(128);
        counts.shrink(96);
        counts.begin();
        counts.grow(16);
        counts.shrink(48);
        assert_eq!(counts.peak.load(SeqCst), 48);
        assert_eq!(counts.live.load(SeqCst), 0);
    }
}
