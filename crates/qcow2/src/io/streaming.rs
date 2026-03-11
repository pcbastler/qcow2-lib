//! Append-only I/O backend overlay for streaming writes.
//!
//! [`StreamingBackend`] wraps an inner [`IoBackend`] with an in-memory
//! `BTreeMap` overlay. All writes go to the overlay. Reads check the
//! overlay first, then fall back to the inner backend.
//!
//! [`StreamingBackend::drain_to`] flushes finalized (immutable) regions
//! to the inner backend in ascending offset order, freeing memory.
//! Gaps between entries are zero-filled so the output is always
//! sequential and contiguous — suitable for append-only storage.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use crate::error::Result;
use crate::io::IoBackend;
use qcow2_core::error::Error;

/// Shared internal state for [`StreamingBackend`].
struct StreamingState {
    /// The underlying (append-only) backend.
    inner: Box<dyn IoBackend>,
    /// In-memory write buffer keyed by file offset.
    overlay: RwLock<BTreeMap<u64, Vec<u8>>>,
    /// Everything below this offset has been drained to inner.
    /// Writes below this are rejected.
    drained_up_to: RwLock<u64>,
    /// Logical file size (max of inner size and highest overlay write end).
    logical_size: RwLock<u64>,
}

/// An append-only I/O backend overlay for streaming writes.
///
/// Wraps an inner [`IoBackend`] with an in-memory `BTreeMap` overlay.
/// All writes go to the overlay. Reads check the overlay first, then
/// fall back to the inner backend.
///
/// # Cloning
///
/// `StreamingBackend` is cheaply clonable (`Arc`-based). Clone a handle
/// before passing the backend to `Qcow2Image::create_on_backend` so you
/// can call [`drain_to`](Self::drain_to) and [`finalize`](Self::finalize)
/// while the image owns the backend.
pub struct StreamingBackend {
    state: Arc<StreamingState>,
}

impl Clone for StreamingBackend {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}

impl StreamingBackend {
    /// Create a new streaming backend wrapping the given inner backend.
    pub fn new(inner: Box<dyn IoBackend>) -> Result<Self> {
        let size = inner.file_size()?;
        Ok(Self {
            state: Arc::new(StreamingState {
                inner,
                overlay: RwLock::new(BTreeMap::new()),
                drained_up_to: RwLock::new(0),
                logical_size: RwLock::new(size),
            }),
        })
    }

    /// Flush all overlay entries fully below `boundary` to the inner backend.
    ///
    /// Entries are written in ascending offset order. Gaps between entries
    /// (and between `drained_up_to` and the first entry) are zero-filled,
    /// so the output to the inner backend is always contiguous.
    ///
    /// Entries that straddle `boundary` (start below but end at or above)
    /// are left in the overlay.
    ///
    /// After draining, writes below the new watermark are rejected.
    pub fn drain_to(&self, boundary: u64) -> Result<()> {
        let mut overlay = self.state.overlay.write().unwrap();
        let mut drained = self.state.drained_up_to.write().unwrap();

        let mut cursor = *drained;

        // Collect keys to drain (entries fully below boundary).
        let keys_to_drain: Vec<u64> = overlay
            .range(..boundary)
            .filter(|(&offset, data)| offset + data.len() as u64 <= boundary)
            .map(|(&k, _)| k)
            .collect();

        for key in keys_to_drain {
            let data = overlay.remove(&key).unwrap();
            let entry_end = key + data.len() as u64;

            // Fill gap between cursor and this entry with zeros.
            if key > cursor {
                let gap = (key - cursor) as usize;
                let zeros = vec![0u8; gap];
                self.state.inner.write_all_at(&zeros, cursor)?;
            }

            self.state.inner.write_all_at(&data, key)?;

            if entry_end > cursor {
                cursor = entry_end;
            }
        }

        // Advance watermark to at least the boundary (even if no entries
        // were drained, the caller asserts nothing below boundary will change).
        if boundary != u64::MAX && boundary > cursor {
            // Zero-fill remaining gap up to boundary.
            let gap = (boundary - cursor) as usize;
            if gap > 0 {
                let zeros = vec![0u8; gap];
                self.state.inner.write_all_at(&zeros, cursor)?;
            }
            cursor = boundary;
        }

        if cursor > *drained {
            *drained = cursor;
        }

        Ok(())
    }

    /// Drain all remaining overlay entries to the inner backend and flush.
    pub fn finalize(&self) -> Result<()> {
        self.drain_to(u64::MAX)?;
        self.state.inner.flush()
    }

    /// Current memory usage of the overlay in bytes.
    pub fn overlay_bytes(&self) -> usize {
        let overlay = self.state.overlay.read().unwrap();
        overlay.values().map(|v| v.len()).sum()
    }

    /// Number of entries in the overlay.
    pub fn overlay_entries(&self) -> usize {
        self.state.overlay.read().unwrap().len()
    }

    /// Current drain watermark.
    pub fn drained_up_to(&self) -> u64 {
        *self.state.drained_up_to.read().unwrap()
    }
}

impl IoBackend for StreamingBackend {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> Result<()> {
        let len = buf.len() as u64;
        let read_end = offset + len;

        // Start with data from inner (or zeros if beyond inner size).
        let inner_size = self.state.inner.file_size()?;
        if offset + len <= inner_size {
            self.state.inner.read_exact_at(buf, offset)?;
        } else if offset < inner_size {
            let inner_len = (inner_size - offset) as usize;
            self.state.inner.read_exact_at(&mut buf[..inner_len], offset)?;
            buf[inner_len..].fill(0);
        } else {
            buf.fill(0);
        }

        // Apply overlay entries on top.
        let overlay = self.state.overlay.read().unwrap();
        for (&entry_offset, entry_data) in overlay.range(..read_end) {
            let entry_end = entry_offset + entry_data.len() as u64;
            if entry_end <= offset {
                continue;
            }
            let overlap_start = offset.max(entry_offset);
            let overlap_end = read_end.min(entry_end);
            let buf_start = (overlap_start - offset) as usize;
            let entry_start = (overlap_start - entry_offset) as usize;
            let copy_len = (overlap_end - overlap_start) as usize;
            buf[buf_start..buf_start + copy_len]
                .copy_from_slice(&entry_data[entry_start..entry_start + copy_len]);
        }

        Ok(())
    }

    fn write_all_at(&self, buf: &[u8], offset: u64) -> Result<()> {
        let drained = *self.state.drained_up_to.read().unwrap();
        if offset < drained {
            return Err(Error::WriteBelowDrain {
                write_offset: offset,
                drained_up_to: drained,
            });
        }

        let end = offset + buf.len() as u64;
        {
            let mut overlay = self.state.overlay.write().unwrap();
            overlay.insert(offset, buf.to_vec());
        }
        {
            let mut size = self.state.logical_size.write().unwrap();
            if end > *size {
                *size = end;
            }
        }
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        Ok(()) // No-op; flushing happens via drain_to/finalize.
    }

    fn file_size(&self) -> Result<u64> {
        Ok(*self.state.logical_size.read().unwrap())
    }

    fn set_len(&self, size: u64) -> Result<()> {
        let mut logical = self.state.logical_size.write().unwrap();
        *logical = size;
        // Also grow inner if needed (inner.set_len is idempotent for MemoryBackend).
        let inner_size = self.state.inner.file_size()?;
        if size > inner_size {
            self.state.inner.set_len(size)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::MemoryBackend;

    fn make_backend() -> StreamingBackend {
        StreamingBackend::new(Box::new(MemoryBackend::zeroed(0))).unwrap()
    }

    fn make_backend_with_data(data: &[u8]) -> StreamingBackend {
        StreamingBackend::new(Box::new(MemoryBackend::new(data.to_vec()))).unwrap()
    }

    #[test]
    fn write_read_roundtrip() {
        let sb = make_backend();
        sb.write_all_at(b"hello", 0).unwrap();
        let mut buf = [0u8; 5];
        sb.read_exact_at(&mut buf, 0).unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn read_fallthrough_to_inner() {
        let sb = make_backend_with_data(b"inner data here!");
        let mut buf = [0u8; 10];
        sb.read_exact_at(&mut buf, 0).unwrap();
        assert_eq!(&buf, b"inner data");
    }

    #[test]
    fn overlay_shadows_inner() {
        let sb = make_backend_with_data(&[0xAA; 16]);
        sb.write_all_at(&[0xBB; 4], 4).unwrap();
        let mut buf = [0u8; 16];
        sb.read_exact_at(&mut buf, 0).unwrap();
        assert_eq!(&buf[..4], &[0xAA; 4]);
        assert_eq!(&buf[4..8], &[0xBB; 4]);
        assert_eq!(&buf[8..], &[0xAA; 8]);
    }

    #[test]
    fn read_spanning_overlay_and_inner() {
        let sb = make_backend_with_data(&[0x11; 32]);
        // Overlay covers bytes 8..16
        sb.write_all_at(&[0x22; 8], 8).unwrap();
        // Read bytes 4..20 (spans inner + overlay + inner)
        let mut buf = [0u8; 16];
        sb.read_exact_at(&mut buf, 4).unwrap();
        assert_eq!(&buf[..4], &[0x11; 4]); // 4..8 from inner
        assert_eq!(&buf[4..12], &[0x22; 8]); // 8..16 from overlay
        assert_eq!(&buf[12..], &[0x11; 4]); // 16..20 from inner
    }

    #[test]
    fn read_spanning_multiple_entries() {
        let sb = make_backend();
        sb.write_all_at(b"AAAA", 0).unwrap();
        sb.write_all_at(b"BBBB", 8).unwrap();
        // Read 0..12, gap at 4..8 should be zeros
        let mut buf = [0u8; 12];
        sb.read_exact_at(&mut buf, 0).unwrap();
        assert_eq!(&buf[..4], b"AAAA");
        assert_eq!(&buf[4..8], &[0; 4]);
        assert_eq!(&buf[8..], b"BBBB");
    }

    #[test]
    fn drain_to_basic() {
        let sb = make_backend();
        sb.write_all_at(b"first", 0).unwrap();
        sb.write_all_at(b"second", 0x100).unwrap();
        sb.write_all_at(b"third", 0x200).unwrap();

        assert_eq!(sb.overlay_entries(), 3);

        // Drain entries below 0x200
        sb.drain_to(0x200).unwrap();

        assert_eq!(sb.overlay_entries(), 1); // only "third" remains
        assert_eq!(sb.drained_up_to(), 0x200); // boundary with zero-fill

        // Verify inner has the data
        let mut buf = [0u8; 5];
        // Read from inner directly would require access, but we can read
        // through the streaming backend which falls through to inner for drained data
        sb.read_exact_at(&mut buf, 0).unwrap();
        assert_eq!(&buf, b"first");
    }

    #[test]
    fn write_below_drain_errors() {
        let sb = make_backend();
        sb.write_all_at(b"data", 0).unwrap();
        sb.drain_to(100).unwrap();

        let result = sb.write_all_at(b"bad", 50);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::WriteBelowDrain {
                write_offset,
                drained_up_to,
            } => {
                assert_eq!(write_offset, 50);
                assert_eq!(drained_up_to, 100);
            }
            other => panic!("expected WriteBelowDrain, got: {other}"),
        }
    }

    #[test]
    fn finalize_drains_all() {
        let sb = make_backend();
        sb.write_all_at(b"one", 0).unwrap();
        sb.write_all_at(b"two", 100).unwrap();
        sb.write_all_at(b"three", 200).unwrap();

        sb.finalize().unwrap();

        assert_eq!(sb.overlay_entries(), 0);
        assert_eq!(sb.overlay_bytes(), 0);

        // All data should be readable via inner fallthrough
        let mut buf = [0u8; 3];
        sb.read_exact_at(&mut buf, 200).unwrap();
        assert_eq!(&buf, b"thr");
    }

    #[test]
    fn file_size_tracks_writes() {
        let sb = make_backend();
        assert_eq!(sb.file_size().unwrap(), 0);

        sb.write_all_at(b"hello", 100).unwrap();
        assert_eq!(sb.file_size().unwrap(), 105);

        sb.write_all_at(b"world", 200).unwrap();
        assert_eq!(sb.file_size().unwrap(), 205);

        // Write that doesn't extend size
        sb.write_all_at(b"x", 50).unwrap();
        assert_eq!(sb.file_size().unwrap(), 205);
    }

    #[test]
    fn set_len_updates_size() {
        let sb = make_backend();
        sb.set_len(1024).unwrap();
        assert_eq!(sb.file_size().unwrap(), 1024);
    }

    #[test]
    fn overlapping_writes() {
        let sb = make_backend();
        sb.write_all_at(b"AAAA", 0).unwrap();
        // Overwrite at same offset
        sb.write_all_at(b"BB", 0).unwrap();

        let mut buf = [0u8; 4];
        sb.read_exact_at(&mut buf, 0).unwrap();
        // BTreeMap::insert replaces at same key, so the old "AAAA" is gone
        // and we have "BB" at offset 0 (2 bytes) + zeros
        assert_eq!(&buf[..2], b"BB");
        assert_eq!(&buf[2..], &[0; 2]);
    }

    #[test]
    fn drain_skips_straddling_entries() {
        let sb = make_backend();
        // Entry at 0x8000 with 0x10000 bytes (ends at 0x18000)
        sb.write_all_at(&vec![0xAA; 0x10000], 0x8000).unwrap();

        // Drain to 0x10000 — entry straddles boundary, should NOT be drained
        sb.drain_to(0x10000).unwrap();

        assert_eq!(sb.overlay_entries(), 1);
        // drained_up_to advances to boundary (0x10000) with zero-fill for the gap
        assert_eq!(sb.drained_up_to(), 0x10000);
    }

    #[test]
    fn overlay_bytes_tracking() {
        let sb = make_backend();
        assert_eq!(sb.overlay_bytes(), 0);

        sb.write_all_at(&[1; 100], 0).unwrap();
        assert_eq!(sb.overlay_bytes(), 100);

        sb.write_all_at(&[2; 50], 200).unwrap();
        assert_eq!(sb.overlay_bytes(), 150);

        sb.drain_to(200).unwrap();
        assert_eq!(sb.overlay_bytes(), 50); // only second entry remains
    }

    #[test]
    fn drain_fills_gaps_with_zeros() {
        let sb = make_backend();
        // Write at offset 100 and 300, leaving gaps 0..100 and 105..300
        sb.write_all_at(b"AAAAA", 100).unwrap();
        sb.write_all_at(b"BBBBB", 300).unwrap();

        sb.drain_to(400).unwrap();

        // Read through to verify zeros filled the gaps
        let mut buf = [0u8; 310];
        sb.read_exact_at(&mut buf, 0).unwrap();

        // 0..100 should be zeros (gap fill)
        assert!(buf[..100].iter().all(|&b| b == 0));
        // 100..105 should be 'A'
        assert_eq!(&buf[100..105], b"AAAAA");
        // 105..300 should be zeros (gap fill)
        assert!(buf[105..300].iter().all(|&b| b == 0));
        // 300..305 should be 'B'
        assert_eq!(&buf[300..305], b"BBBBB");
    }

    #[test]
    fn clone_shares_state() {
        let sb = make_backend();
        let handle = sb.clone();

        sb.write_all_at(b"shared", 0).unwrap();

        let mut buf = [0u8; 6];
        handle.read_exact_at(&mut buf, 0).unwrap();
        assert_eq!(&buf, b"shared");

        handle.drain_to(10).unwrap();
        assert_eq!(sb.drained_up_to(), 10);
    }

    // ---- Edge cases ----

    #[test]
    fn write_at_exact_drain_boundary_succeeds() {
        let sb = make_backend();
        sb.write_all_at(b"data", 0).unwrap();
        sb.drain_to(100).unwrap();

        // Write exactly at the boundary should succeed
        sb.write_all_at(b"ok", 100).unwrap();
        let mut buf = [0u8; 2];
        sb.read_exact_at(&mut buf, 100).unwrap();
        assert_eq!(&buf, b"ok");
    }

    #[test]
    fn write_at_zero_on_fresh_backend_succeeds() {
        let sb = make_backend();
        // drained_up_to is 0, write at 0 should work (not below drain)
        sb.write_all_at(b"start", 0).unwrap();
        let mut buf = [0u8; 5];
        sb.read_exact_at(&mut buf, 0).unwrap();
        assert_eq!(&buf, b"start");
    }

    #[test]
    fn drain_to_zero_is_noop() {
        let sb = make_backend();
        sb.write_all_at(b"data", 0).unwrap();
        sb.drain_to(0).unwrap();
        assert_eq!(sb.overlay_entries(), 1);
        assert_eq!(sb.drained_up_to(), 0);
    }

    #[test]
    fn double_drain_same_boundary() {
        let sb = make_backend();
        sb.write_all_at(b"data", 0).unwrap();
        sb.drain_to(100).unwrap();
        // Second drain to same boundary is a no-op
        sb.drain_to(100).unwrap();
        assert_eq!(sb.drained_up_to(), 100);
    }

    #[test]
    fn read_beyond_logical_size_returns_zeros() {
        let sb = make_backend();
        sb.set_len(1024).unwrap();
        let mut buf = [0xFFu8; 16];
        sb.read_exact_at(&mut buf, 500).unwrap();
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn empty_write_succeeds() {
        let sb = make_backend();
        sb.write_all_at(&[], 0).unwrap();
        assert_eq!(sb.overlay_entries(), 1);
        assert_eq!(sb.overlay_bytes(), 0);
    }

    #[test]
    fn write_after_finalize_errors() {
        let sb = make_backend();
        sb.write_all_at(b"data", 0).unwrap();
        sb.finalize().unwrap();

        // After finalize, drained_up_to is at logical end, so any write below errors
        let result = sb.write_all_at(b"nope", 0);
        assert!(matches!(result, Err(Error::WriteBelowDrain { .. })));
    }

    #[test]
    fn multiple_drains_progressive() {
        let sb = make_backend();
        sb.write_all_at(b"A", 0).unwrap();
        sb.write_all_at(b"B", 100).unwrap();
        sb.write_all_at(b"C", 200).unwrap();

        sb.drain_to(50).unwrap();
        assert_eq!(sb.drained_up_to(), 50);
        assert_eq!(sb.overlay_entries(), 2); // B and C remain

        sb.drain_to(150).unwrap();
        assert_eq!(sb.drained_up_to(), 150);
        assert_eq!(sb.overlay_entries(), 1); // only C remains

        sb.drain_to(300).unwrap();
        assert_eq!(sb.drained_up_to(), 300);
        assert_eq!(sb.overlay_entries(), 0);
    }

    #[test]
    fn drain_preserves_data_integrity() {
        let sb = make_backend();
        // Write sequential known data
        for i in 0u8..10 {
            let data = vec![i; 64];
            sb.write_all_at(&data, i as u64 * 64).unwrap();
        }

        // Drain in stages and verify after each
        sb.drain_to(256).unwrap();
        sb.drain_to(640).unwrap();

        // Verify all data is intact after draining
        for i in 0u8..10 {
            let mut buf = [0u8; 64];
            sb.read_exact_at(&mut buf, i as u64 * 64).unwrap();
            assert!(buf.iter().all(|&b| b == i), "chunk {i} corrupted");
        }
    }
}
