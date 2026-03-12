//! Fast zero detection for cluster data.

/// Returns `true` if the entire buffer contains only zero bytes.
///
/// Uses `u64`-aligned comparison for performance on typical cluster sizes.
pub fn is_all_zeros(data: &[u8]) -> bool {
    // Safety: align_to splits the slice into prefix/middle/suffix where
    // middle is u64-aligned. All parts are checked for zeros.
    let (prefix, middle, suffix) = unsafe { data.align_to::<u64>() };
    prefix.iter().all(|&b| b == 0)
        && middle.iter().all(|&w| w == 0)
        && suffix.iter().all(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::vec;
    use super::*;

    #[test]
    fn empty_is_zeros() {
        assert!(is_all_zeros(&[]));
    }

    #[test]
    fn all_zeros() {
        assert!(is_all_zeros(&[0u8; 65536]));
    }

    #[test]
    fn single_nonzero_start() {
        let mut data = vec![0u8; 65536];
        data[0] = 1;
        assert!(!is_all_zeros(&data));
    }

    #[test]
    fn single_nonzero_end() {
        let mut data = vec![0u8; 65536];
        data[65535] = 1;
        assert!(!is_all_zeros(&data));
    }

    #[test]
    fn single_nonzero_middle() {
        let mut data = vec![0u8; 65536];
        data[32768] = 0xFF;
        assert!(!is_all_zeros(&data));
    }

    #[test]
    fn small_buffer() {
        assert!(is_all_zeros(&[0u8; 3]));
        assert!(!is_all_zeros(&[0, 0, 1]));
    }

    #[test]
    fn unaligned_buffer() {
        // Odd size that won't align perfectly to u64
        assert!(is_all_zeros(&[0u8; 13]));
        let mut data = [0u8; 13];
        data[7] = 1;
        assert!(!is_all_zeros(&data));
    }
}
