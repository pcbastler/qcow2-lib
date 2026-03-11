use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Compare the recovered raw image with the reference raw image.
/// Returns (matching_sectors, total_sectors, mismatched_ranges).
pub fn compare_raw_images(
    reference: &Path,
    recovered: &Path,
) -> Result<CompareResult, String> {
    let mut ref_file = File::open(reference)
        .map_err(|e| format!("open reference {}: {e}", reference.display()))?;
    let mut rec_file = File::open(recovered)
        .map_err(|e| format!("open recovered {}: {e}", recovered.display()))?;

    let ref_size = ref_file.metadata().map_err(|e| format!("metadata: {e}"))?.len();
    let rec_size = rec_file.metadata().map_err(|e| format!("metadata: {e}"))?.len();

    // Use the smaller size for comparison
    let compare_size = ref_size.min(rec_size);
    let sector_size = 512u64;
    let total_sectors = compare_size / sector_size;

    let mut matching = 0u64;
    let mut mismatched_ranges: Vec<(u64, u64)> = Vec::new();
    let mut in_mismatch = false;
    let mut mismatch_start = 0u64;

    let mut ref_buf = vec![0u8; sector_size as usize];
    let mut rec_buf = vec![0u8; sector_size as usize];

    for sector in 0..total_sectors {
        let offset = sector * sector_size;

        ref_file.seek(SeekFrom::Start(offset)).map_err(|e| format!("seek: {e}"))?;
        rec_file.seek(SeekFrom::Start(offset)).map_err(|e| format!("seek: {e}"))?;

        ref_file.read_exact(&mut ref_buf).map_err(|e| format!("read ref: {e}"))?;
        rec_file.read_exact(&mut rec_buf).map_err(|e| format!("read rec: {e}"))?;

        if ref_buf == rec_buf {
            matching += 1;
            if in_mismatch {
                mismatched_ranges.push((mismatch_start, sector - 1));
                in_mismatch = false;
            }
        } else if !in_mismatch {
            mismatch_start = sector;
            in_mismatch = true;
        }
    }

    if in_mismatch {
        mismatched_ranges.push((mismatch_start, total_sectors - 1));
    }

    Ok(CompareResult {
        reference_size: ref_size,
        recovered_size: rec_size,
        compared_sectors: total_sectors,
        matching_sectors: matching,
        mismatched_ranges,
    })
}

#[derive(Debug)]
pub struct CompareResult {
    pub reference_size: u64,
    pub recovered_size: u64,
    pub compared_sectors: u64,
    pub matching_sectors: u64,
    pub mismatched_ranges: Vec<(u64, u64)>,
}

impl CompareResult {
    pub fn match_percent(&self) -> f64 {
        if self.compared_sectors == 0 {
            return 0.0;
        }
        (self.matching_sectors as f64 / self.compared_sectors as f64) * 100.0
    }

    #[allow(dead_code)]
    pub fn is_perfect(&self) -> bool {
        self.matching_sectors == self.compared_sectors && self.reference_size == self.recovered_size
    }
}

impl std::fmt::Display for CompareResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{} sectors match ({:.1}%), {} mismatched ranges, ref={} rec={}",
            self.matching_sectors,
            self.compared_sectors,
            self.match_percent(),
            self.mismatched_ranges.len(),
            self.reference_size,
            self.recovered_size,
        )
    }
}
