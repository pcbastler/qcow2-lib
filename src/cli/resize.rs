//! `resize` subcommand: grow a QCOW2 image's virtual size.

use std::path::Path;

use qcow2_lib::engine::image::Qcow2Image;
use qcow2_lib::error::Result;

/// Run the resize subcommand.
pub fn run(path: &Path, size_str: &str) -> Result<()> {
    let new_size = parse_size(size_str).map_err(|msg| qcow2_lib::error::Error::ConversionFailed {
        message: msg,
    })?;

    let mut image = Qcow2Image::open_rw(path)?;
    let old_size = image.virtual_size();
    image.resize(new_size)?;
    image.flush()?;

    println!(
        "Resized {} from {} to {} ({}).",
        path.display(),
        format_size(old_size),
        format_size(new_size),
        size_str,
    );
    Ok(())
}

/// Parse a human-readable size string with optional K/M/G/T suffix.
fn parse_size(s: &str) -> std::result::Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty size string".to_string());
    }

    let (num_str, multiplier) = match s.as_bytes().last() {
        Some(b'T' | b't') => (&s[..s.len() - 1], 1024u64 * 1024 * 1024 * 1024),
        Some(b'G' | b'g') => (&s[..s.len() - 1], 1024u64 * 1024 * 1024),
        Some(b'M' | b'm') => (&s[..s.len() - 1], 1024u64 * 1024),
        Some(b'K' | b'k') => (&s[..s.len() - 1], 1024u64),
        _ => (s, 1u64),
    };

    let num: u64 = num_str
        .parse()
        .map_err(|e| format!("invalid size '{s}': {e}"))?;

    num.checked_mul(multiplier)
        .ok_or_else(|| format!("size overflow: {s}"))
}

/// Format a byte size as a human-readable string.
fn format_size(bytes: u64) -> String {
    const GIB: u64 = 1024 * 1024 * 1024;
    const MIB: u64 = 1024 * 1024;

    if bytes >= GIB && bytes % GIB == 0 {
        format!("{} GiB", bytes / GIB)
    } else if bytes >= MIB && bytes % MIB == 0 {
        format!("{} MiB", bytes / MIB)
    } else {
        format!("{} bytes", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_size_plain_bytes() {
        assert_eq!(parse_size("65536").unwrap(), 65536);
    }

    #[test]
    fn parse_size_kilobytes() {
        assert_eq!(parse_size("64K").unwrap(), 65536);
        assert_eq!(parse_size("64k").unwrap(), 65536);
    }

    #[test]
    fn parse_size_megabytes() {
        assert_eq!(parse_size("10M").unwrap(), 10 * 1024 * 1024);
        assert_eq!(parse_size("10m").unwrap(), 10 * 1024 * 1024);
    }

    #[test]
    fn parse_size_gigabytes() {
        assert_eq!(parse_size("2G").unwrap(), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_size("2g").unwrap(), 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn parse_size_terabytes() {
        assert_eq!(parse_size("1T").unwrap(), 1024u64 * 1024 * 1024 * 1024);
    }

    #[test]
    fn parse_size_invalid() {
        assert!(parse_size("abc").is_err());
        assert!(parse_size("").is_err());
        // Overflow through multiplication
        assert!(parse_size("17179869184G").is_err(), "should reject overflow");
        // Suffix without number
        assert!(parse_size("K").is_err(), "should reject bare suffix");
        // Decimal number
        assert!(parse_size("1.5M").is_err(), "should reject decimal");
    }
}
