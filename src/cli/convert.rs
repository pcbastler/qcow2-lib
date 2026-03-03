//! `convert` subcommand: convert between QCOW2 and raw formats.

use std::path::Path;

use qcow2_lib::engine::converter;
use qcow2_lib::error::Result;

/// Detected input format.
enum InputFormat {
    Qcow2,
    Raw,
}

/// Desired output format.
#[derive(Clone, clap::ValueEnum)]
pub enum OutputFormat {
    /// QCOW2 format.
    Qcow2,
    /// Raw disk image.
    Raw,
}

/// Run the convert subcommand.
pub fn run(input: &Path, output: &Path, format: &OutputFormat, compress: bool) -> Result<()> {
    let input_format = detect_format(input)?;

    match (input_format, format) {
        (InputFormat::Qcow2, OutputFormat::Raw) => {
            converter::convert_to_raw(input, output)?;
            println!(
                "Converted {} (qcow2) -> {} (raw)",
                input.display(),
                output.display(),
            );
        }
        (InputFormat::Qcow2, OutputFormat::Qcow2) => {
            converter::convert_qcow2_to_qcow2(input, output, compress)?;
            let suffix = if compress { " (compressed)" } else { "" };
            println!(
                "Converted {} (qcow2) -> {} (qcow2){suffix}",
                input.display(),
                output.display(),
            );
        }
        (InputFormat::Raw, OutputFormat::Qcow2) => {
            converter::convert_from_raw(input, output, compress)?;
            let suffix = if compress { " (compressed)" } else { "" };
            println!(
                "Converted {} (raw) -> {} (qcow2){suffix}",
                input.display(),
                output.display(),
            );
        }
        (InputFormat::Raw, OutputFormat::Raw) => {
            return Err(qcow2_lib::error::Error::ConversionFailed {
                message: "raw-to-raw conversion is not supported".to_string(),
            });
        }
    }

    Ok(())
}

/// Detect whether the input file is QCOW2 or raw by checking the magic bytes.
fn detect_format(path: &Path) -> Result<InputFormat> {
    use std::fs::File;
    use std::io::Read;

    let mut file = File::open(path).map_err(|source| qcow2_lib::error::Error::Io {
        source,
        offset: 0,
        context: "opening input file for format detection",
    })?;

    let mut magic = [0u8; 4];
    if file.read_exact(&mut magic).is_ok() && &magic == b"QFI\xfb" {
        Ok(InputFormat::Qcow2)
    } else {
        Ok(InputFormat::Raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_format_qcow2() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.qcow2");
        // Write QCOW2 magic
        std::fs::write(&path, b"QFI\xfb\x00\x00\x00\x03").unwrap();
        assert!(matches!(detect_format(&path).unwrap(), InputFormat::Qcow2));
    }

    #[test]
    fn detect_format_raw() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.raw");
        std::fs::write(&path, &[0u8; 512]).unwrap();
        assert!(matches!(detect_format(&path).unwrap(), InputFormat::Raw));
    }

    #[test]
    fn detect_format_nonexistent() {
        let result = detect_format(Path::new("/nonexistent/file"));
        assert!(result.is_err(), "should return error for nonexistent file");
    }
}
