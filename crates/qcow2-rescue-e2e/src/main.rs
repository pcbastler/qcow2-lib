mod config;
mod corruptor;
mod fs_setup;
mod image_gen;
mod recovery;
mod runner;
mod validator;

use std::path::PathBuf;
use std::process;

fn usage() -> ! {
    eprintln!("Usage:");
    eprintln!("  qcow2-rescue-e2e generate <output-dir>     Generate test images (needs root/Docker)");
    eprintln!("  qcow2-rescue-e2e test <images-dir>         Run corruption + recovery tests (host)");
    process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        usage();
    }

    let command = &args[1];
    let dir = PathBuf::from(&args[2]);

    match command.as_str() {
        "generate" => {
            println!("=== qcow2-rescue e2e: generating test images ===");
            println!("output: {}", dir.display());
            std::fs::create_dir_all(&dir).unwrap();

            if let Err(e) = runner::generate_all(&dir) {
                eprintln!("FATAL: {e}");
                process::exit(1);
            }
            println!("=== generation complete ===");
        }
        "test" => {
            println!("=== qcow2-rescue e2e: running tests ===");
            println!("images: {}", dir.display());

            let rescue_bin = PathBuf::from(
                std::env::var("QCOW2_RESCUE_BIN")
                    .unwrap_or_else(|_| "qcow2-rescue".into()),
            );

            let results = runner::test_all(&dir, &rescue_bin);

            println!();
            runner::print_matrix(&results);

            let total = results.len();
            let passed = results.iter().filter(|r| r.passed).count();
            let failed = total - passed;

            if failed > 0 {
                process::exit(1);
            }
        }
        _ => usage(),
    }
}
