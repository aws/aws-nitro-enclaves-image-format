use std::env;
use std::fs::{self, File};
use std::io::{self, Write};
use aws_nitro_enclaves_image_format::defs::{EifSectionType};
use aws_nitro_enclaves_image_format::utils::eif_reader::EifSectionIterator;

fn extract_ramdisks(eif_path: &str, output_dir: &str, prefix: &str) -> io::Result<()> {
    println!("Starting extraction process...");

    // Open the EIF file
    let eif_file = File::open(eif_path).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    // Ensure the output directory exists
    fs::create_dir_all(output_dir)?;

    // Create the section iterator
    let iterator = EifSectionIterator::new(eif_file);
    let mut ramdisk_count = 0;

    println!("Reading section data...");
    for section_result in iterator {
        let (section, _, data) = section_result.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        if section.section_type == EifSectionType::EifSectionRamdisk {
            let output_file_path = format!("{}/{}{}.dat", output_dir, prefix, ramdisk_count);
            let mut output_file = File::create(&output_file_path)?;
            output_file.write_all(&data)?;
            println!("Saved ramdisk to {}", output_file_path);
            ramdisk_count += 1;
        }
    }

    if ramdisk_count == 0 {
        eprintln!("No Ramdisk sections found");
        return Err(io::Error::new(io::ErrorKind::NotFound, "No Ramdisk sections found"));
    }

    println!("Extraction completed successfully.");
    Ok(())
}

fn main() {
    // Collect the arguments passed to the program
    let args: Vec<String> = env::args().collect();

    // Check if we have received the correct number of arguments
    if args.len() != 4 {
        eprintln!("Usage: {} <EIF_PATH> <OUTPUT_DIR> <PREFIX>", args[0]);
        std::process::exit(1);
    }

    let eif_path = &args[1];
    let output_dir = &args[2];
    let prefix = &args[3];

    // Extract the ramdisks
    if let Err(e) = extract_ramdisks(eif_path, output_dir, prefix) {
        eprintln!("Failed to extract ramdisks: {}", e);
    } else {
        println!("Successfully extracted ramdisks to '{}'", output_dir);
    }
}
