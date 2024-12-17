use sha2::{Digest, Sha256};
use walkdir::WalkDir;
use serde::{Serialize, Deserialize};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use clap::{Arg, Command};

#[derive(Serialize, Deserialize)]
struct FileRecord {
    path: String,
    checksum: String,
}

fn calculate_checksum(path: &str) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    hasher.update(buffer);
    // Format hashed bits into lowercase hex
    Ok(format!("{:x}", hasher.finalize()))
}

fn scan_directory(dir: &str) -> io::Result<Vec<FileRecord>> {
    let mut records = Vec::new();

    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() {
            let path_str = path.to_string_lossy().to_string();
            println!("Processing: {}", path_str);
            match calculate_checksum(&path_str) {
                Ok(checksum) => records.push(FileRecord { path: path_str, checksum }),
                Err(e) => eprintln!("Failed to process {}: {}", path_str, e),
            }
        }
    }

    Ok(records)
}

// Updated to append each record as a new JSON object in NDJSON format
fn save_to_ndjson(record: &FileRecord, output: &str) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .create(true) // Creates the file if it does not exist
        .append(true) // Appends data to the file if it already exists
        .open(output)?;

    let json_string = serde_json::to_string(record)?; // Serialize the record to JSON
    writeln!(file, "{}", json_string)?; // Write the JSON string followed by a newline
    Ok(())
}

fn main() -> io::Result<()> {
    // Set up command-line argument parsing using clap (4.x version)
    let matches = Command::new("File Integrity Checker")
        .version("1.0")
        .author("Your Name <your-email@example.com>")
        .about("Scans files in a directory and saves their checksums in NDJSON format")
        .arg(
            Arg::new("directory")
                .short('d')
                .long("directory")
                .value_name("DIR")
                .help("The directory to scan")
                .default_value("./"), // Default is the current directory
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("The output file to save the checksums")
                .default_value("file_integrity.ndjson"), // Default output file
        )
        .get_matches();

    // Get values from the command-line arguments
    let directory = matches.get_one::<String>("directory").unwrap();
    let output_file = matches.get_one::<String>("output").unwrap();

    println!("Scanning directory: {}", directory);
    let records = scan_directory(directory)?;

    // Loop through all records and append each one to the file
    for record in records {
        save_to_ndjson(&record, output_file)?;
    }

    println!("Integrity data saved to {}", output_file);

    Ok(())
}
