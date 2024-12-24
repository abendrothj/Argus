use std::env::current_dir;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;
use serde::{Serialize, Deserialize};
use std::fs::{canonicalize, create_dir_all, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use clap::{Arg, ArgAction, Command};
use tokio::sync::mpsc;
use notify::{RecommendedWatcher, RecursiveMode, Watcher, Event, EventKind};

#[derive(Serialize, Deserialize)]
struct FileRecord {
    path: String,
    checksum: String,
}
async fn start_monitoring(directory: &str) -> notify::Result<()> {
    let (tx, mut rx) = mpsc::channel(100);
    let mut watcher = RecommendedWatcher::new(move |res| {
        let _ = tx.blocking_send(res);
    }, Default::default())?;
    watcher.watch(Path::new(directory), RecursiveMode::Recursive)?;

    println!("Started watching directory {}", directory);
    while let Some(res) = rx.recv().await {
        match res {
            Ok(event) => handle_event(event),
            Err(e) => println!("watch error: {:?}", e),
        }
    }

    Ok(())
}

fn handle_event(event: Event) {
    println!("Event detected: {:?}", event);

    for path in &event.paths {
        match &event.kind {
            EventKind::Modify(modification) => {
                match modification {
                    notify::event::ModifyKind::Data(_) => {
                        println!("Data modified: {}", path.display());
                    }
                    notify::event::ModifyKind::Metadata(_) => {
                        println!("Metadata modified: {}", path.display());
                    }
                    notify::event::ModifyKind::Name(_) => {
                        println!("Name modified: {}", path.display());
                    }
                    _ => {
                        println!("Other modification: {:?}", event);
                    }
                }
            }
            EventKind::Create(_) => {
                println!("File created: {}", path.display());
            }
            EventKind::Remove(_) => {
                println!("File removed: {}", path.display());
            }
            EventKind::Access(_) => {
                println!("File access: {}", path.display());
            }
            _ => {
                println!("Other event detected: {:?}", event);
            }
        }
    }
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

    for entry in WalkDir::new(dir).follow_links(false).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() {
            match canonicalize(path) {
                Ok(abs_path) => {
                    let abs_path_str = abs_path.to_string_lossy().to_string();
                    println!("Processing file: {}", abs_path_str);

                    match calculate_checksum(&abs_path_str) {
                        Ok(checksum) => records.push(FileRecord { path: abs_path_str, checksum }),
                        Err(e) => println!("Error while processing file: {}\n{}", abs_path_str, e),
                    }
                }
                Err(e) => eprintln!("Couldn't get absolute path for {}: {}", path.display(), e),
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
#[tokio::main]
async fn main() -> io::Result<()> {
    // Set up command-line argument parsing using clap (4.x version)
    let matches = Command::new("File Integrity Checker")
        .version("1.0")
        .author("Jake Abendroth - jake@jakea.net")
        .about("Scans files in a directory and saves their checksums in NDJSON format")
        .arg(
            Arg::new("directory")
                .short('d')
                .long("directory")
                .value_name("DIR")
                .help("The directory to scan")
                .default_value("./") // Default is the current directory
                .value_parser(directory_checker),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("The output file to save the checksums")
                .default_value("file_integrity.ndjson")
                .value_parser(output_file_checker),
        )
        .arg(
            Arg::new("monitor")
                .short('m')
                .long("monitor")
                .help("Enables monitoring on the given directory.")
                .action(ArgAction::SetTrue),
        )
        .get_matches();

    // Get values from the command-line arguments
    let directory = matches.get_one::<String>("directory").unwrap();
    let output_file = matches.get_one::<String>("output").unwrap();
    let monitor_mode = matches.get_flag("monitor");

    if monitor_mode {
        println!("Monitoring directory: {}", directory);
        if let Err(e) = start_monitoring(directory).await {
            eprintln!("Couldn't start monitoring: {}", e);
        }
    } else {
        println!("Scanning directory: {}", directory);
        let records = scan_directory(directory)?;

        for record in records {
            save_to_ndjson(&record, output_file)?;
        }

        println!("Integrity data saved to {}", output_file);
    }

    Ok(())
}

//
// Value_Parser functions
//
fn directory_checker(s: &str) -> Result<String, String> {
    let path = Path::new(s);
    if !path.exists() {
        return Err("Directory doesn't exist".into());
    }
    else if !path.is_dir() {
        return Err("Path does not point at a directory.".into());
    }
    else if path.read_dir().is_err() {
        return Err("Directory not readable, could be because of permissions.".into());
    }
    Ok(s.to_string())
}
fn output_file_checker(val: &str) -> Result<String, String> {
    let path = Path::new(val);
    let mut full_path = path.to_path_buf();

    // If the path is relative, use the current directory as the base
    if !path.is_absolute() {
        if let Ok(current_dir) = current_dir() {
            full_path = current_dir.join(path);
        } else {
            return Err("Could not determine the current working directory.".into());
        }
    }
    if let Some(parent_dir) = full_path.parent() {
        // If specified location is in folders that don't exist, we will create them
        if parent_dir != Path::new("/") {
            if let Err(e) = create_dir_all(parent_dir) {
                return Err(format!("Failed to create directory {}: {}", parent_dir.display(), e));
            }
        }
    }

    // Try to create or open the file (in append mode)
    if let Err(e) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&full_path)
    {
        return Err(format!("Failed to open output file '{}': {}", full_path.display(), e));
    }

    Ok(val.to_string())
}