use std::env::current_dir;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;
use serde::{Serialize, Deserialize};
use std::fs::{canonicalize, create_dir_all, File, OpenOptions};
use std::io::{self, Read, Write, BufRead};
use std::path::Path;
use clap::{Arg, ArgAction, Command};
use tokio::sync::mpsc;
use notify::{RecommendedWatcher, RecursiveMode, Watcher, Event, EventKind};
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Clone)]
struct FileRecord {
    path: String,
    checksum: String,
    timestamp: u64,
    size: u64,
}

#[derive(Serialize, Deserialize)]
struct ComparisonResult {
    added_files: Vec<FileRecord>,
    removed_files: Vec<FileRecord>,
    modified_files: Vec<FileChange>,
    stats: ComparisonStats,
}

#[derive(Serialize, Deserialize)]
struct FileChange {
    path: String,
    old_checksum: String,
    new_checksum: String,
    old_timestamp: u64,
    new_timestamp: u64,
    old_size: u64,
    new_size: u64,
}

#[derive(Serialize, Deserialize)]
struct ComparisonStats {
    total_files_old: usize,
    total_files_new: usize,
    files_added: usize,
    files_removed: usize,
    files_modified: usize,
    total_size_change: i64,
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

                    let metadata = entry.metadata()?;
                    let timestamp = metadata.modified()
                        .unwrap_or(UNIX_EPOCH)
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    match calculate_checksum(&abs_path_str) {
                        Ok(checksum) => records.push(FileRecord {
                            path: abs_path_str,
                            checksum,
                            timestamp,
                            size: metadata.len(),
                        }),
                        Err(e) => println!("Error while processing file: {}\n{}", abs_path_str, e),
                    }
                }
                Err(e) => eprintln!("Couldn't get absolute path for {}: {}", path.display(), e),
            }
        }
    }

    Ok(records)
}

fn compare_with_existing(file_path: &Path, new_records: &[FileRecord]) -> io::Result<ComparisonResult> {
    let file = File::open(file_path).map_err(|e| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("Failed to open compare file {}: {}", file_path.display(), e)
        )
    })?;

    let mut existing_records = Vec::new();
    for line in io::BufReader::new(file).lines() {
        if let Ok(record_line) = line {
            if let Ok(record) = serde_json::from_str::<FileRecord>(&record_line) {
                existing_records.push(record);
            }
        }
    }

    // Create maps for faster lookup
    let existing_map: HashMap<_, _> = existing_records.iter()
        .map(|r| (&r.path, r))
        .collect();
    let new_map: HashMap<_, _> = new_records.iter()
        .map(|r| (&r.path, r))
        .collect();

    let mut added_files = Vec::new();
    let mut removed_files = Vec::new();
    let mut modified_files = Vec::new();
    let mut total_size_change: i64 = 0;

    // Find added and modified files
    for new_record in new_records {
        match existing_map.get(&new_record.path) {
            Some(existing) => {
                if existing.checksum != new_record.checksum {
                    modified_files.push(FileChange {
                        path: new_record.path.clone(),
                        old_checksum: existing.checksum.clone(),
                        new_checksum: new_record.checksum.clone(),
                        old_timestamp: existing.timestamp,
                        new_timestamp: new_record.timestamp,
                        old_size: existing.size,
                        new_size: new_record.size,
                    });
                    total_size_change += new_record.size as i64 - existing.size as i64;
                }
            }
            None => {
                added_files.push(new_record.clone());
                total_size_change += new_record.size as i64;
            }
        }
    }

    // Find removed files
    for existing_record in existing_records {
        if !new_map.contains_key(&existing_record.path) {
            removed_files.push(existing_record.clone());
            total_size_change -= existing_record.size as i64;
        }
    }

    let stats = ComparisonStats {
        total_files_old: existing_records.len(),
        total_files_new: new_records.len(),
        files_added: added_files.len(),
        files_removed: removed_files.len(),
        files_modified: modified_files.len(),
        total_size_change,
    };

    Ok(ComparisonResult {
        added_files,
        removed_files,
        modified_files,
        stats,
    })
}

fn save_comparison_results(results: &ComparisonResult, output_file: &str) -> io::Result<()> {
    let mut file = File::create(output_file)?;
    
    writeln!(file, "Comparison Results Summary:")?;
    writeln!(file, "==========================")?;
    writeln!(file, "Total files in old snapshot: {}", results.stats.total_files_old)?;
    writeln!(file, "Total files in new snapshot: {}", results.stats.total_files_new)?;
    writeln!(file, "Files added: {}", results.stats.files_added)?;
    writeln!(file, "Files removed: {}", results.stats.files_removed)?;
    writeln!(file, "Files modified: {}", results.stats.files_modified)?;
    writeln!(file, "Total size change: {} bytes", results.stats.total_size_change)?;
    writeln!(file)?;

    if !results.added_files.is_empty() {
        writeln!(file, "Added Files:")?;
        writeln!(file, "------------")?;
        for file_record in &results.added_files {
            writeln!(file, "  + {} ({} bytes)", file_record.path, file_record.size)?;
        }
        writeln!(file)?;
    }

    if !results.removed_files.is_empty() {
        writeln!(file, "Removed Files:")?;
        writeln!(file, "--------------")?;
        for file_record in &results.removed_files {
            writeln!(file, "  - {} ({} bytes)", file_record.path, file_record.size)?;
        }
        writeln!(file)?;
    }

    if !results.modified_files.is_empty() {
        writeln!(file, "Modified Files:")?;
        writeln!(file, "--------------")?;
        for change in &results.modified_files {
            writeln!(file, "  * {}", change.path)?;
            writeln!(file, "    Size: {} -> {} bytes", change.old_size, change.new_size)?;
            writeln!(file, "    Checksum: {} -> {}", change.old_checksum, change.new_checksum)?;
            writeln!(file)?;
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> io::Result<()> {
    // Set up command-line argument parsing using clap (4.x version)
    let matches = Command::new("File Integrity Checker")
        .version("1.0")
        .author("Jake Abendroth")
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
        .arg(
            Arg::new("compare")
                .short('c')
                .long("compare")
                .value_name("FILE")
                .help("Compare current directory state with an existing checksum file"),
        )
        .arg(
            Arg::new("report")
                .short('r')
                .long("report")
                .value_name("FILE")
                .help("Output file for the comparison report (defaults to report.txt)")
                .default_value("report.txt"),
        )
        .get_matches();

    // Get values from the command-line arguments
    let directory = matches.get_one::<String>("directory").unwrap();
    let output_file = matches.get_one::<String>("output").unwrap();
    let monitor_mode = matches.get_flag("monitor");
    let compare_file = matches.get_one::<String>("compare");
    let report_file = matches.get_one::<String>("report").unwrap();

    if monitor_mode {
        println!("Monitoring directory: {}", directory);
        if let Err(e) = start_monitoring(directory).await {
            eprintln!("Couldn't start monitoring: {}", e);
        }
    } else {
        println!("Scanning directory: {}", directory);
        let records = scan_directory(directory)?;

        if let Some(compare_path) = compare_file {
            let cmp_path = Path::new(compare_path);
            if cmp_path.exists() {
                println!("Comparing with existing file: '{}'", compare_path);
                let results = compare_with_existing(&cmp_path, &records)?;
                
                // Print summary to console
                println!("\nComparison Summary:");
                println!("==================");
                println!("Total files in old snapshot: {}", results.stats.total_files_old);
                println!("Total files in new snapshot: {}", results.stats.total_files_new);
                println!("Files added: {}", results.stats.files_added);
                println!("Files removed: {}", results.stats.files_removed);
                println!("Files modified: {}", results.stats.files_modified);
                println!("Total size change: {} bytes", results.stats.total_size_change);
                
                // Save detailed report
                println!("\nSaving detailed report to '{}'", report_file);
                save_comparison_results(&results, report_file)?;
            } else {
                eprintln!("Compare file '{}' does not exist. Proceeding to write new checksums.", compare_path);
            }
        }

        // Save the new checksums
        let mut output = File::create(output_file)?;
        for record in records {
            let json_string = serde_json::to_string(&record)?;
            writeln!(output, "{}", json_string)?;
        }

        println!("Integrity data saved to '{}'", output_file);
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
