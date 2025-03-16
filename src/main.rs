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
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::collections::HashMap;
use rayon::prelude::*;
use indicatif::{ProgressBar, ProgressStyle, ParallelProgressIterator};
use ignore::{WalkBuilder, WalkState};

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

struct SaveResult {
    successful: usize,
    failed: usize,
    total_bytes: u64,
}

async fn start_monitoring(directory: &str) -> notify::Result<()> {
    let (tx, mut rx) = mpsc::channel(100);
    let mut watcher = RecommendedWatcher::new(move |res| {
        let _ = tx.blocking_send(res);
    }, Default::default())?;
    watcher.watch(Path::new(directory), RecursiveMode::Recursive)?;

    println!("Started watching directory {}", directory);
    println!("Press Ctrl+C to stop monitoring");

    while let Some(res) = rx.recv().await {
        match res {
            Ok(event) => handle_event(event),
            Err(e) => eprintln!("Watch error: {:?}", e),
        }
    }

    Ok(())
}

fn handle_event(event: Event) {
    for path in &event.paths {
        match &event.kind {
            EventKind::Modify(modification) => {
                match modification {
                    notify::event::ModifyKind::Data(_) => {
                        process_file_change(path, "modified");
                    }
                    notify::event::ModifyKind::Name(_) => {
                        println!("File renamed: {}", path.display());
                    }
                    _ => {} // Ignore other modification types
                }
            }
            EventKind::Create(_) => {
                process_file_change(path, "created");
            }
            EventKind::Remove(_) => {
                println!("File removed: {}", path.display());
            }
            _ => {} // Ignore other event types
        }
    }
}

fn process_file_change(path: &Path, action: &str) {
    if !path.is_file() {
        return;
    }

    match path.metadata() {
        Ok(metadata) => {
            let size = metadata.len();
            if size > MAX_FILE_SIZE {
                eprintln!("Skipping large file {}: {} bytes", path.display(), size);
                return;
            }

            match calculate_checksum(&path.to_string_lossy()) {
                Ok(checksum) => {
                    let timestamp = metadata.modified()
                        .unwrap_or(UNIX_EPOCH)
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    println!("File {}: {}", action, path.display());
                    println!("  Size: {} bytes", size);
                    println!("  Timestamp: {}", timestamp);
                    println!("  Checksum: {}", checksum);
                }
                Err(e) => eprintln!("Error calculating checksum for {} file {}: {}", 
                    action, path.display(), e),
            }
        }
        Err(e) => eprintln!("Error reading metadata for {} file {}: {}", 
            action, path.display(), e),
    }
}

const MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024; // 1GB
const BUFFER_SIZE: usize = 1024 * 1024; // 1MB

fn calculate_checksum(path: &str) -> io::Result<String> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    let file_size = metadata.len();

    if file_size > MAX_FILE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("File size {} bytes exceeds maximum allowed size of {} bytes", 
                file_size, MAX_FILE_SIZE)
        ));
    }

    let mut reader = io::BufReader::with_capacity(BUFFER_SIZE, file);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0; BUFFER_SIZE];
    let mut total_read = 0u64;

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        total_read += bytes_read as u64;
        hasher.update(&buffer[..bytes_read]);
    }

    if total_read != file_size {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("File size mismatch: expected {} bytes, read {} bytes", 
                file_size, total_read)
        ));
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn read_ignore_file(dir: &str) -> io::Result<Vec<String>> {
    let ignore_file = Path::new(dir).join(".argusignore");
    if ignore_file.exists() {
        let file = File::open(ignore_file)?;
        let reader = io::BufReader::new(file);
        Ok(reader.lines()
            .filter_map(|line| line.ok())
            .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
            .collect())
    } else {
        Ok(Vec::new())
    }
}

fn scan_directory(dir: &str, no_ignore: bool, no_git_ignore: bool) -> io::Result<Vec<FileRecord>> {
    // Build walker with ignore patterns
    let mut walker = WalkBuilder::new(dir);
    walker.hidden(false); // Include hidden files by default
    
    // Configure ignore patterns based on flags
    if !no_ignore {
        // Read and add .argusignore patterns
        match read_ignore_file(dir) {
            Ok(patterns) => {
                for pattern in patterns {
                    if let Err(e) = walker.add_ignore(pattern) {
                        eprintln!("Warning: Invalid ignore pattern: {}", e);
                    }
                }
            }
            Err(e) => eprintln!("Warning: Failed to read .argusignore: {}", e),
        }

        // Add .gitignore if not explicitly disabled
        if !no_git_ignore {
            walker.git_ignore(true);
            walker.add_custom_ignore_filename(".gitignore");
        } else {
            walker.git_ignore(false);
        }
    } else {
        // Disable all ignore patterns
        walker.git_ignore(false);
    }
    
    // Collect all file entries that aren't ignored
    let entries: Vec<_> = walker.build()
        .filter_map(|entry| match entry {
            Ok(entry) => {
                if entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
                    Some(entry)
                } else {
                    None
                }
            }
            Err(e) => {
                eprintln!("Warning: Failed to read entry: {}", e);
                None
            }
        })
        .collect();

    let total_files = entries.len();
    println!("Found {} files to process (after applying ignore patterns)", total_files);

    // Create progress tracking structures
    let pb = ProgressBar::new(total_files as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files ({percent}%) {binary_bytes_per_sec} ({binary_bytes}/{total_binary_bytes}) {msg}")
        .unwrap()
        .progress_chars("#>-"));

    let start_time = std::time::Instant::now();
    let processed_files = std::sync::atomic::AtomicUsize::new(0);
    let total_bytes = std::sync::atomic::AtomicU64::new(0);
    let pb_clone = pb.clone();

    // Process files in parallel with better error handling and progress tracking
    let records: Vec<FileRecord> = entries.into_par_iter()
        .filter_map(|entry| {
            let path = entry.path();
            match canonicalize(path) {
                Ok(abs_path) => {
                    let abs_path_str = abs_path.to_string_lossy().to_string();
                    
                    match entry.metadata() {
                        Ok(metadata) => {
                            let file_size = metadata.len();
                            // Skip files larger than 1GB
                            if file_size > MAX_FILE_SIZE {
                                eprintln!("Warning: Skipping large file {}: {} bytes", abs_path_str, file_size);
                                return None;
                            }

                            let timestamp = metadata.modified()
                                .unwrap_or(UNIX_EPOCH)
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();

                            match calculate_checksum(&abs_path_str) {
                                Ok(checksum) => {
                                    // Update progress atomically
                                    processed_files.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    total_bytes.fetch_add(file_size, std::sync::atomic::Ordering::Relaxed);
                                    
                                    // Update progress bar
                                    pb_clone.inc(1);
                                    pb_clone.set_length(total_bytes.load(std::sync::atomic::Ordering::Relaxed));
                                    
                                    Some(FileRecord {
                                        path: abs_path_str,
                                        checksum,
                                        timestamp,
                                        size: file_size,
                                    })
                                }
                                Err(e) => {
                                    eprintln!("Error calculating checksum for {}: {}", abs_path_str, e);
                                    None
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Error reading metadata for {}: {}", abs_path_str, e);
                            None
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Couldn't get absolute path for {}: {}", path.display(), e);
                    None
                }
            }
        })
        .collect();

    let duration = start_time.elapsed();
    let processed = processed_files.load(std::sync::atomic::Ordering::Relaxed);
    let bytes = total_bytes.load(std::sync::atomic::Ordering::Relaxed);
    
    pb.finish_with_message(format!(
        "Processed {} files ({:.2} MB) in {:.2}s ({:.2} MB/s)", 
        processed,
        bytes as f64 / 1024.0 / 1024.0,
        duration.as_secs_f64(),
        (bytes as f64 / 1024.0 / 1024.0) / duration.as_secs_f64()
    ));

    Ok(records)
}

fn compare_with_existing(file_path: &Path, new_records: &[FileRecord]) -> io::Result<ComparisonResult> {
    let file = File::open(file_path).map_err(|e| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("Failed to open NDJSON file {}: {}", file_path.display(), e)
        )
    })?;

    let mut existing_records = Vec::new();
    let mut parse_errors = 0;
    let reader = io::BufReader::new(file);

    for (line_num, line) in reader.lines().enumerate() {
        match line {
            Ok(record_line) => {
                if record_line.trim().is_empty() {
                    continue; // Skip empty lines
                }
                match serde_json::from_str::<FileRecord>(&record_line) {
                    Ok(record) => existing_records.push(record),
                    Err(e) => {
                        parse_errors += 1;
                        eprintln!(
                            "Warning: Invalid NDJSON record at line {}: {}",
                            line_num + 1,
                            e
                        );
                    }
                }
            }
            Err(e) => {
                parse_errors += 1;
                eprintln!(
                    "Warning: Failed to read line {} from NDJSON file: {}",
                    line_num + 1,
                    e
                );
            }
        }
    }

    if existing_records.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "No valid records found in NDJSON file. Total errors: {}",
                parse_errors
            )
        ));
    }

    if parse_errors > 0 {
        eprintln!(
            "Warning: {} errors occurred while reading NDJSON file. {} valid records found.",
            parse_errors,
            existing_records.len()
        );
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

fn save_records_to_ndjson(records: &[FileRecord], output_file: &str) -> io::Result<SaveResult> {
    let file = File::create(output_file)?;
    let mut writer = io::BufWriter::new(file);
    let mut result = SaveResult {
        successful: 0,
        failed: 0,
        total_bytes: 0,
    };
    
    for record in records {
        match serde_json::to_string(record) {
            Ok(json_string) => {
                if json_string.contains('\n') {
                    result.failed += 1;
                    eprintln!(
                        "Warning: Record for {} contains newline character (invalid in NDJSON format). Skipping.", 
                        record.path
                    );
                    continue;
                }

                match writeln!(writer, "{}", json_string) {
                    Ok(_) => {
                        result.successful += 1;
                        result.total_bytes += record.size;
                    }
                    Err(e) => {
                        result.failed += 1;
                        eprintln!(
                            "Error writing record for {}: {}. Skipping.", 
                            record.path, e
                        );
                    }
                }
            }
            Err(e) => {
                result.failed += 1;
                eprintln!(
                    "Error serializing record for {}: {}. Skipping.", 
                    record.path, e
                );
            }
        }
    }
    
    // Ensure all data is written
    writer.flush()?;

    if result.failed > 0 {
        eprintln!(
            "Warning: {} records failed to save, {} records saved successfully.",
            result.failed,
            result.successful
        );
    }

    Ok(result)
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
        .arg(
            Arg::new("threads")
                .short('t')
                .long("threads")
                .value_name("NUM")
                .help("Number of threads to use for parallel processing (default: number of CPU cores)")
                .value_parser(clap::value_parser!(usize)),
        )
        .arg(
            Arg::new("no-ignore")
                .long("no-ignore")
                .help("Don't use ignore patterns from .gitignore and .argusignore")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("no-git-ignore")
                .long("no-git-ignore")
                .help("Don't use ignore patterns from .gitignore")
                .action(ArgAction::SetTrue),
        )
        .get_matches();

    // Get values from the command-line arguments
    let directory = matches.get_one::<String>("directory").unwrap();
    let output_file = matches.get_one::<String>("output").unwrap();
    let monitor_mode = matches.get_flag("monitor");
    let compare_file = matches.get_one::<String>("compare");
    let report_file = matches.get_one::<String>("report").unwrap();
    let no_ignore = matches.get_flag("no-ignore");
    let no_git_ignore = matches.get_flag("no-git-ignore");

    // Configure thread pool if specified
    if let Some(thread_count) = matches.get_one::<usize>("threads") {
        rayon::ThreadPoolBuilder::new()
            .num_threads(*thread_count)
            .build_global()
            .unwrap_or_else(|e| eprintln!("Failed to set thread count: {}", e));
    }

    if monitor_mode {
        println!("Monitoring directory: {}", directory);
        if let Err(e) = start_monitoring(directory).await {
            eprintln!("Couldn't start monitoring: {}", e);
        }
    } else {
        println!("Scanning directory: {}", directory);
        let records = scan_directory(directory, no_ignore, no_git_ignore)?;

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

        // Save the new checksums with improved feedback
        println!("Saving checksums to '{}'", output_file);
        match save_records_to_ndjson(&records, output_file)? {
            SaveResult { successful, failed, total_bytes } => {
                println!("Successfully saved {} records ({:.2} MB)", 
                    successful,
                    total_bytes as f64 / 1024.0 / 1024.0
                );
                if failed > 0 {
                    eprintln!("Failed to save {} records", failed);
                }
            }
        }
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
