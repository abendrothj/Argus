# Argus - Directory Checksum/Monitoring Tool

Argus is a high-performance file integrity checker built in Rust. It recursively scans a given directory, calculates the SHA-256 checksum for each file, and stores the results in NDJSON format. With support for parallel processing, ignore patterns, and real-time monitoring, it's a robust tool for tracking file changes and verifying file integrity.

## Features

- Fast parallel processing with configurable thread count
- Recursive directory scanning with efficient memory usage
- SHA-256 checksum calculation with progress tracking
- NDJSON output format for easy data processing
- Real-time directory monitoring with checksum updates
- Comprehensive ignore pattern support (.gitignore and .argusignore)
- Detailed comparison reports with size and timestamp tracking
- Progress bar with speed and throughput metrics
- Efficient handling of large files (up to 1GB)
- Robust error handling and user feedback

#### Coming soon:
- Automation?

## Requirements

- Rust 1.60 or higher
- `cargo` (comes with Rust)

## Installation

### 1. Clone the repository:

```bash
git clone https://github.com/your-username/argus.git
cd argus
```

### 2. Build the project:

To compile the project in release mode (for an optimized executable):

```bash
cargo build --release
```

### 3. Run the Standalone Executable:

Once built, the standalone executable can be found in the `target/release/` directory.

To scan a directory and save the integrity checksums to an output file, run:

```bash
./target/release/argus --directory /path/to/dir --output output.ndjson
```

Replace `/path/to/dir` with the directory you want to scan and `output.ndjson` with the desired output file name.

If you want to use the default directory (current working directory) and the default output file (`./file_integrity.ndjson`), simply run:

```bash
./target/release/argus
```

### Command-Line Arguments
- `--monitor`, `-m`: Enable real-time monitoring of directory changes
- `--directory`, `-d`: Directory to scan or monitor (defaults to current directory)
- `--output`, `-o`: Output file for checksums in NDJSON format (defaults to `file_integrity.ndjson`)
- `--compare`, `-c`: Compare current directory state with an existing NDJSON file
- `--report`, `-r`: Output file for the comparison report (defaults to report.txt)
- `--threads`, `-t`: Number of threads for parallel processing (default: number of CPU cores)
- `--no-ignore`: Ignore all ignore patterns (both .gitignore and .argusignore)
- `--no-git-ignore`: Ignore only .gitignore patterns (still use .argusignore)
- `--help`, `-h`: Display help message
- `--version`, `-V`: Display version information

### Ignore Patterns

Argus supports ignore patterns similar to .gitignore. You can specify patterns in two ways:

1. Create a `.argusignore` file in the directory you're scanning
2. Use existing `.gitignore` files (automatically detected)

The `.argusignore` file uses the same pattern format as `.gitignore`. For example:

```gitignore
# Ignore temporary files
*.tmp
*.temp

# Ignore directories
node_modules/
target/
.git/

# Ignore specific file types
*.log
*.cache
```

A sample `.argusignore` file is provided with common patterns. You can customize it for your needs.

### Example Usage

```bash
# Basic scan with 8 threads
./argus -d ./test_dir -o checksums.ndjson -t 8

# Compare with previous scan and generate detailed report
./argus -d ./test_dir -c checksums.ndjson -r changes.txt

# Monitor directory with real-time checksum updates
./argus -m -d /path/to/watch

# Scan without any ignore patterns
./argus -d ./test_dir --no-ignore

# Scan using only .argusignore (ignore .gitignore)
./argus -d ./test_dir --no-git-ignore
```

## Performance

Argus is designed for performance:
- Parallel processing with configurable thread count
- Efficient buffered I/O operations
- Memory-efficient file processing
- Progress tracking with throughput metrics
- Atomic operations for thread safety

## File Format

The output is in **NDJSON** (Newline Delimited JSON) format, with each line containing a valid JSON object:

```ndjson
{"path": "/path/to/file1", "checksum": "abc123...", "timestamp": 1234567890, "size": 1024}
{"path": "/path/to/file2", "checksum": "def456...", "timestamp": 1234567891, "size": 2048}
```

Each record contains:
- `path`: Absolute path to the file
- `checksum`: SHA-256 hash of the file contents
- `timestamp`: Last modification time (Unix timestamp)
- `size`: File size in bytes

## Development

If you'd like to contribute to this project, just make a pull request with information about your changes/improvements :)

## License

This project is licensed under the GPLv3 License. See the [LICENSE](LICENSE) file for details.

---

Made with ❤️ in Rust. 
