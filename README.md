# Argus - Directory Checksum/Monitoring Tool

Argus is a simple file integrity checker built in Rust. It recursively scans a given directory, calculates the SHA-256 checksum for each file, and stores the results in a file. It supports output in NDJSON (Newline Delimited JSON) format.

## Features

- Recursively scan a directory and its subdirectories
- Calculate the SHA-256 checksum of each file
- Output results in NDJSON format for easy processing
- Supports command-line arguments for custom input and output paths
- Directory monitoring mode
- Parallel processing for faster scanning
- Ignore patterns support (like .gitignore)
- Detailed comparison reports

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
- `--monitor`, `-m`: Sets monitoring mode on
- `--directory`, `-d`: The directory to scan or monitor (defaults to the current directory if not specified)
- `--output`, `-o`: The output file to save the checksums (checksum mode, defaults to `file_integrity.ndjson`)
- `--compare`, `-c`: Compare current directory state with an existing checksum file
- `--report`, `-r`: Output file for the comparison report (defaults to report.txt)
- `--threads`, `-t`: Number of threads to use for parallel processing (default: number of CPU cores)
- `--no-ignore`: Don't use ignore patterns from .gitignore
- `--no-git-ignore`: Don't use ignore patterns from .gitignore
- `--help`, `-h`: Displays the help message
- `--version`, `-V`: Display the program's version

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
# Basic scan with parallel processing
./argus -d ./test_dir -o checksums.ndjson -t 4

# Compare with previous scan and generate report
./argus -d ./test_dir -c checksums.ndjson -r changes.txt

# Monitor directory ignoring patterns in .gitignore and .argusignore
./argus -m -d /path/to/watch

# Scan without using ignore patterns
./argus -d ./test_dir --no-ignore
```

## File Format

The output file for checksums is in **NDJSON** format, which stores each file's checksum as a separate JSON object on a new line:
(Absolute path is used, including character limit bypass prefix if ran on Windows)

```ndjson
{"path": "/path/to/file1", "checksum": "abc123...", "timestamp": 1234567890, "size": 1024}
{"path": "/path/to/file2", "checksum": "def456...", "timestamp": 1234567891, "size": 2048}
```

## Development

If you'd like to contribute to this project, just make a pull request with information about your changes/improvements :)

## License

This project is licensed under the GPLv3 License. See the [LICENSE](LICENSE) file for details.

---

Made with ❤️ in Rust. 
