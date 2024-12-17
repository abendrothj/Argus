
# Argus - File Integrity Checker

Argus is a simple file integrity checker built in Rust. It recursively scans a given directory, calculates the SHA-256 checksum for each file, and stores the results in a file. It supports output in NDJSON (Newline Delimited JSON) format.

## Features

- Recursively scan a directory and its subdirectories.
- Calculate the SHA-256 checksum of each file.
- Output results in NDJSON format for easy processing.
- Supports command-line arguments for custom input and output paths.
- Other features are WIP

## Requirements

- Rust 1.60 or higher.
- `cargo` (comes with Rust).

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

If you want to use the default directory (current directory) and the default output file (`file_integrity.ndjson`), simply run:

```bash
./target/release/argus
```

### Command-Line Arguments

- `--directory`, `-d`: The directory to scan (defaults to the current directory if not specified).
- `--output`, `-o`: The output file to save the checksums (defaults to `file_integrity.ndjson`).

### Example Usage

```bash
./target/release/argus -- --directory ./test_directory --output checksums.ndjson
```

This will scan the `test_directory` folder and save the checksums in `checksums.ndjson`.

## File Format

The output file is in **NDJSON** format, which stores each file's checksum as a separate JSON object on a new line:

```json
{"path": "/path/to/file1", "checksum": "abc123..."}
{"path": "/path/to/file2", "checksum": "def456..."}
```

## Development

To contribute to this project:

1. Fork the repository.
2. Clone your fork.
3. Make changes and test.
4. Create a pull request.

## License

This project is licensed under the GPLv3 License. See the [LICENSE](LICENSE) file for details.

---

Made with ❤️ in Rust.
