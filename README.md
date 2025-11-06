# pwgen-rs

A Rust implementation of the classic `pwgen` password generator with no external dependencies.
Generates cryptographically secure and memorable passwords using `/dev/urandom` as the entropy source.

## Features

- 🔒 **Cryptographically secure** - Uses `/dev/urandom` for true randomness
- 🧠 **Memorable passwords** - Optional consonant-vowel pattern for easy-to-remember passwords
- ⚡ **Zero dependencies** - Pure Rust implementation
- 📦 **Statically linked** - Single binary for easy distribution
- 🎯 **Full compatibility** - Supports all original pwgen options

## Installation

### Download Binary
Get the latest binary from [Releases](https://github.com/Karag0/pwgen-rs/releases):

```bash
chmod +x pwgen-rs
./pwgen-rs --help
```

### Install via Cargo
```bash
cargo install pwgen-rs
```

### Build from Source
```bash
git clone https://github.com/Karag0/pwgen-rs
cd pwgen-rs
cargo build --release
```

The binary will be available at `target/release/pwgen-rs`.

## Usage Examples

```bash
# Generate 5 passwords of 12 characters
./pwgen-rs 12 5

# Generate secure random passwords
./pwgen-rs -s 16 3

# Generate passwords without numbers
./pwgen-rs -0 10 5

# Generate passwords with symbols
./pwgen-rs -y 12 3

# Generate passwords without vowels (avoid offensive words)
./pwgen-rs -v 8 5
```

## Common Options

- `-s, --secure` - Generate completely random passwords
- `-0, --no-numerals` - Don't include numbers
- `-A, --no-capitalize` - Don't include capital letters
- `-y, --symbols` - Include at least one special symbol
- `-v, --no-vowels` - Avoid vowels to prevent accidental words
- `-B, --ambiguous` - Don't include ambiguous characters (like 0/O, 1/l)
- `-1` - Print passwords in a single column

## License

GPL-3.0 License - see [LICENSE](LICENSE) file for details.

---

**Note**: This is a Rust rewrite of the original `pwgen` utility, maintaining full compatibility
while providing a modern, secure implementation.
