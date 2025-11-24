# macOS kcpassword Decryptor

Educational tool for understanding XOR encryption in macOS autologin passwords.

------------------------------------------------------------------------

## Authors

Marc Brandt\
Hochschule für Polizei Baden-Württemberg

------------------------------------------------------------------------

## Contents

This package contains three Python 3 implementations:

1. **kcpassword_decryptor_gui.py** - Full-featured GUI application with educational content
2. **decrypt_kcpassword.py** - Command-line tool with detailed output

### Usage

```bash
# Run the GUI application
python3 kcpassword_decryptor_gui.py

# If reading from system file, use sudo
sudo python3 kcpassword_decryptor_gui.py
```

## Command-Line Tool

### Basic Usage

```bash
# Decrypt a kcpassword file
python3 decrypt_kcpassword.py /path/to/kcpassword

# Read from system (requires root)
sudo python3 decrypt_kcpassword.py /etc/kcpassword

# Quiet mode (only output password)
python3 decrypt_kcpassword.py /etc/kcpassword --quiet

# Verbose mode (show XOR key array)
python3 decrypt_kcpassword.py /etc/kcpassword --verbose
```

### Command-Line Options

```
usage: decrypt_kcpassword.py [-h] [-v] [-q] path

positional arguments:
  path           Path to the kcpassword file (usually /etc/kcpassword)

optional arguments:
  -h, --help     show this help message and exit
  -v, --verbose  Show detailed XOR decryption steps
  -q, --quiet    Only output the password, no additional information
```

### Example Output

```
Path to kcpassword file: /etc/kcpassword
Reading and decrypting...

Decryption Process:
================================================================================

Step 1 (Key Index: 0):
  Encrypted: 0x3C (00111100b)
  Key:       0x7D (01111101b)
  XOR:       0x41 (01000001b) = 'A'

Step 2 (Key Index: 1):
  Encrypted: 0xE8 (11101000b)
  Key:       0x89 (10001001b)
  XOR:       0x61 (01100001b) = 'a'

...

================================================================================
DECRYPTED PASSWORD: YourPassword123
================================================================================

Password length: 15 characters
```

## Understanding kcpassword

### What is kcpassword?

The `kcpassword` file on macOS stores the autologin password in an obfuscated format. It's located at `/etc/kcpassword` and is only present when automatic login is enabled.

### The XOR Key

macOS uses a hardcoded 11-byte XOR key:

```python
KEY = [0x7D, 0x89, 0x52, 0x23, 0xD2, 0xBC, 0xDD, 0xEA, 0xA3, 0xB9, 0x1F]
```

### How It Works

1. Each byte of the password is XORed with the corresponding key byte
2. If the password is longer than 11 characters, the key cycles back to the beginning
3. A termination marker (key byte == encrypted byte) signals the end
4. Since XOR is reversible, the same operation decrypts the password

## Requirements

- Python 3.6 or higher
- tkinter (usually included with Python)
- Standard library only (no external dependencies!)

### Checking Python Version

```bash
python3 --version
```

### Installing tkinter (if needed)

**macOS:**
```bash
# tkinter is included with Python from python.org
# If using Homebrew Python:
brew install python-tk
```

## Quick Start Examples

### Example 1: GUI Application
```bash
# Launch the GUI
python3 kcpassword_decryptor_gui.py

# Then click "Select File" and choose your kcpassword file
```

### Example 2: Command-Line Decryption
```bash
# Copy kcpassword from system (requires root)
sudo cp /etc/kcpassword ~/kcpassword_backup

# Decrypt the backup
python3 decrypt_kcpassword.py ~/kcpassword_backup
```

## 📝 License & Credits
Educational use only. Use responsibly.
