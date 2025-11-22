#!/usr/bin/env python3
""" 
Python 3 "Decrypt_AutologinPW"
Original Author: Marc Brandt
Date: 05.01.2016
Ported to Python 3: 2025
Version: 2.0
"""

import argparse
import sys

# XOR key used by macOS
KEY = [0x7D, 0x89, 0x52, 0x23, 0xD2, 0xBC, 0xDD, 0xEA, 0xA3, 0xB9, 0x1F]


def open_file(path):
    """
    Opens the kcpassword file and reads its contents as bytes.
    
    Args:
        path: Path to the kcpassword file
        
    Returns:
        List of byte values from the file
    """
    try:
        with open(path, "rb") as f:
            content = f.read()
            return list(content)
    except FileNotFoundError:
        print(f"Error: File not found: {path}")
        sys.exit(1)
    except PermissionError:
        print(f"Error: Permission denied. Try running with sudo.")
        sys.exit(1)


def xor_decrypt(encrypted_bytes, key):
    """
    Decrypts the encrypted bytes using XOR with the given key.
    
    Args:
        encrypted_bytes: List of encrypted byte values
        key: List of key byte values
        
    Returns:
        The decrypted password as a string
    """
    password = ""
    key_index = 0
    
    print("\nDecryption Process:")
    print("=" * 80)
    
    for i, encrypted_byte in enumerate(encrypted_bytes):
        key_byte = key[key_index]
        
        # Check for termination marker
        # After the password, a byte equal to the current key byte signals the end
        if key_byte == encrypted_byte:
            print(f"\nTermination marker found at position {i}")
            print(f"Key byte (0x{key_byte:02X}) matches encrypted byte - end of password")
            break
            
        # XOR operation
        decrypted_byte = encrypted_byte ^ key_byte
        char = chr(decrypted_byte)
        password += char
        
        # Display step information
        print(f"\nStep {i + 1} (Key Index: {key_index}):")
        print(f"  Encrypted: 0x{encrypted_byte:02X} ({encrypted_byte:08b}b)")
        print(f"  Key:       0x{key_byte:02X} ({key_byte:08b}b)")
        print(f"  XOR:       0x{decrypted_byte:02X} ({decrypted_byte:08b}b) = '{char}'")
        
        # Move to next key byte (cycle through key)
        key_index = (key_index + 1) % len(key)
    
    print("=" * 80)
    return password


def main():
    parser = argparse.ArgumentParser(
        description="Decrypt macOS kcpassword file using XOR cipher",
        epilog="Example: python3 decrypt_kcpassword.py /etc/kcpassword"
    )
    parser.add_argument(
        'path',
        help='Path to the kcpassword file (usually /etc/kcpassword)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed XOR decryption steps'
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Only output the password, no additional information'
    )
    
    args = parser.parse_args()
    
    if not args.quiet:
        print(f"Path to kcpassword file: {args.path}")
        print("Reading and decrypting...")
    
    # Read the encrypted file
    encrypted_bytes = open_file(args.path)
    
    # Decrypt using XOR
    if args.quiet:
        # Suppress verbose output
        import io
        import contextlib
        
        f = io.StringIO()
        with contextlib.redirect_stdout(f):
            password = xor_decrypt(encrypted_bytes, KEY)
        print(password)
    else:
        password = xor_decrypt(encrypted_bytes, KEY)
        print(f"\n{'=' * 80}")
        print(f"DECRYPTED PASSWORD: {password}")
        print(f"{'=' * 80}")
        print(f"\nPassword length: {len(password)} characters")
        
        if args.verbose:
            print("\nXOR Key used:")
            print([f"0x{b:02X}" for b in KEY])


if __name__ == "__main__":
    main()
