#!/usr/bin/env python3
"""
kcpassword Decryptor GUI
Educational tool for understanding XOR encryption in macOS
Author: Marc Brandt
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os

class KCPasswordDecryptor:
    def __init__(self, root):
        self.root = root
        self.root.title("macOS kcpassword Decryptor")
        self.root.geometry("900x650")
        
        # XOR key used by macOS
        self.KEY = [0x7D, 0x89, 0x52, 0x23, 0xD2, 0xBC, 0xDD, 0xEA, 0xA3, 0xB9, 0x1F]
        
        self.setup_ui()
        
    def setup_ui(self):
        # Header
        header_frame = tk.Frame(self.root, relief=tk.RAISED, borderwidth=2)
        header_frame.pack(fill=tk.X, padx=5, pady=5)
        
        title_label = tk.Label(
            header_frame,
            text="macOS kcpassword Decryptor",
            font=("Helvetica", 16, "bold")
        )
        title_label.pack(pady=10)
        
        subtitle_label = tk.Label(
            header_frame,
            text="XOR Cipher Analysis Tool",
            font=("Helvetica", 10)
        )
        subtitle_label.pack(pady=(0, 10))
        
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.decrypt_tab = tk.Frame(self.notebook)
        self.learn_tab = tk.Frame(self.notebook)
        
        self.notebook.add(self.decrypt_tab, text="Decrypt Password")
        self.notebook.add(self.learn_tab, text="Learn About XOR")
        
        self.setup_decrypt_tab()
        self.setup_learn_tab()
        
    def setup_decrypt_tab(self):
        # Main container
        container = tk.Frame(self.decrypt_tab)
        container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # File Upload Section
        upload_frame = tk.LabelFrame(
            container,
            text="File Selection",
            font=("Helvetica", 10, "bold"),
            padx=10,
            pady=10
        )
        upload_frame.pack(fill=tk.X, pady=(0, 10))
        
        info_label = tk.Label(
            upload_frame,
            text="The kcpassword file is located at /etc/kcpassword on macOS systems",
            font=("Helvetica", 9),
            justify=tk.LEFT
        )
        info_label.pack(anchor=tk.W, pady=(0, 10))
        
        button_frame = tk.Frame(upload_frame)
        button_frame.pack()
        
        upload_btn = tk.Button(
            button_frame,
            text="Select File...",
            command=self.select_file,
            width=15
        )
        upload_btn.pack(side=tk.LEFT, padx=5)
        
        system_btn = tk.Button(
            button_frame,
            text="Read from System",
            command=self.read_system_file,
            width=15
        )
        system_btn.pack(side=tk.LEFT, padx=5)
        
        # Result Section
        result_frame = tk.LabelFrame(
            container,
            text="Decrypted Password",
            font=("Helvetica", 10, "bold"),
            padx=10,
            pady=10
        )
        result_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.password_label = tk.Label(
            result_frame,
            text="No password decrypted yet",
            font=("Courier", 14, "bold"),
            relief=tk.SUNKEN,
            borderwidth=2,
            padx=20,
            pady=15,
            bg="white"
        )
        self.password_label.pack(fill=tk.X)
        
        # XOR Visualization Section
        viz_frame = tk.LabelFrame(
            container,
            text="Step-by-Step XOR Decryption Process",
            font=("Helvetica", 10, "bold"),
            padx=10,
            pady=10
        )
        viz_frame.pack(fill=tk.BOTH, expand=True)
        
        self.viz_text = scrolledtext.ScrolledText(
            viz_frame,
            font=("Courier", 9),
            wrap=tk.WORD,
            relief=tk.SUNKEN,
            borderwidth=2
        )
        self.viz_text.pack(fill=tk.BOTH, expand=True)
        
    def setup_learn_tab(self):
        # Scrollable container
        canvas = tk.Canvas(self.learn_tab, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.learn_tab, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Content
        content = tk.Frame(scrollable_frame)
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        title = tk.Label(
            content,
            text="Understanding XOR Encryption in macOS kcpassword",
            font=("Helvetica", 14, "bold")
        )
        title.pack(anchor=tk.W, pady=(0, 15))
        
        # What is XOR
        self.create_section(content, "What is XOR?",
            "XOR (eXclusive OR) is a binary operation that compares two bits.\n"
            "It returns 1 when the bits are different, and 0 when they are the same.\n\n"
            "XOR Truth Table:\n"
            "┌───────┬───────┬─────────┐\n"
            "│ Bit A │ Bit B │ A XOR B │\n"
            "├───────┼───────┼─────────┤\n"
            "│   0   │   0   │    0    │\n"
            "│   0   │   1   │    1    │\n"
            "│   1   │   0   │    1    │\n"
            "│   1   │   1   │    0    │\n"
            "└───────┴───────┴─────────┘"
        )
        
        # How macOS uses XOR
        self.create_section(content, "How macOS Uses XOR for kcpassword",
            "macOS uses a simple XOR cipher with a static key to obfuscate\n"
            "(not securely encrypt!) the autologin password stored in /etc/kcpassword.\n\n"
            "The Static XOR Key:\n"
            "[0x7D, 0x89, 0x52, 0x23, 0xD2, 0xBC, 0xDD, 0xEA, 0xA3, 0xB9, 0x1F]\n\n"
            "This 11-byte key is hardcoded and publicly known, making this\n"
            "obfuscation rather than real encryption."
        )
        
        # The Process
        self.create_section(content, "The Encryption/Decryption Process",
            "1. Take each byte of the password and XOR it with the\n"
            "   corresponding byte from the key\n\n"
            "2. Cycle through the key: If the password is longer than\n"
            "   11 characters, the key repeats from the beginning\n\n"
            "3. Termination marker: After the password, a byte matching\n"
            "   the next key byte is written to signal the end\n\n"
            "4. Reversible operation: Since XOR is its own inverse\n"
            "   (A XOR B XOR B = A), the same operation decrypts the password"
        )
        
        # Example
        self.create_section(content, "Example: Encrypting/Decrypting 'A'",
            "Character 'A' = 0x41 = 01000001 (binary)\n"
            "Key[0]        = 0x7D = 01111101 (binary)\n\n"
            "Encryption:\n"
            "  01000001  (A)\n"
            "⊕ 01111101  (Key)\n"
            "──────────\n"
            "  00111100  (0x3C - Encrypted)\n\n"
            "Decryption (XOR again with same key):\n"
            "  00111100  (Encrypted)\n"
            "⊕ 01111101  (Key)\n"
            "──────────\n"
            "  01000001  (0x41 = 'A' - Original!)"
        )
        
    def create_section(self, parent, title, content):
        frame = tk.LabelFrame(
            parent,
            text=title,
            font=("Helvetica", 10, "bold"),
            padx=15,
            pady=15
        )
        frame.pack(fill=tk.X, pady=(0, 10))
        
        text_label = tk.Label(
            frame,
            text=content,
            font=("Courier", 9),
            justify=tk.LEFT,
            anchor=tk.W
        )
        text_label.pack(anchor=tk.W)
        
    def select_file(self):
        filename = filedialog.askopenfilename(
            title="Select kcpassword file",
            filetypes=[("All files", "*.*"), ("kcpassword", "kcpassword")]
        )
        if filename:
            self.decrypt_file(filename)
            
    def read_system_file(self):
        system_path = "/etc/kcpassword"
        if os.path.exists(system_path):
            try:
                self.decrypt_file(system_path)
            except PermissionError:
                messagebox.showerror(
                    "Permission Denied",
                    "Cannot read /etc/kcpassword - root privileges required.\n\n"
                    "Try running with: sudo python3 kcpassword_decryptor_gui.py"
                )
        else:
            messagebox.showwarning(
                "File Not Found",
                "The file /etc/kcpassword does not exist on this system.\n\n"
                "This usually means autologin is not configured."
            )
            
    def decrypt_file(self, filepath):
        try:
            with open(filepath, "rb") as f:
                encrypted_data = f.read()
                
            password, steps = self.decrypt_password(encrypted_data)
            
            # Display password
            self.password_label.config(text=password if password else "Empty password")
            
            # Display visualization
            self.viz_text.delete(1.0, tk.END)
            self.viz_text.insert(tk.END, steps)
            
            messagebox.showinfo(
                "Success",
                f"Password decrypted successfully!\n\nPassword: {password}"
            )
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt file:\n{str(e)}")
            
    def decrypt_password(self, data):
        password = ""
        visualization = "Step-by-Step XOR Decryption:\n"
        visualization += "=" * 80 + "\n\n"
        
        key_index = 0
        
        for i, encrypted_byte in enumerate(data):
            key_byte = self.KEY[key_index]
            
            # Check for termination
            if key_byte == encrypted_byte:
                visualization += f"Termination marker found at position {i}\n"
                visualization += f"Key byte (0x{key_byte:02X}) matches encrypted byte - end of password\n"
                break
                
            # XOR operation
            decrypted_byte = encrypted_byte ^ key_byte
            char = chr(decrypted_byte)
            password += char
            
            # Create visualization
            visualization += f"Step {i + 1} (Key Index: {key_index}):\n"
            visualization += f"{'─' * 80}\n"
            visualization += f"  Encrypted Byte:  0x{encrypted_byte:02X}  =  {encrypted_byte:08b}b  =  {encrypted_byte:3d}\n"
            visualization += f"  Key Byte:        0x{key_byte:02X}  =  {key_byte:08b}b  =  {key_byte:3d}\n"
            visualization += f"  XOR Result:      0x{decrypted_byte:02X}  =  {decrypted_byte:08b}b  =  {decrypted_byte:3d}\n"
            visualization += f"  Character:       '{char}'\n"
            visualization += "\n"
            
            key_index = (key_index + 1) % len(self.KEY)
            
        visualization += "=" * 80 + "\n"
        visualization += f"Final Password: {password}\n"
        visualization += f"Length: {len(password)} characters\n"
        
        return password, visualization


def main():
    root = tk.Tk()
    app = KCPasswordDecryptor(root)
    root.mainloop()


if __name__ == "__main__":
    main()