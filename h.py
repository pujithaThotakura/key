# Save this code into a cell and run it in Jupyter
from tkinter import filedialog, messagebox, Tk, Label, Button, Entry
from cryptography.fernet import Fernet
import os

def start_gui():
    class FileCryptoApp:
        def __init__(self, root):
            self.root = root
            self.root.title("File Encryption/Decryption Tool")
            self.root.geometry("400x300")
            self.file_path = ""

            Label(root, text="Select a file to encrypt or decrypt").pack(pady=10)
            Button(root, text="Browse File", command=self.browse_file).pack(pady=5)

            Label(root, text="Enter your key (or generate one):").pack(pady=5)
            self.key_entry = Entry(root, width=50)
            self.key_entry.pack(pady=5)

            Button(root, text="Generate Key", command=self.generate_key).pack(pady=5)
            Button(root, text="Encrypt File", command=self.encrypt_file).pack(pady=5)
            Button(root, text="Decrypt File", command=self.decrypt_file).pack(pady=5)

        def browse_file(self):
            self.file_path = filedialog.askopenfilename()

        def generate_key(self):
            key = Fernet.generate_key()
            self.key_entry.delete(0, 'end')
            self.key_entry.insert(0, key.decode())
            messagebox.showinfo("Key Generated", "A new encryption key has been generated.")

        def encrypt_file(self):
            if not self.file_path:
                messagebox.showerror("Error", "Please select a file.")
                return
            try:
                key = self.key_entry.get().encode()
                fernet = Fernet(key)
                with open(self.file_path, 'rb') as file:
                    original = file.read()
                encrypted = fernet.encrypt(original)
                with open(self.file_path + ".encrypted", 'wb') as enc_file:
                    enc_file.write(encrypted)
                messagebox.showinfo("Success", "File encrypted successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed.\n{e}")

        def decrypt_file(self):
            if not self.file_path:
                messagebox.showerror("Error", "Please select a file.")
                return
            try:
                key = self.key_entry.get().encode()
                fernet = Fernet(key)
                with open(self.file_path, 'rb') as enc_file:
                    encrypted = enc_file.read()
                decrypted = fernet.decrypt(encrypted)
                output_path = self.file_path.replace(".encrypted", ".decrypted")
                with open(output_path, 'wb') as dec_file:
                    dec_file.write(decrypted)
                messagebox.showinfo("Success", f"File decrypted successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed.\n{e}")

    root = Tk()
    app = FileCryptoApp(root)
    root.mainloop()

start_gui()
