import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import socket
import threading
import os

#Utility Functions
def pad(data):
    return data + b"\0" * (AES.block_size - len(data) % AES.block_size)

def unpad(data):
    return data.rstrip(b"\0")

#RSA Key Management
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open("private.pem", "wb") as f:
        f.write(private_key)
    with open("public.pem", "wb") as f:
        f.write(public_key)
    messagebox.showinfo("Success", "RSA Key Pair generated successfully!")
    
# ---------------- AES + RSA Hybrid Encryption ---------------- #
def encrypt_file():
    file_path = filedialog.askopenfilename(filetypes=[("WAV files", ".wav"), ("All Files", ".*")])
    if not file_path:
        return

    if not os.path.exists("public.pem"):
        messagebox.showerror("Error", "Public key not found! Please generate RSA keys first.")
        return

    with open(file_path, "rb") as f:
        data = f.read()

    aes_key = get_random_bytes(16)
    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    ciphertext = cipher_aes.encrypt(pad(data))

    with open("public.pem", "rb") as f:
        recipient_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_aes_key = cipher_rsa.encrypt(aes_key)

    encrypted_file = file_path.replace(".wav", "_encrypted.bin")
    with open(encrypted_file, "wb") as f:
        f.write(len(enc_aes_key).to_bytes(2, 'big'))
        f.write(enc_aes_key)
        f.write(cipher_aes.iv)
        f.write(ciphertext)

    messagebox.showinfo("Success", f"File Encrypted!\nSaved as: {encrypted_file}")


def decrypt_file():
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.bin")])
    if not file_path:
        return
    if not os.path.exists("private.pem"):
        messagebox.showerror("Error", "Private key not found! Please generate RSA keys first.")
        return

    with open(file_path, "rb") as f:
        key_len = int.from_bytes(f.read(2), 'big')
        enc_aes_key = f.read(key_len)
        iv = f.read(16)
        ciphertext = f.read()

    with open("private.pem", "rb") as f:
        private_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(enc_aes_key)

    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    decrypted_data = unpad(cipher_aes.decrypt(ciphertext))

    decrypted_file = file_path.replace("_encrypted.bin", "_decrypted.wav")
    with open(decrypted_file, "wb") as f:
        f.write(decrypted_data)

    messagebox.showinfo("Success", f"File Decrypted!\nSaved as: {decrypted_file}")

# ---------------- LAN File Transfer ---------------- #
def send_file_over_lan():
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.bin"), ("All Files", "*.*")])
    if not file_path:
        return

    host = host_entry.get()
    port = int(port_entry.get())

    try:
        s = socket.socket()
        s.connect((host, port))
        with open(file_path, "rb") as f:
            while chunk := f.read(1024):
                s.send(chunk)
        s.close()
        messagebox.showinfo("Success", f"File sent to {host}:{port}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to send file:\n{e}")


def receive_file_over_lan():
    def server_thread():
        try:
            s = socket.socket()
            s.bind(('', int(port_entry.get())))
            s.listen(1)
            conn, addr = s.accept()
            save_path = filedialog.asksaveasfilename(defaultextension=".bin", filetypes=[("Encrypted files", "*.bin")])
            if not save_path:
                conn.close()
                s.close()
                return
            with open(save_path, "wb") as f:
                while data := conn.recv(1024):
                    f.write(data)
            conn.close()
            s.close()
            messagebox.showinfo("Success", f"File received and saved as {save_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Receiver error:\n{e}")

    threading.Thread(target=server_thread, daemon=True).start()
    messagebox.showinfo("Receiver Active", f"Listening on port {port_entry.get()}...")


# ---------------- GUI Setup ---------------- #
root = tk.Tk()
root.title("Hybrid Audio Encryptor & Secure LAN Transfer")
root.geometry("600x500")
root.config(bg="#101820")

title = tk.Label(root, text="🔒 Audio Encryptor & Secure File Transfer", bg="#101820", fg="#FEE715", font=("Helvetica", 16, "bold"))
title.pack(pady=20)

frame = tk.Frame(root, bg="#1B1B2F", bd=3, relief="ridge")
frame.pack(padx=20, pady=10, fill="both", expand=True)

btn_style = {"width": 25, "height": 2, "font": ("Arial", 12, "bold")}

tk.Button(frame, text="Generate RSA Keys", command=generate_rsa_keys, bg="#008CBA", fg="white", **btn_style).pack(pady=8)
tk.Button(frame, text="Encrypt Audio File", command=encrypt_file, bg="#3a7bd5", fg="white", **btn_style).pack(pady=8)
tk.Button(frame, text="Decrypt File", command=decrypt_file, bg="#00c853", fg="white", **btn_style).pack(pady=8)

tk.Label(frame, text="LAN Transfer", bg="#1B1B2F", fg="#FEE715", font=("Helvetica", 14, "bold")).pack(pady=10)
tk.Label(frame, text="Target Host (Receiver IP):", bg="#1B1B2F", fg="white").pack()
host_entry = tk.Entry(frame, width=30)
host_entry.insert(0, "127.0.0.1")
host_entry.pack()

tk.Label(frame, text="Port:", bg="#1B1B2F", fg="white").pack()
port_entry = tk.Entry(frame, width=10)
port_entry.insert(0, "5000")
port_entry.pack()

tk.Button(frame, text="Send Encrypted File", command=send_file_over_lan, bg="#FF6F61", fg="white", **btn_style).pack(pady=5)
tk.Button(frame, text="Receive Encrypted File", command=receive_file_over_lan, bg="#6A1B9A", fg="white", **btn_style).pack(pady=5)

tk.Label(root, text="Developed by Stuti, Nishtha, Jahnavi", bg="#101820", fg="#AAAAAA", font=("Arial", 10)).pack(pady=5)

root.mainloop()
