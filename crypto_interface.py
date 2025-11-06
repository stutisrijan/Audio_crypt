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