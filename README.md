**Hybrid Audio Encryptor & Secure LAN Transfer**

**Overview**
A Python-based GUI tool that securely **encrypts, decrypts, and transfers audio files** using a **hybrid AES + RSA cryptography system**.  
It allows users to protect audio data and share it safely over a local network.

**Features**
- AES + RSA hybrid encryption  
- Works with WAV, MP3, FLAC, etc.  
- LAN file transfer (send/receive over TCP)  
- RSA key generation  
- Simple Tkinter-based interface

**How It Works**
- Generate RSA Keys → Creates public.pem & private.pem.
- Encrypt Audio File → AES encrypts file, RSA secures AES key.
- Decrypt File → Recovers original audio.

**Result**
<img width="750" height="778" alt="image" src="https://github.com/user-attachments/assets/a8455a4e-4566-45e3-9b58-3084a46b30ed" />
