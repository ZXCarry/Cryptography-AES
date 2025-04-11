# 🔐 AES Encryption/Decryption with JavaFX GUI

This project is a full Java implementation of the **AES (Advanced Encryption Standard)** algorithm, bundled with a simple and intuitive **JavaFX GUI**. It allows both encryption and decryption of plaintext or entire files using 128-, 192-, or 256-bit keys.

---

## 🧠 Features

- ✅ Full AES implementation (from scratch, no external crypto libraries)
- ✅ Supports 128-bit, 192-bit, and 256-bit keys
- ✅ Includes all AES operations: SubBytes, ShiftRows, MixColumns, AddRoundKey, Key Expansion
- ✅ Encrypt/decrypt user input or files
- ✅ Zero-padding for input that isn't a multiple of 16 bytes
- ✅ JavaFX-based GUI for easy interaction
- ✅ Clean and well-commented source code

---

## 🖥️ GUI Preview

![Image](https://github.com/user-attachments/assets/3166ff6d-1545-4abe-bcac-fcc2e45f2609)

---

## 🚀 Getting Started

### 📦 Requirements

- Java 11 or later
- JavaFX SDK (download from https://openjfx.io)

### ⚙️ Build & Run

1. Compile the project:
   ```bash
   javac -d out src/org/example/*.java
   ```

2. Run the application:
   ```bash
   java --module-path /path/to/javafx-sdk/lib --add-modules javafx.controls,javafx.fxml -cp out org.example.AESInterface
   ```

   > Make sure to replace `/path/to/javafx-sdk` with the path to your JavaFX installation.

---

## 🔑 Key Format

- Input your encryption key in **hexadecimal format** (no spaces).
- Accepted lengths:
  - 32 characters (128-bit key)
  - 48 characters (192-bit key)
  - 64 characters (256-bit key)

If the key is invalid, the program will show an error.

---

## 📂 File Encryption

You can also encrypt and decrypt files:

- Select a file to encrypt/decrypt using the built-in file chooser
- Choose an output path to save the result
- The entire file will be encrypted/decrypted as a byte stream

⚠️ Use the exact same key for decryption to recover the original data.

---

## 🧊 Padding Information

This implementation uses **zero-padding**:
- If the input isn't divisible by 16 bytes, it gets padded with `0x00`
- Upon decryption, trailing zeroes are removed

---

## 📚 Code Structure

- `AES.java` — core AES implementation
- `AESInterface.java` — JavaFX-based UI for using the AES functions

All AES internals (S-Boxes, RCON, KeyExpansion, etc.) are implemented manually for educational purposes.

---

## 📄 License

This project is licensed under the **Apache License 2.0**.  
You may use, modify, and distribute it in accordance with the terms of the license.

See the full license here: [Apache-2.0 License](https://www.apache.org/licenses/LICENSE-2.0)

---

## ✍️ Author

Created by **ZXCarry**  
- Contact: nusz010101@gmail.com
- Language: Polish comments and interface, English documentation
