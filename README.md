# StegoCrypt 🔐  
### Secure Image Handling Using Hybrid Cryptography & Steganography

StegoCrypt is a web-based cybersecurity project developed as part of an **MSc in Cybersecurity at Dublin Business School**.  
The system combines **cryptography and steganography** to securely embed and protect secret images or text within digital images for cloud-oriented environments.

---

## 📌 Project Overview

StegoCrypt integrates:
- **RC6 (128-bit) symmetric encryption**
- **Discrete Cosine Transform (DCT)** for preprocessing
- **Least Significant Bit (LSB) steganography**
- **Z-pattern embedding** for improved imperceptibility

The application allows users to embed, encrypt, decrypt, and extract hidden data using a simple **Flask-based web interface**.

---

## 🚀 Features

- Secure embedding of **secret images and text**
- Double-layer protection using **steganography + encryption**
- Z-pattern traversal to reduce detectability
- Automatic extraction after decryption
- Performance evaluation using image quality metrics

---

## 🛠️ Tech Stack

- **Programming Language:** Python  
- **Web Framework:** Flask  
- **Cryptography:** RC6 (128-bit)  
- **Steganography:** LSB  
- **Image Processing:** DCT / IDCT  
- **Libraries:** OpenCV, NumPy, SciPy, Matplotlib, scikit-image  

---

## 📊 Performance Metrics

The system evaluates embedding quality using:
- **PSNR (Peak Signal-to-Noise Ratio)**
- **SSIM (Structural Similarity Index)**
- **SNR (Signal-to-Noise Ratio)**
- **BPP (Bits Per Pixel)**

**Results achieved:**
- PSNR > **49 dB**
- SSIM ≥ **0.998**

These values indicate high imperceptibility and strong structural preservation.

---

## ▶️ How to Run the Project

1. Clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/StegoCrypt.git

2. Navigate to the project folder:

cd StegoCrypt

3. Install required dependencies:

pip install -r requirements.txt

4. Run the Flask application:

python app.py

5. Open your browser and go to:

http://127.0.0.1:5000
