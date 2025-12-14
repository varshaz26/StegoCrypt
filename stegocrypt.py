import os
import cv2
import numpy as np
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash
from skimage.metrics import structural_similarity as ssim
from scipy.fftpack import dct, idct
from math import log10

app = Flask(__name__)
app.secret_key = 'secret'
UPLOAD_FOLDER = 'static/uploads/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ----------------- Utility Functions -----------------
def apply_dct_and_idct_color(img):
    img = cv2.resize(img, (min(img.shape[1], img.shape[0]), min(img.shape[1], img.shape[0])))
    dct_img = np.zeros_like(img, dtype=np.float32)
    for c in range(3):
        d = dct(dct(img[:, :, c].astype(np.float32), axis=0, norm='ortho'), axis=1, norm='ortho')
        dct_img[:, :, c] = idct(idct(d, axis=0, norm='ortho'), axis=1, norm='ortho')
    return np.clip(dct_img, 0, 255).astype(np.uint8)

def get_z_pattern_indices(rows, cols):
    indices = []
    for r in range(rows):
        for c in (range(cols) if r % 2 == 0 else reversed(range(cols))):
            indices.append((r, c))
    return indices

def add_watermark(image, text="", pos=(10, 30)):
    return cv2.putText(image.copy(), text, pos, cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2, cv2.LINE_AA)

def embed_text_in_image(image, secret_text):
    binary_text = ''.join(format(ord(char), '08b') for char in secret_text) + '00000000'
    img_flat = image.flatten()
    for i in range(len(binary_text)):
        img_flat[i] = (img_flat[i] & ~1) | int(binary_text[i])
    return img_flat.reshape(image.shape)

def extract_text_from_image(image):
    img_flat = image.flatten()
    bits = [str(img_flat[i] & 1) for i in range(0, len(img_flat), 1)]
    chars = [bits[i:i+8] for i in range(0, len(bits), 8)]
    text = ''
    for char_bits in chars:
        char = chr(int(''.join(char_bits), 2))
        if char == '\x00': break
        text += char
    return text

def extract_embedded_image(stego_img):
    rows, cols, _ = stego_img.shape
    recovered_img = np.zeros_like(stego_img)
    indices = get_z_pattern_indices(rows, cols)
    for (i, j) in indices:
        for c in range(3):
            pixel = stego_img[i, j, c]
            bits = format(pixel, '08b')[4:]
            recovered_img[i, j, c] = int(bits + '0000', 2)
    return recovered_img

# ----------------- Metric Functions -----------------
def calculate_psnr(img1, img2):
    mse = np.mean((img1 - img2) ** 2)
    return 100 if mse == 0 else 10 * log10(255 * 255 / mse)

def calculate_ssim_metric(img1, img2):
    return ssim(img1, img2, multichannel=True)

def calculate_snr(img1, img2):
    noise = img1 - img2
    signal_power = np.sum(img1.astype(np.float64) ** 2)
    noise_power = np.sum(noise.astype(np.float64) ** 2)
    return 10 * log10(signal_power / noise_power) if noise_power else float('inf')

def calculate_bpp(image_path):
    file_size = os.path.getsize(image_path) * 8
    img = cv2.imread(image_path)
    return file_size / (img.shape[0] * img.shape[1])

# ----------------- Encryption/Decryption -----------------
# ----- Encryption/Decryption Functions -----
def rol(x, y): 
    return ((x << (y % 32)) | (x >> (32 - (y % 32)))) & 0xFFFFFFFF

def ror(x, y): 
    return ((x >> (y % 32)) | (x << (32 - (y % 32)))) & 0xFFFFFFFF

def key_schedule(key):
    w, r = 32, 20
    P, Q = 0xB7E15163, 0x9E3779B9
    key_words = [int.from_bytes(key[i:i+4], 'big') for i in range(0, len(key), 4)]
    S = [(P + i * Q) & 0xFFFFFFFF for i in range(2 * r + 4)]
    A = B = i = j = 0
    v = 3 * max(len(S), len(key_words))
    for _ in range(v):
        A = S[i] = rol((S[i] + A + B) & 0xFFFFFFFF, 3)
        B = key_words[j] = rol((key_words[j] + A + B) & 0xFFFFFFFF, (A + B) & 0x1F)
        i = (i + 1) % len(S)
        j = (j + 1) % len(key_words)
    return S

def encrypt_block(block, keys, r):
    A = int.from_bytes(block[:4], 'big')
    B = int.from_bytes(block[4:], 'big')
    A = (A + keys[0]) & 0xFFFFFFFF
    B = (B + keys[1]) & 0xFFFFFFFF
    for i in range(1, r + 1):
        A = (rol(A ^ B, B) + keys[2 * i]) & 0xFFFFFFFF
        B = (rol(B ^ A, A) + keys[2 * i + 1]) & 0xFFFFFFFF
    A = (A + keys[2 * r + 2]) & 0xFFFFFFFF
    B = (B + keys[2 * r + 3]) & 0xFFFFFFFF
    return A.to_bytes(4, 'big') + B.to_bytes(4, 'big')

def decrypt_block(block, keys, r):
    A = int.from_bytes(block[:4], 'big')
    B = int.from_bytes(block[4:], 'big')
    B = (B - keys[2 * r + 3]) & 0xFFFFFFFF
    A = (A - keys[2 * r + 2]) & 0xFFFFFFFF
    for i in range(r, 0, -1):
        B = ror((B - keys[2 * i + 1]) & 0xFFFFFFFF, A) ^ A
        A = ror((A - keys[2 * i]) & 0xFFFFFFFF, B) ^ B
    B = (B - keys[1]) & 0xFFFFFFFF
    A = (A - keys[0]) & 0xFFFFFFFF
    return A.to_bytes(4, 'big') + B.to_bytes(4, 'big')

def pad_data(data, block_size):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def unpad_data(data):
    return data[:-data[-1]]

def encrypt_data(key, data):
    r, bs = 20, 8
    keys = key_schedule(key)
    data = pad_data(data, bs)
    return b''.join(encrypt_block(data[i:i+bs], keys, r) for i in range(0, len(data), bs))

def decrypt_data(key, encrypted):
    r, bs = 20, 8
    keys = key_schedule(key)
    decrypted = b''.join(decrypt_block(encrypted[i:i+bs], keys, r) for i in range(0, len(encrypted), bs))
    return unpad_data(decrypted)


# ----------------- Flask Routes -----------------
@app.route('/', methods=['GET', 'POST'])
def index():
    metrics = {}
    extracted_text = ''
    if request.method == 'POST':
        img1_file = request.files['image1']
        img2_file = request.files['image2']
        secret_text = request.form.get('secret_text', '')

        if not img1_file:
            flash('Cover image is required.'); return redirect(request.url)

        img1_path = os.path.join(app.config['UPLOAD_FOLDER'], img1_file.filename)
        img1_file.save(img1_path)
        img1 = cv2.imread(img1_path)

        if img2_file:
            img2_path = os.path.join(app.config['UPLOAD_FOLDER'], img2_file.filename)
            img2_file.save(img2_path)
            img2 = cv2.resize(cv2.imread(img2_path), (img1.shape[1], img1.shape[0]))
            dct_img = apply_dct_and_idct_color(img2)
            indices = get_z_pattern_indices(img1.shape[0], img1.shape[1])

            for (i, j) in indices:
                for c in range(3):
                    v1 = format(img1[i][j][c], '08b')
                    v2 = format(dct_img[i][j][c], '08b')
                    img1[i][j][c] = int(v1[:4] + v2[:4], 2)
        
        if secret_text:
            img1 = embed_text_in_image(img1, secret_text)

        stego_img = add_watermark(img1)
        stego_path = os.path.join(app.config['UPLOAD_FOLDER'], 'pic3in2.png')
        cv2.imwrite(stego_path, stego_img)

        encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted_image.enc')
        with open(stego_path, 'rb') as f:
            enc = encrypt_data(b'0000000000000000', f.read())
        with open(encrypted_path, 'wb') as f:
            f.write(enc)

        metrics['bpp'] = round(calculate_bpp(stego_path), 3)
        if img2_file:
            metrics['psnr'] = round(calculate_psnr(img2, dct_img), 3)
            metrics['ssim'] = round(calculate_ssim_metric(img2, dct_img), 3)
            metrics['snr'] = round(calculate_snr(img2, dct_img), 3)

        return render_template('index.html', original1=img1_file.filename,
                               original2=img2_file.filename if img2_file else None,
                               merged='pic3in2.png', encrypted='encrypted_image.enc',
                               zpattern='z_pattern.png', metrics=metrics,
                               extracted_text=None)

    return render_template('index.html')

@app.route('/decrypt', methods=['POST'])
def decrypt():
    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted_image.enc')
    with open(encrypted_path, 'rb') as f:
        dec = decrypt_data(b'0000000000000000', f.read())

    stego_decoded_path = os.path.join(app.config['UPLOAD_FOLDER'], 'decrypted_stego.png')
    with open(stego_decoded_path, 'wb') as f:
        f.write(dec)

    stego_img = cv2.imread(stego_decoded_path)
    secret_img = extract_embedded_image(stego_img)
    secret_out_path = os.path.join(app.config['UPLOAD_FOLDER'], 'extracted_secret_image.png')
    cv2.imwrite(secret_out_path, secret_img)

    secret_text = extract_text_from_image(stego_img)

    flash("Secret image and text extracted successfully.")
    return render_template('index.html', decrypted='extracted_secret_image.png', extracted_text=secret_text)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(debug=True)