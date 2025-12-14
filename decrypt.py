import os
import cv2
import numpy as np
from math import log10

# --------- Encryption Decryption Core ----------
def rol(x, y): return ((x << (y % 32)) | (x >> (32 - (y % 32)))) & 0xFFFFFFFF
def ror(x, y): return ((x >> (y % 32)) | (x << (32 - (y % 32)))) & 0xFFFFFFFF

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

def unpad_data(data): return data[:-data[-1]]

def decrypt_data(key, encrypted):
    r, bs = 20, 8
    keys = key_schedule(key)
    decrypted = b''.join(decrypt_block(encrypted[i:i+bs], keys, r) for i in range(0, len(encrypted), bs))
    return unpad_data(decrypted)

# --------- Stego Extraction Utilities ----------
def get_z_pattern_indices(rows, cols):
    indices = []
    for r in range(rows):
        cols_range = range(cols) if r % 2 == 0 else reversed(range(cols))
        for c in cols_range:
            indices.append((r, c))
    return indices

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

# --------- Main Decryption Process ----------
def decrypt_stego_image(enc_path, key_bytes, out_image_path, out_secret_path):
    # Step 1: Read and decrypt file
    with open(enc_path, 'rb') as f:
        enc_data = f.read()
    decrypted_data = decrypt_data(key_bytes, enc_data)

    # Step 2: Save decrypted image temporarily
    with open(out_image_path, 'wb') as f:
        f.write(decrypted_data)

    # Step 3: Load image and extract content
    stego_img = cv2.imread(out_image_path)
    extracted_img = extract_embedded_image(stego_img)
    extracted_text = extract_text_from_image(stego_img)

    # Step 4: Save results
    cv2.imwrite(out_secret_path, extracted_img)
    print("[✔] Decryption Complete")
    print("[🖼] Secret Image Saved To:", out_secret_path)
    print("[📝] Extracted Text:", extracted_text)

# --------- Run Script Example ----------
if __name__ == '__main__':
    encrypted_file = 'encrypted_image.enc'  # Update path as needed
    decrypted_image_path = 'decrypted_stego_image.png'
    extracted_secret_path = 'extracted_secret_image.png'
    key = b'0000000000000000'

    decrypt_stego_image(encrypted_file, key, decrypted_image_path, extracted_secret_path)
