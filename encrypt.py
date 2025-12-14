import cv2
import numpy as np
import matplotlib.pyplot as plt
from scipy.fftpack import dct, idct

# --- Encryption setup remains same (RC6-like logic) ---
# (key_schedule, rol, ror, encrypt_block, decrypt_block, etc., remain unchanged)

# ---------------- NEW ENCRYPT FUNCTION ---------------- #

def rol(x, y):
    y = y % 32
    return ((x << y) | (x >> (32 - y))) & 0xFFFFFFFF

def ror(x, y):
    y = y % 32
    return ((x >> y) | (x << (32 - y))) & 0xFFFFFFFF

def key_schedule(key):
    w = 32
    r = 20
    P = 0xB7E15163
    Q = 0x9E3779B9

    key_words = [int.from_bytes(key[i:i+4], byteorder='big') for i in range(0, len(key), 4)]
    S = [(P + (i * Q)) & 0xFFFFFFFF for i in range(2 * r + 4)]

    A = B = i = j = 0
    v = 3 * max(len(S), len(key_words))

    for _ in range(v):
        A = S[i] = rol((S[i] + A + B) & 0xFFFFFFFF, 3)
        B = key_words[j] = rol((key_words[j] + A + B) & 0xFFFFFFFF, (A + B) & 0x1F)
        i = (i + 1) % len(S)
        j = (j + 1) % len(key_words)

    return S

def encrypt_block(block, round_keys, r):
    A = int.from_bytes(block[:4], byteorder='big')
    B = int.from_bytes(block[4:], byteorder='big')

    A = (A + round_keys[0]) & 0xFFFFFFFF
    B = (B + round_keys[1]) & 0xFFFFFFFF

    for i in range(1, r + 1):
        A = (rol((A ^ B), B) + round_keys[2*i]) & 0xFFFFFFFF
        B = (rol((B ^ A), A) + round_keys[2*i + 1]) & 0xFFFFFFFF

    A = (A + round_keys[2*r + 2]) & 0xFFFFFFFF
    B = (B + round_keys[2*r + 3]) & 0xFFFFFFFF

    return A.to_bytes(4, byteorder='big') + B.to_bytes(4, byteorder='big')

def decrypt_block(block, round_keys, r):
    A = int.from_bytes(block[:4], byteorder='big')
    B = int.from_bytes(block[4:], byteorder='big')

    B = (B - round_keys[2*r + 3]) & 0xFFFFFFFF
    A = (A - round_keys[2*r + 2]) & 0xFFFFFFFF

    for i in range(r, 0, -1):
        B = ror((B - round_keys[2*i + 1]) & 0xFFFFFFFF, A) ^ A
        A = ror((A - round_keys[2*i]) & 0xFFFFFFFF, B) ^ B

    B = (B - round_keys[1]) & 0xFFFFFFFF
    A = (A - round_keys[0]) & 0xFFFFFFFF

    return A.to_bytes(4, byteorder='big') + B.to_bytes(4, byteorder='big')

def pad_data(data, block_size):
    padding_len = block_size - len(data) % block_size
    return data + bytes([padding_len] * padding_len)

def unpad_data(data):
    padding_len = data[-1]
    return data[:-padding_len]

def encrypt_data(key, data):
    block_size = 8
    r = 20
    round_keys = key_schedule(key)
    padded_data = pad_data(data, block_size)
    encrypted_blocks = []

    for i in range(0, len(padded_data), block_size):
        block = padded_data[i:i+block_size]
        encrypted_blocks.append(encrypt_block(block, round_keys, r))

    return b''.join(encrypted_blocks)

def decrypt_data(key, encrypted_data):
    block_size = 8
    r = 20
    round_keys = key_schedule(key)
    decrypted_blocks = []

    for i in range(0, len(encrypted_data), block_size):
        block = encrypted_data[i:i+block_size]
        decrypted_blocks.append(decrypt_block(block, round_keys, r))

    decrypted_data = b''.join(decrypted_blocks)
    return unpad_data(decrypted_data)

def encrypt_data(key, data):
    block_size = 8
    r = 20

    round_keys = key_schedule(key)
    encrypted_blocks = []
    padded_data = pad_data(data, block_size)

    for i in range(0, len(padded_data), block_size):
        block = padded_data[i:i+block_size]
        encrypted_block = encrypt_block(block, round_keys, r)
        encrypted_blocks.append(encrypted_block)

    return b''.join(encrypted_blocks)


def encrypt():
    # Load input images
    img1 = cv2.imread('coverimage.png')  # Cover image
    img2 = cv2.imread('secretimage.png')  # Secret image

    # Resize images to same size
    img2 = cv2.resize(img2, (img1.shape[1], img1.shape[0]))

    # Perform DCT + IDCT per channel on img2 (color-preserving transform)
    def apply_dct_color(image):
        dct_image = np.zeros_like(image, dtype=np.float32)
        for c in range(3):
            dct_channel = dct(dct(image[:, :, c].astype(np.float32), axis=0, norm='ortho'), axis=1, norm='ortho')
            idct_channel = idct(idct(dct_channel, axis=0, norm='ortho'), axis=1, norm='ortho')
            dct_image[:, :, c] = np.clip(idct_channel, 0, 255)
        return dct_image.astype(np.uint8)

    transformed_img2 = apply_dct_color(img2)
    cv2.imwrite("dct_output.png", transformed_img2)

    # Show transformation visually (optional)
    plt.figure(figsize=(10, 4))
    plt.subplot(131)
    plt.title('Original Secret (img2)')
    plt.imshow(cv2.cvtColor(img2, cv2.COLOR_BGR2RGB))
    plt.subplot(132)
    plt.title('DCT + IDCT Processed')
    plt.imshow(cv2.cvtColor(transformed_img2, cv2.COLOR_BGR2RGB))
    plt.subplot(133)
    plt.title('Cover Image (img1)')
    plt.imshow(cv2.cvtColor(img1, cv2.COLOR_BGR2RGB))
    plt.tight_layout()
    plt.show()

    # Embed the transformed image into img1 using 4 MSBs from both
    for i in range(img1.shape[0]):
        for j in range(img1.shape[1]):
            for c in range(3):
                v1 = format(img1[i, j, c], '08b')
                v2 = format(transformed_img2[i, j, c], '08b')
                combined = v1[:4] + v2[:4]
                img1[i, j, c] = int(combined, 2)

    # Save the stego-image
    cv2.imwrite("stego_image.png", img1)

    # Encrypt the image file
    with open('stego_image.png', 'rb') as f:
        image_data = f.read()
    key = b'0000000000000000'
    encrypted_data = encrypt_data(key, image_data)

    print("Encrypted Data Length:", len(encrypted_data))
    print("Encrypted Data (Hex):", encrypted_data[:64].hex() + '...')  # Show a short preview

    with open('encrypted_image.enc', 'wb') as f:
        f.write(encrypted_data)

# Run it
encrypt()
