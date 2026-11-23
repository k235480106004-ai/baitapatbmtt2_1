"""
BÀI 1: CHƯƠNG TRÌNH MÃ HÓA VÀ GIẢI MÃ AES (SYMMETRIC STREAMING ENCRYPTION)
Hỗ trợ sinh khóa, lưu/đọc khóa, mã hóa chuỗi/file dung lượng lớn (GB) theo luồng (chunking).
"""

import os
import time
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def generate_aes_key(key_size=32):
    """Sinh khóa AES (mặc định 256-bit = 32 bytes)"""
    return os.urandom(key_size)

def save_key_to_file(key, filename="aes_key.bin"):
    """Lưu khóa AES ra file"""
    with open(filename, "wb") as f:
        f.write(key)
    print(f"[+] Đã lưu khóa AES vào file: {filename}")

def load_key_from_file(filename="aes_key.bin"):
    """Đọc khóa AES từ file"""
    with open(filename, "rb") as f:
        key = f.read()
    print(f"[+] Đã đọc khóa AES từ file: {filename} ({len(key)*8}-bit)")
    return key

def encrypt_text(plaintext, key):
    """Mã hóa văn bản chuỗi bằng AES-256-CBC"""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return iv + ciphertext

def decrypt_text(encrypted_bytes, key):
    """Giải mã văn bản bằng AES-256-CBC"""
    iv = encrypted_bytes[:16]
    ciphertext = encrypted_bytes[16:]
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    
    return plaintext.decode('utf-8')

def encrypt_file_stream(input_file, output_file, key, chunk_size=64*1024*1024):
    """Mã hóa file dung lượng lớn theo luồng (Streaming Block Encryption)"""
    start_time = time.time()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(128).padder()
    file_size = os.path.getsize(input_file)
    processed = 0

    with open(input_file, "rb") as f_in, open(output_file, "wb") as f_out:
        f_out.write(iv)  # Ghi 16-byte IV vào đầu file
        while True:
            chunk = f_in.read(chunk_size)
            processed += len(chunk)
            if len(chunk) == 0:
                break
            if len(chunk) < chunk_size or processed == file_size:
                # Chunk cuối cùng: thực hiện Pad
                padded_chunk = padder.update(chunk) + padder.finalize()
                encrypted_chunk = encryptor.update(padded_chunk) + encryptor.finalize()
                f_out.write(encrypted_chunk)
                break
            else:
                padded_chunk = padder.update(chunk)
                encrypted_chunk = encryptor.update(padded_chunk)
                f_out.write(encrypted_chunk)
                
    elapsed_time = time.time() - start_time
    speed = (file_size / (1024*1024)) / elapsed_time if elapsed_time > 0 else 0
    print(f"[+] Mã hóa file hoàn tất: {output_file}")
    print(f"    - Dữ liệu mã hóa: {file_size / (1024*1024):.2f} MB")
    print(f"    - Thời gian mã hóa: {elapsed_time:.4f} giây")
    print(f"    - Tốc độ mã hóa: {speed:.2f} MB/s")
    return elapsed_time

def decrypt_file_stream(input_file, output_file, key, chunk_size=64*1024*1024):
    """Giải mã file dung lượng lớn theo luồng"""
    start_time = time.time()
    file_size = os.path.getsize(input_file)
    
    with open(input_file, "rb") as f_in, open(output_file, "wb") as f_out:
        iv = f_in.read(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        
        remaining = file_size - 16
        while remaining > 0:
            read_bytes = min(chunk_size, remaining)
            chunk = f_in.read(read_bytes)
            remaining -= len(chunk)
            
            decrypted_chunk = decryptor.update(chunk)
            if remaining == 0:
                decrypted_chunk += decryptor.finalize()
                unpadded_chunk = unpadder.update(decrypted_chunk) + unpadder.finalize()
                f_out.write(unpadded_chunk)
            else:
                unpadded_chunk = unpadder.update(decrypted_chunk)
                f_out.write(unpadded_chunk)
                
    elapsed_time = time.time() - start_time
    speed = (file_size / (1024*1024)) / elapsed_time if elapsed_time > 0 else 0
    print(f"[+] Giải mã file hoàn tất: {output_file}")
    print(f"    - Thời gian giải mã: {elapsed_time:.4f} giây")
    print(f"    - Tốc độ giải mã: {speed:.2f} MB/s")
    return elapsed_time

def compare_files_byte_by_byte(file1, file2):
    """So sánh từng Byte và Hash SHA-256 của file nguồn và file giải mã"""
    print("[*] Đang so sánh tính toàn vẹn từng Byte giữa 2 tệp...")
    sha1 = hashlib.sha256()
    sha2 = hashlib.sha256()
    
    same = True
    bytes_checked = 0
    with open(file1, "rb") as f1, open(file2, "rb") as f2:
        while True:
            b1 = f1.read(65536)
            b2 = f2.read(65536)
            
            sha1.update(b1)
            sha2.update(b2)
            
            bytes_checked += len(b1)
            if b1 != b2:
                same = False
                break
            if not b1:
                break
                
    h1 = sha1.hexdigest()
    h2 = sha2.hexdigest()
    
    print(f"    - SHA-256 File Nguồn  : {h1}")
    print(f"    - SHA-256 File Giải Mã: {h2}")
    if same and h1 == h2:
        print(f"[SUCCESS] FILE GIẢI MÃ HOÀN TOÀN TRÙNG KHỚP 100% VỚI FILE NGUỒN! ({bytes_checked} bytes)")
    else:
        print("[FAIL] FILE GIẢI MÃ CÓ SAI KHÁC SO VỚI FILE NGUỒN!")
    return same
