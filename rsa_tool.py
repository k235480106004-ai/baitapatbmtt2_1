"""
BÀI 2: CHƯƠNG TRÌNH MÃ HÓA VÀ GIẢI MÃ RSA (.NET / PYTHON COMPATIBLE)
Hỗ trợ sinh khóa PEM, đọc cấu trúc ASN.1/DER PEM, mã hóa/giải mã khóa AES,
đánh giá tốc độ e vs d, hiệu ứng thác đổ SHA-256 và Chữ ký số ngẫu nhiên RSASSA-PSS.
"""

import time
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

def generate_rsa_keypair(key_size=2048):
    """Sinh cặp khóa RSA (2048-bit)"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def export_keys_to_pem(private_key, public_key, priv_file="private_key.pem", pub_file="public_key.pem"):
    """Xuất cặp khóa RSA ra tệp tin chuẩn định dạng PEM"""
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    with open(priv_file, "wb") as f:
        f.write(priv_pem)
    with open(pub_file, "wb") as f:
        f.write(pub_pem)
        
    print(f"[+] Đã xuất Khóa Bí Mật ra file: {priv_file}")
    print(f"[+] Đã xuất Khóa Công Khai ra file: {pub_file}")

def view_pem_structure(pem_file):
    """Phân tích và hiển thị cấu trúc Byte/ASN.1 của file PEM"""
    with open(pem_file, "rb") as f:
        content = f.read().decode('utf-8')
        
    print(f"=== PHÂN TÍCH FILE PEM: {pem_file} ===")
    lines = content.strip().split('\n')
    print(f"Header: {lines[0]}")
    print(f"Footer: {lines[-1]}")
    
    # Giải mã Base64 lấy dữ liệu nhị phân DER
    b64_body = "".join(lines[1:-1])
    der_bytes = base64.b64decode(b64_body)
    print(f"Độ dài nhị phân (DER binary): {len(der_bytes)} bytes")
    print(f"Hex Dump (32 bytes đầu): {der_bytes[:32].hex()}")
    print("Ý nghĩa các thành phần ASN.1:")
    print("  - Sequence Tag (0x30): Đánh dấu khối danh sách các số nguyên.")
    print("  - Modulus (n = p * q): Số nguyên tố tích lớn tạo thành không gian mã hóa.")
    print("  - Public Exponent (e = 65537): Số mũ công khai dùng mã hóa/xác thực.")
    print("  - Private Exponent (d): Số mũ bí mật giải mã (d = e^-1 mod phi(n)).")
    print("  - Primes (p, q), Exponents (dp, dq), Coefficient (qinv): Các tham số tăng tốc CRT.")
    print("-" * 50)

def load_public_key_from_pem(pub_file="public_key.pem"):
    """Đọc Khóa Công Khai từ PEM lấy tham số (n, e)"""
    with open(pub_file, "rb") as f:
        pub_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    numbers = pub_key.public_numbers()
    print(f"[+] Đã import Public Key từ {pub_file}")
    print(f"    - Public Exponent (e): {numbers.e}")
    print(f"    - Modulus (n): {hex(numbers.n)[:30]}...")
    return pub_key

def load_private_key_from_pem(priv_file="private_key.pem"):
    """Đọc Khóa Bí Mật từ PEM lấy tham số (n, e, d, p, q...)"""
    with open(priv_file, "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    numbers = priv_key.private_numbers()
    print(f"[+] Đã import Private Key từ {priv_file}")
    print(f"    - Modulus (n): {hex(numbers.public_numbers.n)[:30]}...")
    print(f"    - Private Exponent (d): {hex(numbers.d)[:30]}...")
    return priv_key

def encrypt_rsa_data(public_key, data_bytes, output_file="encrypted_rsa.b64"):
    """Mã hóa dữ liệu nhỏ (ví dụ khóa AES 32 bytes) bằng RSA Public Key"""
    if len(data_bytes) > 190:
        raise ValueError("Dữ liệu vượt quá giới hạn tối đa của RSA-2048 với OAEP Padding (190 bytes)")
        
    ciphertext = public_key.encrypt(
        data_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    b64_str = base64.b64encode(ciphertext).decode('utf-8')
    with open(output_file, "w") as f:
        f.write(b64_str)
        
    print(f"[+] Đã mã hóa dữ liệu ({len(data_bytes)} bytes) -> Lưu file Base64: {output_file}")
    return b64_str

def decrypt_rsa_data(private_key, input_file="encrypted_rsa.b64"):
    """Giải mã dữ liệu RSA bằng Private Key từ file Base64"""
    with open(input_file, "r") as f:
        b64_str = f.read().strip()
    ciphertext = base64.b64decode(b64_str)
    
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"[+] Đã giải mã thành công từ file {input_file} ({len(plaintext)} bytes)")
    return plaintext

def benchmark_rsa_speed(private_key, public_key, iterations=100):
    """Đánh giá tốc độ mã hóa với Public Key (e nhỏ) vs Giải mã với Private Key (d lớn)"""
    test_data = b"AES_KEY_32_BYTES_SECRET_KEY_1234"  # 32-byte AES key
    
    print(f"[*] Đang thực hiện Benchmark RSA ({iterations} lượt)...")
    
    # 1. Đo thời gian mã hóa (Public Key: e = 65537 - kích thước bé)
    t0 = time.time()
    ciphertexts = []
    for _ in range(iterations):
        c = public_key.encrypt(
            test_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        ciphertexts.append(c)
    enc_time = time.time() - t0
    
    # 2. Đo thời gian giải mã (Private Key: d - kích thước siêu lớn 2048-bit)
    t0 = time.time()
    for c in ciphertexts:
        _ = private_key.decrypt(
            c,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    dec_time = time.time() - t0
    
    print(f"    - Thời gian Mã hóa (Public Key e=65537): {enc_time:.6f}s (TB: {enc_time/iterations*1000:.3f} ms/lần)")
    print(f"    - Thời gian Giải mã (Private Key d lớn): {dec_time:.6f}s (TB: {dec_time/iterations*1000:.3f} ms/lần)")
    print(f"    - Tỉ lệ chênh lệch: Giải mã với Private Key chậm hơn Mã hóa với Public Key {dec_time/enc_time:.2f} lần.")
    print("    => ĐÁNH GIÁ: Phép nâng lũy thừa mod với số mũ nhỏ (e=65537) cực nhanh so với số mũ d (2048 bit).")

def sha256_avalanche_effect(input1, input2):
    """Đánh giá hiệu ứng thác đổ (Avalanche Effect) của hàm băm SHA-256"""
    h1_hex = hashlib.sha256(input1.encode('utf-8')).hexdigest()
    h2_hex = hashlib.sha256(input2.encode('utf-8')).hexdigest()
    
    h1_bin = bin(int(h1_hex, 16))[2:].zfill(256)
    h2_bin = bin(int(h2_hex, 16))[2:].zfill(256)
    
    diff_bits = sum(b1 != b2 for b1, b2 in zip(h1_bin, h2_bin))
    pct = (diff_bits / 256) * 100
    
    print("=== ĐÁNH GIÁ HIỆU ỨNG THÁC ĐỔ SHA-256 ===")
    print(f"  Input 1: '{input1}'")
    print(f"  Hash 1 : {h1_hex}")
    print(f"  Input 2: '{input2}'")
    print(f"  Hash 2 : {h2_hex}")
    print(f"  Số bit khác biệt: {diff_bits}/256 bits ({pct:.2f}%)")
    print("  => KẾT LUẬN: Thay đổi dù chỉ 1 bit/ký tự đầu vào dẫn đến thay đổi ~50% các bit băm ngẫu nhiên.")

def demonstrate_rsassa_pss_signature(private_key, public_key, message):
    """Đề xuất & Thực nghiệm Chữ ký số ngẫu nhiên RSASSA-PSS (Cùng private key + message -> Chữ ký khác nhau)"""
    print("=== THỰC NGHIỆM CHỮ KÝ SỐ RSASSA-PSS ===")
    print(f"Thông điệp ký: '{message}'")
    
    # Lần ký 1
    sig1 = private_key.sign(
        message.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    # Lần ký 2 (Cùng key, cùng message)
    sig2 = private_key.sign(
        message.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    b64_sig1 = base64.b64encode(sig1).decode('utf-8')
    b64_sig2 = base64.b64encode(sig2).decode('utf-8')
    
    print(f"Chữ ký Lần 1 (Base64): {b64_sig1[:40]}...")
    print(f"Chữ ký Lần 2 (Base64): {b64_sig2[:40]}...")
    print(f"Hai chữ ký có giống nhau không?: {b64_sig1 == b64_sig2}")
    
    # Xác minh cả 2 chữ ký với Public Key
    try:
        public_key.verify(
            sig1,
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("[+] Xác thực Chữ ký 1: HỢP LỆ (VALID)")
    except Exception as e:
        print("[-] Xác thực Chữ ký 1: THẤT BẠI")

    try:
        public_key.verify(
            sig2,
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("[+] Xác thực Chữ ký 2: HỢP LỆ (VALID)")
    except Exception as e:
        print("[-] Xác thực Chữ ký 2: THẤT BẠI")

    print("=> GIẢI PHÁP ĐỀ XUẤT: RSASSA-PSS chèn thêm Salt ngẫu nhiên trước khi băm, giúp chống lại các cuộc tấn công replay & cho ra chữ ký biến đổi mỗi lần ký.")
