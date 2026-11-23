"""
MAIN RUNNER CHƯƠNG TRÌNH AN TOÀN VÀ BẢO MẬT THÔNG TIN
Tự động chạy toàn bộ các yêu cầu của Bài 1 (AES) và Bài 2 (RSA)
"""

import os
import aes_tool
import rsa_tool

def main():
    print("="*70)
    print("  CHƯƠNG TRÌNH THỰC NGHIỆM BÀI TẬP MÔN AN TOÀN VÀ BẢO MẬT THÔNG TIN")
    print("  Sinh viên thực hiện: Nguyễn Trung Kiên")
    print("="*70)
    
    # -------------------------------------------------------------
    # BÀI 1: AES SYMMETRIC ENCRYPTION
    # -------------------------------------------------------------
    print("\n>>> THỰC THI BÀI 1: MÃ HÓA AES DẠNG STREAMING DUNG LƯỢNG LỚN <<<")
    key = aes_tool.generate_aes_key(32)
    aes_tool.save_key_to_file(key, "aes_key.bin")
    loaded_key = aes_tool.load_key_from_file("aes_key.bin")
    
    # Test mã hóa đoạn văn bản
    text = "Nguyễn Trung Kiên - Bài tập An toàn và Bảo mật thông tin 2026"
    enc_text = aes_tool.encrypt_text(text, loaded_key)
    dec_text = aes_tool.decrypt_text(enc_text, loaded_key)
    print(f"[+] Mã hóa văn bản thành công!")
    print(f"    - Plaintext : {text}")
    print(f"    - Decrypted : {dec_text}")
    
    # Test mã hóa file mẫu
    test_file_in = "large_test_data.bin"
    test_file_enc = "large_test_data.enc"
    test_file_dec = "large_test_data.dec"
    
    print("\n[*] Tạo file mẫu thử nghiệm (50 MB)...")
    with open(test_file_in, "wb") as f:
        f.write(os.urandom(50 * 1024 * 1024))
        
    aes_tool.encrypt_file_stream(test_file_in, test_file_enc, loaded_key)
    aes_tool.decrypt_file_stream(test_file_enc, test_file_dec, loaded_key)
    aes_tool.compare_files_byte_by_byte(test_file_in, test_file_dec)

    # -------------------------------------------------------------
    # BÀI 2: RSA ASYMMETRIC ENCRYPTION & DIGITAL SIGNATURE
    # -------------------------------------------------------------
    print("\n>>> THỰC THI BÀI 2: RSA PEM, SHA-256 AVALANCHE & CHỮ KÝ SỐ RSASSA-PSS <<<")
    priv_key, pub_key = rsa_tool.generate_rsa_keypair(2048)
    rsa_tool.export_keys_to_pem(priv_key, pub_key, "private_key.pem", "public_key.pem")
    
    rsa_tool.view_pem_structure("public_key.pem")
    rsa_tool.view_pem_structure("private_key.pem")
    
    imported_pub = rsa_tool.load_public_key_from_pem("public_key.pem")
    imported_priv = rsa_tool.load_private_key_from_pem("private_key.pem")
    
    # Mã hóa khóa AES 32 bytes qua RSA
    rsa_tool.encrypt_rsa_data(imported_pub, loaded_key, "aes_key_encrypted_rsa.b64")
    decrypted_aes_key = rsa_tool.decrypt_rsa_data(imported_priv, "aes_key_encrypted_rsa.b64")
    print(f"[+] Kiểm tra trùng khớp khóa AES sau khi giải mã RSA: {loaded_key == decrypted_aes_key}")
    
    # Đánh giá tốc độ RSA
    rsa_tool.benchmark_rsa_speed(imported_priv, imported_pub, iterations=100)
    
    # SHA-256 Avalanche Effect
    rsa_tool.sha256_avalanche_effect("AnToanBaoMatThongTin2026", "AnToanBaoMatThongTin2027")
    
    # RSASSA-PSS Digital Signature
    rsa_tool.demonstrate_rsassa_pss_signature(imported_priv, imported_pub, "Chữ ký điện tử bảo mật hợp đồng 2026")

if __name__ == "__main__":
    main()
