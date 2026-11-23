========================================================================
BỘ MÃ NGUỒN BÀI TẬP MÔN AN TOÀN VÀ BẢO MẬT THÔNG TIN
Sinh viên: Vũ Thế Anh 
========================================================================

DANH MỤC CÁC TỆP NGUỒN:
1. aes_tool.py  : Module mã hóa/giải mã AES-256 đối xứng theo luồng (Streaming),
                  xử lý file dung lượng lớn (GB), sinh/lưu/nạp khóa, so sánh byte.
2. rsa_tool.py  : Module RSA bất đối xứng, xuất/nạp file PEM, phân tích ASN.1 DER,
                  mã hóa/giải mã khóa AES, đánh giá tốc độ Public vs Private key,
                  hiệu ứng thác đổ SHA-256 và Chữ ký số ngẫu nhiên RSASSA-PSS.
3. main.py      : Chương trình điều khiển trung tâm tự động thực thi toàn bộ yêu cầu.

CÁCH CHẠY CHƯƠNG TRÌNH:
Yêu cầu thư viện: cryptography
Cài đặt: pip install cryptography

Chạy lệnh:
python main.py
