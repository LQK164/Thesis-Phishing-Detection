import requests


def filter_valid_unique_urls(input_file, output_file):
    urls = set()
    valid_urls = set()

    # Đọc file và thêm các URL duy nhất vào tập hợp
    with open(input_file, "r", encoding="utf-8") as file:
        for line in file:
            url = line.strip()
            if url:
                urls.add(url)  # Loại bỏ URL trùng lặp ngay trong bước đọc

    # Kiểm tra trạng thái của từng URL để giữ lại URL còn sống
    for url in urls:
        try:
            response = requests.head(url, timeout=5)
            if response.status_code < 400:
                valid_urls.add(url)  # Chỉ thêm URL còn sống vào kết quả
        except requests.RequestException:
            continue  # Bỏ qua URL nếu không truy cập được

    # Ghi kết quả vào file
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("Danh sách URL còn sống và không bị trùng:\n\n")
        for url in valid_urls:
            f.write(f"{url}\n")


# Sử dụng hàm
input_file = r"URLs Storage/phishtank_urls.txt"
output_file = "ket_qua_url_con_song_va_khong_trung.txt"
filter_valid_unique_urls(input_file, output_file)
