import time
from concurrent.futures import ThreadPoolExecutor

import requests


def check_url(url):
    """
    Kiểm tra trạng thái của một URL.
    Trả về URL nếu trạng thái HTTP hợp lệ (<400), ngược lại trả về None.
    """
    try:
        response = requests.head(url, timeout=5)
        if response.status_code < 400:
            return url
    except requests.RequestException:
        return None


def measure_time(func):
    """
    Decorator để đo thời gian thực thi của một hàm.
    """

    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        print(f"Thời gian thực thi: {end_time - start_time:.2f} giây")
        return result

    return wrapper


def merge_input_files(input_files, phishing_file):
    """
    Gộp các file đầu vào thành một file phishing_file.
    """
    urls = set()
    for input_file in input_files:
        with open(input_file, "r", encoding="utf-8") as file:
            for line in file:
                url = line.strip()
                if url:
                    urls.add(url)  # Lọc trùng lặp
    with open(phishing_file, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(urls)) + "\n")
    print(f"Gộp xong {len(urls)} URL vào {phishing_file}")


def get_existing_urls(file_path):
    """
    Đọc danh sách URL từ file.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        return set()


@measure_time
def process_phishing_urls(
    phishing_file, active_file, new_urls_file, output_file, max_workers=50
):
    # Bước 1: Đọc tất cả URL từ phishing_file
    with open(phishing_file, "r", encoding="utf-8") as file:
        urls = set(line.strip() for line in file if line.strip())

    # Bước 2: Kiểm tra trạng thái URL và lọc các URL còn sống
    valid_urls = set()
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(check_url, urls)
        for result in results:
            if result:
                valid_urls.add(result)

    # Bước 3: So sánh với active_file
    existing_urls = get_existing_urls(active_file)
    new_urls = valid_urls - existing_urls

    # Ghi URL mới vào new_urls_file
    with open(new_urls_file, "w", encoding="utf-8") as f:
        if new_urls:
            f.write("\n".join(sorted(new_urls)) + "\n")
        else:
            f.write("")  # Ghi file rỗng nếu không có URL mới

    # Bước 4: Ghi đè danh sách URL còn sống vào active_file
    with open(active_file, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(valid_urls)))

    # Bước 5: Ghi các URL còn sống vào output_file
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(valid_urls)))

    # Thống kê
    print(f"Tổng số URL trong {phishing_file}: {len(urls)}")
    print(f"Số lượng URL còn sống: {len(valid_urls)}")
    print(f"Số lượng URL mới: {len(new_urls)}")


# Sử dụng hàm
input_files = [
    r"URLs_Storage/phishtank_urls.txt",
    r"URLs_Storage/phishstats_urls.txt",
    r"URLs_Storage/openphish_urls.txt",
]  # Danh sách file đầu vào
phishing_file = "phishing_urls.txt"  # File gộp tất cả URL
active_file = "active_phishing_urls.txt"  # File chứa URL còn sống từ lần chạy trước
new_urls_file = "new_phishing_urls.txt"  # File chứa URL mới
output_file = "active_phishing_urls.txt"  # Ghi đè file active với URL còn sống

# Gộp các file đầu vào
merge_input_files(input_files, phishing_file)

# Xử lý URL và xuất kết quả
process_phishing_urls(phishing_file, active_file, new_urls_file, output_file)
