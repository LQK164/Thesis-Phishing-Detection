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


@measure_time
def process_phishing_urls(input_files, phishing_file, output_file, max_workers=50):
    urls = set()

    # Bước 1: Thu thập URL từ các file và gộp lại
    start_collect_time = time.time()
    for input_file in input_files:
        with open(input_file, "r", encoding="utf-8") as file:
            for line in file:
                url = line.strip()
                if url:
                    urls.add(url)  # Lọc trùng lặp ngay khi đọc
    end_collect_time = time.time()
    print(
        f"Thời gian thu thập và gộp URL: {end_collect_time - start_collect_time:.2f} giây"
    )

    # Ghi tất cả URL vào file phishing_file
    with open(phishing_file, "w", encoding="utf-8") as f:
        f.write("\n".join(urls))

    # Bước 2: Kiểm tra trạng thái URL và ghi các URL còn sống
    valid_urls = set()
    start_check_time = time.time()
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(check_url, urls)
        for result in results:
            if result:  # Chỉ thêm URL còn sống
                valid_urls.add(result)
    end_check_time = time.time()
    print(
        f"Thời gian kiểm tra URL còn sống: {end_check_time - start_check_time:.2f} giây"
    )

    # Ghi các URL còn sống vào file output_file
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(valid_urls))

    # Bước 3: Đếm số lượng URL còn sống
    print(f"Số lượng URL còn sống: {len(valid_urls)}")


# Sử dụng hàm
input_files = [
    r"URLs_Storage/phishtank_urls.txt",
    r"URLs_Storage/phishstats_urls.txt",
    r"URLs_Storage/openphish_urls.txt",
]  # Danh sách 3 file đầu vào
phishing_file = "phishing_urls.txt"  # File gộp tất cả URL
output_file = "active_phishing_urls.txt"  # File chứa URL còn sống
process_phishing_urls(input_files, phishing_file, output_file)
