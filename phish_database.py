import requests

url = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt"


def get_urls_from_github(url):
    response = requests.get(url)

    # Kiểm tra nếu yêu cầu thành công (status code 200)
    if response.status_code == 200:
        # Tách các dòng của file
        urls = response.text.splitlines()
        return urls
    else:
        print("Không thể truy cập URL. Mã lỗi:", response.status_code)
        return None


# Gọi hàm và lưu danh sách URL vào file
urls = get_urls_from_github(url)
if urls:
    with open(
        "URLs_Storage/phishing_database_github.txt", "w", encoding="utf-8"
    ) as file:
        for u in urls:
            file.write(u + "\n")
    print("Danh sách URL đã được lưu vào.")
