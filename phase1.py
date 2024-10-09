import json
import os
from concurrent.futures import Future, ThreadPoolExecutor
from functools import partial

import httpx
from tenacity import retry, retry_if_exception_type, wait_random

PARALLEL = 50


class ServiceUnavailableError(Exception):

    """Service unavailable error."""


# Hàm lấy dữ liệu từ OpenPhish


def get_openphish_data(client: httpx.Client):
    url = "https://openphish.com/feed.txt"

    response = client.get(url)

    phishing_urls = response.text.splitlines()

    return phishing_urls


# Hàm lấy dữ liệu từ API của PhishStats


@retry(
    retry=retry_if_exception_type(ServiceUnavailableError),
    wait=wait_random(min=0.5, max=1),
)
def get_phishstats_data_from_api(client: httpx.Client, api_url: str):
    response = client.get(api_url)

    if response.status_code == 200:
        data = response.json()  # Parse dữ liệu JSON

        phishing_urls = [
            str(entry["url"]) for entry in data if "url" in entry
        ]  # Lọc các URL từ dữ liệu

        return phishing_urls

    elif response.status_code == 503:
        raise ServiceUnavailableError

    else:
        raise Exception(f"Error: {response.status_code}")


# Get URLs from PhishStats API


def collect_phishstats_urls(client: httpx.Client):
    all_urls: list[str] = []

    def on_done(page: int, future: Future[list[str]]):
        if future.cancelled():
            print(f"Page no.{page}: cancelled")

        elif future.exception():
            print(f"Page no.{page}: generated an exception: {future.exception()}")

        else:
            urls = future.result()

            all_urls.extend(urls)

            print(f"Page no.{page}: {len(urls)} URLs")

    # with ThreadPool(cpu_count()) as executor:

    #     results = executor.imap_unordered(partial(get_phishstats_data_from_api, client), [(f"https://phishstats.info:2096/api/phishing?_p={page}&_size=100", page) for page in range(100)])

    #     while True:

    #         try:

    #             page, urls = next(results)

    #         except StopIteration:

    #             break

    #         except Exception as exc:

    #             print(f"Generated an exception: {exc}")

    #         else:

    #             all_urls.extend(urls)

    #             print(f"Page no.{page}: {len(urls)} URLs")

    with ThreadPoolExecutor(max_workers=100) as executor:
        future_to_page = {
            executor.submit(
                get_phishstats_data_from_api,
                client,
                f"https://phishstats.info:2096/api/phishing?_p={page}&_size=100",
            ): page
            for page in range(100)
        }

        for future in future_to_page:
            page = future_to_page[future]

            future.add_done_callback(partial(on_done, page))

    return all_urls


# Hàm lấy dữ liệu từ API của Phishtank


def collect_phishtank_urls(client: httpx.Client):
    with open("phishtank.json", "r") as file:
        data = json.load(file)

        return [
            entry["url"] for entry in data if "url" in entry
        ]  # Lọc các URL từ dữ liệu


# Hàm lưu URL


def save_urls_to_file(urls: list[str], folder_path: str, filename: str):
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

    file_path = os.path.join(folder_path, filename)

    with open(file_path, "w") as file:
        for url in urls:
            file.write(url + "\n")


if __name__ == "__main__":
    with httpx.Client() as client:
        # Thu thập URL từ OpenPhish

        print("Getting OpenPhish data")

        openphish_urls = get_openphish_data(client)

        # Thu thập URL từ PhishStats

        print("Collecting PhishStats URLs")

        phishstats_urls = collect_phishstats_urls(client)

        # Thu thập URL từ PhishTank

        print("Collecting PhishTank URLs")

        phishtank_urls = collect_phishtank_urls(client)

    # Lưu các URL vào file

    print("Saving OpenPhish URLs")

    save_urls_to_file(openphish_urls, "./URLs Storage", "openphish_urls.txt")

    print("Saving PhishStats URLs")

    save_urls_to_file(phishstats_urls, "./URLs Storage", "phishstats_urls.txt")

    print("Saving PhishTank URLs")

    save_urls_to_file(phishtank_urls, "./URLs Storage", "phishtank_urls.txt")
