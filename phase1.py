import logging
import logging.config
import os
from concurrent.futures import Future, ThreadPoolExecutor
from functools import partial
from typing import Callable, TypeVar

import httpx
from tenacity import retry, retry_if_exception_type, wait_random

PARALLEL = 50

# Cấu hình logging
LOGGING_CONFIG = {
    "version": 1,
    "handlers": {
        "default": {
            "class": "logging.StreamHandler",
            "formatter": "phase1",
            "stream": "ext://sys.stderr",
        },
        "file": {
            "class": "logging.FileHandler",
            "formatter": "phase1",
            "filename": "url_count.log",
        },
    },
    "formatters": {
        "phase1": {
            "format": "%(levelname)s [%(asctime)s] %(name)s - %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        }
    },
    "loggers": {
        "": {
            "handlers": ["default", "file"],
            "level": "DEBUG",
        },
    },
}
logging.config.dictConfig(LOGGING_CONFIG)


class ServiceUnavailableError(Exception):
    """Service unavailable error."""


class StatusCodeError(Exception):
    """Status code error."""

    def __init__(self, status_code: int):
        self.status_code = status_code

    def __str__(self):
        return f"StatusCodeError({self.status_code})"


T = TypeVar("T")


def get(
    client: httpx.Client,
    url: str,
    tag: str = "",
    apply_fn: Callable[[httpx.Response], T] | None = None,
):
    if not tag:
        tag = url
    response = client.get(url)

    if response.status_code == 200:
        if apply_fn:
            return apply_fn(response)
        return response
    elif response.status_code == 503:
        raise ServiceUnavailableError
    else:
        raise StatusCodeError(response.status_code)


# Hàm lấy dữ liệu từ OpenPhish
def get_openphish_data(client: httpx.Client):
    return get(
        client,
        "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
        "OpenPhish",
        lambda response: response.text.splitlines(),
    )


# Hàm lấy dữ liệu từ API của PhishStats
@retry(
    retry=retry_if_exception_type(ServiceUnavailableError),
    wait=wait_random(min=0.5, max=1),
)
def get_phishstats_data_from_api(client: httpx.Client, api_url: str):
    return get(
        client,
        api_url,
        "PhishStats",
        lambda response: [
            str(entry["url"]) for entry in response.json() if "url" in entry
        ],  # Lọc các URL từ dữ liệu
    )


# Get URLs from PhishStats API
def collect_phishstats_urls(client: httpx.Client, pages: int = 100):
    all_urls: list[str] = []
    any_error = False

    def on_done(page: int, future: Future[list[str] | httpx.Response]):
        global any_error

        if future.cancelled():
            logging.info(f"PhishStats page no.{page}: cancelled")

        elif future.exception():
            logging.error(
                f"PhishStats page no.{page} generated an exception: {future.exception()}"
            )
            any_error = True

        else:
            urls = future.result()

            if isinstance(urls, httpx.Response):
                logging.error(
                    f"PhishStats page no.{page}: status code {urls.status_code}"
                )
                return

            if not urls:
                logging.error(f"PhishStats page no.{page}: no URLs")
                return

            all_urls.extend(urls)

            logging.info(f"PhishStats page no.{page}: {len(urls)} URLs")

    with ThreadPoolExecutor(max_workers=pages) as executor:
        future_to_page = {
            executor.submit(
                get_phishstats_data_from_api,
                client,
                f"https://phishstats.info:2096/api/phishing?_p={page}&_size=100",
            ): page
            for page in range(pages)
        }

        for future in future_to_page:
            page = future_to_page[future]
            future.add_done_callback(partial(on_done, page))

    if any_error:
        logging.warn("PhishStats: some pages were not fetched. See logs above")

    return all_urls


# Hàm lấy dữ liệu từ API của Phishtank
def collect_phishtank_urls(client: httpx.Client):
    return get(
        client,
        "https://data.phishtank.com/data/online-valid.json",
        "PhishTank",
        lambda response: [
            entry["url"] for entry in response.json() if "url" in entry
        ],  # Lọc các URL từ dữ liệu
    )


# Hàm lưu URL
def save_urls_to_file(urls: list[str], folder_path: str, filename: str):
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

    file_path = os.path.join(folder_path, filename)

    with open(file_path, "w", encoding="utf-8") as file:
        for url in urls:
            file.write(url + "\n")


if __name__ == "__main__":
    with httpx.Client(follow_redirects=True) as client:
        # Thu thập URL từ OpenPhish

        logging.info("Getting OpenPhish data")

        try:
            openphish_urls = get_openphish_data(client)
            if isinstance(openphish_urls, httpx.Response):
                logging.warn("OpenPhish: apply_fn not called")
                openphish_urls = []
        except ServiceUnavailableError:
            logging.info("OpenPhish service unavailable")
            openphish_urls = []
        except Exception as e:
            logging.error(f"OpenPhish: {e}")
            openphish_urls = []

        # Thu thập URL từ PhishStats

        logging.info("Collecting PhishStats URLs")

        phishstats_urls = collect_phishstats_urls(client)
        if not phishstats_urls:
            logging.error("PhishStats: no URLs")

        # Thu thập URL từ PhishTank

        logging.info("Collecting PhishTank URLs")

        try:
            phishtank_urls = collect_phishtank_urls(client)
            if isinstance(phishtank_urls, httpx.Response):
                logging.warn("PhishTank: apply_fn not called")
                phishtank_urls = []
        except ServiceUnavailableError:
            logging.info("PhishTank service unavailable")
            phishtank_urls = []
        except Exception as e:
            logging.error(f"PhishTank: {e}")
            phishtank_urls = []

    # Lưu các URL vào file

    if openphish_urls:
        logging.info(f"Saving {len(openphish_urls)} OpenPhish URLs")
        save_urls_to_file(openphish_urls, "./URLs Storage", "openphish_urls.txt")

    if phishstats_urls:
        logging.info(f"Saving {len(phishstats_urls)} PhishStats URLs")
        save_urls_to_file(phishstats_urls, "./URLs Storage", "phishstats_urls.txt")

    if phishtank_urls:
        logging.info(f"Saving {len(phishtank_urls)} PhishTank URLs")
        save_urls_to_file(phishtank_urls, "./URLs Storage", "phishtank_urls.txt")
