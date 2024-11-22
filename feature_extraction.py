import re
import time
import urllib.parse
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from datetime import datetime
from functools import partial
from typing import Any

# from selenium.webdriver.chrome.service import Service
# from selenium.webdriver.common.keys import Keys
# from selenium.webdriver.common.by import By
from urllib.parse import urlparse

import dns.resolver
import Levenshtein
import pandas as pd
import polars as pl
import requests
import tldextract
import whois
from bs4 import BeautifulSoup

HINTS = [
    "wp",
    "login",
    "includes",
    "admin",
    "content",
    "site",
    "images",
    "js",
    "alibaba",
    "css",
    "myaccount",
    "dropbox",
    "themes",
    "plugins",
    "signin",
    "view",
]

#################################################################################################################################
#               Having IP address in hostname
#################################################################################################################################


def having_ip_address(url: str):
    match = re.search(
        "(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
        "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|"  # IPv4
        "((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)|"  # IPv4 in hexadecimal
        "(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|"
        "[0-9a-fA-F]{7}",
        url,
    )  # Ipv6
    if match:
        return 1
    else:
        return 0


#################################################################################################################################
#               URL hostname length
#################################################################################################################################


def url_length(url: str):
    return len(url)


#################################################################################################################################
#               URL shortening
#################################################################################################################################


def shortening_service(full_url: str):
    match = re.search(
        r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"
        r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"
        r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"
        r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|"
        r"db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|"
        r"q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|"
        r"x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|"
        r"tr\.im|link\.zip\.net",
        full_url,
    )
    if match:
        return 1
    else:
        return 0


#################################################################################################################################
#               Count at (@) symbol at base url
#################################################################################################################################


def count_at(base_url: str):
    return base_url.count("@")


#################################################################################################################################
#               Count comma (,) symbol at base url
#################################################################################################################################


def count_comma(base_url: str):
    return base_url.count(",")


#################################################################################################################################
#               Count dollar ($) symbol at base url
#################################################################################################################################


def count_dollar(base_url: str):
    return base_url.count("$")


#################################################################################################################################
#               Having semicolon (;) symbol at base url
#################################################################################################################################


def count_semicolon(url: str):
    return url.count(";")


#################################################################################################################################
#               Count (space, %20) symbol at base url (Das'19)
#################################################################################################################################


def count_space(base_url: str):
    return base_url.count(" ") + base_url.count("%20")


#################################################################################################################################
#               Count and (&) symbol at base url (Das'19)
#################################################################################################################################


def count_and(base_url: str):
    return base_url.count("&")


#################################################################################################################################
#               Count redirection (//) symbol at full url
#################################################################################################################################


def count_double_slash(full_url: str):
    list = [x.start(0) for x in re.finditer("//", full_url)]
    if list[len(list) - 1] > 6:
        return 1
    else:
        return 0
    # TODO: fix me
    return full_url.count("//")


#################################################################################################################################
#               Count slash (/) symbol at full url
#################################################################################################################################


def count_slash(full_url: str):
    return full_url.count("/")


#################################################################################################################################
#               Count equal (=) symbol at base url
#################################################################################################################################


def count_equal(base_url: str):
    return base_url.count("=")


#################################################################################################################################
#               Count percentage (%) symbol at base url (Chiew2019)
#################################################################################################################################


def count_percentage(base_url: str):
    return base_url.count("%")


#################################################################################################################################
#               Count exclamation (?) symbol at base url
#################################################################################################################################


def count_exclamation(base_url: str):
    return base_url.count("?")


#################################################################################################################################
#               Count underscore (_) symbol at base url
#################################################################################################################################


def count_underscore(base_url: str):
    return base_url.count("_")


#################################################################################################################################
#               Count dash (-) symbol at base url
#################################################################################################################################


def count_hyphens(base_url: str):
    return base_url.count("-")


#################################################################################################################################
#              Count number of dots in hostname
#################################################################################################################################


def count_dots(hostname: str):
    return hostname.count(".")


#################################################################################################################################
#              Count number of colon (:) symbol
#################################################################################################################################


def count_colon(url: str):
    return url.count(":")


#################################################################################################################################
#               Count number of stars (*) symbol (Srinivasa Rao'19)
#################################################################################################################################


def count_star(url: str):
    return url.count("*")


#################################################################################################################################
#               Count number of OR (|) symbol (Srinivasa Rao'19)
#################################################################################################################################


def count_or(url: str):
    return url.count("|")


#################################################################################################################################
#               Path entension != .txt
#################################################################################################################################


def path_extension(url_path: str):
    if url_path.endswith(".txt"):
        return 1
    return 0


#################################################################################################################################
#               Having multiple http or https in url path
#################################################################################################################################


def count_http_token(url_path: str):
    return url_path.count("http")


#################################################################################################################################
#               Uses https protocol
#################################################################################################################################


def https_token(scheme: str):
    if scheme == "https":
        return 0
    return 1


#################################################################################################################################
#               Ratio of digits in hostname
#################################################################################################################################


def ratio_digits(hostname: str):
    return len(re.sub("[^0-9]", "", hostname)) / len(hostname)


#################################################################################################################################
#               Count number of digits in domain/subdomain/path
#################################################################################################################################


def count_digits(line: str):
    return len(re.sub("[^0-9]", "", line))


#################################################################################################################################
#              Checks if tilde symbol exist in webpage URL (Chiew2019)
#################################################################################################################################


def count_tilde(full_url: str):
    if full_url.count("~") > 0:
        return 1
    return 0


#################################################################################################################################
#               number of phish-hints in url path
#################################################################################################################################


def phish_hints(url_path: str):
    count = 0
    for hint in HINTS:
        count += url_path.lower().count(hint)
    return count


#################################################################################################################################
#               Check if TLD exists in the path
#################################################################################################################################


def tld_in_path(tld: str, path: str):
    if path.lower().count(tld) > 0:
        return 1
    return 0


#################################################################################################################################
#               Check if tld is used in the subdomain
#################################################################################################################################


def tld_in_subdomain(tld: str, subdomain: str):
    if subdomain.count(tld) > 0:
        return 1
    return 0


#################################################################################################################################
#               Check if TLD in bad position (Chiew2019)
#################################################################################################################################


def tld_in_bad_position(tld: str, subdomain: str, path: str):
    if tld_in_path(tld, path) == 1 or tld_in_subdomain(tld, subdomain) == 1:
        return 1
    return 0


#################################################################################################################################
#               Abnormal subdomain starting with wwww-, wwNN
#################################################################################################################################


def abnormal_subdomain(url: str):
    if re.search(r"(http[s]?://(w[w]?|\d))([w]?(\d|-))", url):
        return 1
    return 0


#################################################################################################################################
#               Number of redirection
#################################################################################################################################


def count_redirection(page: requests.Response):
    return len(page.history)


#################################################################################################################################
#               Number of redirection to different domains
#################################################################################################################################


def count_external_redirection(page: requests.Response, domain: str):
    count = 0
    if len(page.history) == 0:
        return 0
    else:
        for i, response in enumerate(page.history, 1):
            if domain.lower() not in response.url.lower():
                count += 1
            return count


#################################################################################################################################
#               Consecutive Character Repeat (Sahingoz2019)
#################################################################################################################################


def char_repeat(words_raw: list[str]):
    def __all_same(items: str):
        return all(x == items[0] for x in items)

    repeat = {"2": 0, "3": 0, "4": 0, "5": 0}
    part = [2, 3, 4, 5]

    for word in words_raw:
        for char_repeat_count in part:
            for i in range(len(word) - char_repeat_count + 1):
                sub_word = word[i : i + char_repeat_count]
                if __all_same(sub_word):
                    repeat[str(char_repeat_count)] = repeat[str(char_repeat_count)] + 1
    return sum(list(repeat.values()))


#################################################################################################################################
#               puny code in domain (Sahingoz2019)
#################################################################################################################################


def punycode(url: str):
    if url.startswith("http://xn--") or url.startswith("http://xn--"):
        return 1
    else:
        return 0


#################################################################################################################################
#               domain in brand list (Sahingoz2019)
#################################################################################################################################


def domain_in_brand(domain: str, urls: list[str]):
    if domain in urls:
        return 1
    else:
        return 0


def domain_in_brand1(domain: str, urls: list[str]):
    for d in urls:
        if len(Levenshtein.editops(domain.lower(), d.lower())) < 2:
            return 1
    return 0


#################################################################################################################################
#               brand name in path (Srinivasa-Rao2019)
#################################################################################################################################


def brand_in_path(domain: str, path: str, urls: list[str]):
    for b in urls:
        if "." + b + "." in path and b not in domain:
            return 1
    return 0


#################################################################################################################################
#               count www in url words (Sahingoz2019)
#################################################################################################################################


def check_www(words_raw: list[str]):
    count = 0
    for word in words_raw:
        if not word.find("www") == -1:
            count += 1
    return count


#################################################################################################################################
#               count com in url words (Sahingoz2019)
#################################################################################################################################


def check_com(words_raw: list[str]):
    count = 0
    for word in words_raw:
        if not word.find("com") == -1:
            count += 1
    return count


#################################################################################################################################
#               check port presence in domain
#################################################################################################################################


def port(url: str):
    if re.search(
        r"^[a-z][a-z0-9+\-.]*://([a-z0-9\-._~%!$&'()*+,;=]+@)?([a-z0-9\-._~%]+|\[[a-z0-9\-._~%!$&'()*+,;=:]+\]):([0-9]+)",
        url,
    ):
        return 1
    return 0


#################################################################################################################################
#               length of raw word list (Sahingoz2019)
#################################################################################################################################


def length_word_raw(words_raw):
    return len(words_raw)


#################################################################################################################################
#               count average word length in raw word list (Sahingoz2019)
#################################################################################################################################


def average_word_length(words_raw: list[str]):
    if len(words_raw) == 0:
        return 0
    return sum(len(word) for word in words_raw) / len(words_raw)


#################################################################################################################################
#               longest word length in raw word list (Sahingoz2019)
#################################################################################################################################


def longest_word_length(words_raw: list[str]):
    if len(words_raw) == 0:
        return 0
    return max(len(word) for word in words_raw)


#################################################################################################################################
#               shortest word length in raw word list (Sahingoz2019)
#################################################################################################################################


def shortest_word_length(words_raw: list[str]):
    if len(words_raw) == 0:
        return 0
    return min(len(word) for word in words_raw)


#################################################################################################################################
#               prefix suffix
#################################################################################################################################


def prefix_suffix(url: str):
    if re.findall(r"https?://[^\-]+-[^\-]+/", url):
        return 1
    else:
        return 0


#################################################################################################################################
#               count subdomain
#################################################################################################################################


def count_subdomain(url: str):
    if len(re.findall(r"\.", url)) == 1:
        return 1
    elif len(re.findall(r"\.", url)) == 2:
        return 2
    else:
        return 3


#################################################################################################################################
#               Statistical report
#################################################################################################################################

import socket


def statistical_report(url: str, domain: str):
    url_match = re.search(
        r"at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly",
        url,
    )
    try:
        ip_address = socket.gethostbyname(domain)
        ip_match = re.search(
            r"146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|"
            r"107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|"
            r"118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|"
            r"216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|"
            r"34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|"
            r"216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42",
            ip_address,
        )
        if url_match or ip_match:
            return 1
        else:
            return 0
    except:
        return 2


#################################################################################################################################
#               Suspicious TLD
#################################################################################################################################

suspicious_tlds = [
    "fit",
    "tk",
    "gp",
    "ga",
    "work",
    "ml",
    "date",
    "wang",
    "men",
    "icu",
    "online",
    "click",  # Spamhaus
    "country",
    "stream",
    "download",
    "xin",
    "racing",
    "jetzt",
    "ren",
    "mom",
    "party",
    "review",
    "trade",
    "accountants",
    "science",
    "work",
    "ninja",
    "xyz",
    "faith",
    "zip",
    "cricket",
    "win",
    "accountant",
    "realtor",
    "top",
    "christmas",
    "gdn",  # Shady Top-Level Domains
    "link",  # Blue Coat Systems
    "asia",
    "club",
    "la",
    "ae",
    "exposed",
    "pe",
    "go.id",
    "rs",
    "k12.pa.us",
    "or.kr",
    "ce.ke",
    "audio",
    "gob.pe",
    "gov.az",
    "website",
    "bj",
    "mx",
    "media",
    "sa.gov.au",  # statistics
]


def suspicious_tld(tld: str):
    if tld in suspicious_tlds:
        return 1
    return 0


#################################################################################################################################
#               Number of hyperlinks present in a website (Kumar Jain'18)
#################################################################################################################################


def nb_hyperlinks(
    Href: dict[str, Any],
    Link: dict[str, Any],
    Media: dict[str, Any],
    Form: dict[str, Any],
    CSS: dict[str, Any],
    Favicon: dict[str, Any],
):
    return (
        len(Href["internals"])
        + len(Href["externals"])
        + len(Link["internals"])
        + len(Link["externals"])
        + len(Media["internals"])
        + len(Media["externals"])
        + len(Form["internals"])
        + len(Form["externals"])
        + len(CSS["internals"])
        + len(CSS["externals"])
        + len(Favicon["internals"])
        + len(Favicon["externals"])
    )


#################################################################################################################################
#               Internal hyperlinks ratio (Kumar Jain'18)
#################################################################################################################################


def h_total(
    Href: dict[str, Any],
    Link: dict[str, Any],
    Media: dict[str, Any],
    Form: dict[str, Any],
    CSS: dict[str, Any],
    Favicon: dict[str, Any],
):
    return nb_hyperlinks(Href, Link, Media, Form, CSS, Favicon)


def h_internal(
    Href: dict[str, Any],
    Link: dict[str, Any],
    Media: dict[str, Any],
    Form: dict[str, Any],
    CSS: dict[str, Any],
    Favicon: dict[str, Any],
):
    return (
        len(Href["internals"])
        + len(Link["internals"])
        + len(Media["internals"])
        + len(Form["internals"])
        + len(CSS["internals"])
        + len(Favicon["internals"])
    )


def internal_hyperlinks(
    Href: dict[str, Any],
    Link: dict[str, Any],
    Media: dict[str, Any],
    Form: dict[str, Any],
    CSS: dict[str, Any],
    Favicon: dict[str, Any],
):
    total = h_total(Href, Link, Media, Form, CSS, Favicon)
    if total == 0:
        return 0
    else:
        return h_internal(Href, Link, Media, Form, CSS, Favicon) / total


#################################################################################################################################
#               External hyperlinks ratio (Kumar Jain'18)
#################################################################################################################################


def h_external(
    Href: dict[str, Any],
    Link: dict[str, Any],
    Media: dict[str, Any],
    Form: dict[str, Any],
    CSS: dict[str, Any],
    Favicon: dict[str, Any],
):
    return (
        len(Href["externals"])
        + len(Link["externals"])
        + len(Media["externals"])
        + len(Form["externals"])
        + len(CSS["externals"])
        + len(Favicon["externals"])
    )


def external_hyperlinks(
    Href: dict[str, Any],
    Link: dict[str, Any],
    Media: dict[str, Any],
    Form: dict[str, Any],
    CSS: dict[str, Any],
    Favicon: dict[str, Any],
):
    total = h_total(Href, Link, Media, Form, CSS, Favicon)
    if total == 0:
        return 0
    else:
        return h_external(Href, Link, Media, Form, CSS, Favicon) / total


#################################################################################################################################
#               Extrenal CSS (Kumar Jain'18)
#################################################################################################################################


def external_css(CSS: dict[str, Any]):
    return len(CSS["externals"])


#################################################################################################################################
#               Internal redirections (Kumar Jain'18)
#################################################################################################################################


def h_i_error(
    Href: dict[str, Any],
    Link: dict[str, Any],
    Media: dict[str, Any],
    Form: dict[str, Any],
    CSS: dict[str, Any],
    Favicon: dict[str, Any],
):
    if h_internal(Href, Link, Media, Form, CSS, Favicon) > 10:
        return 0
    count = 0
    for link in Href["internals"]:
        try:
            if requests.get("https://" + link, timeout=1).status_code >= 400:
                count += 1
        except:
            continue
    for link in Link["internals"]:
        try:
            if requests.get("https://" + link, timeout=1).status_code >= 400:
                count += 1
        except:
            continue
    for link in Media["internals"]:
        try:
            if requests.get("https://" + link, timeout=1).status_code >= 400:
                count += 1
        except:
            continue
    for link in Form["internals"]:
        try:
            if requests.get("https://" + link, timeout=1).status_code >= 400:
                count += 1
        except:
            continue
    for link in CSS["internals"]:
        try:
            if requests.get("https://" + link, timeout=1).status_code >= 400:
                count += 1
        except:
            continue
    for link in Favicon["internals"]:
        try:
            if requests.get("https://" + link, timeout=1).status_code >= 400:
                count += 1
        except:
            continue
    return count


# def h_i_redirect(Href, Link, Media, Form, CSS, Favicon):
#    count = 0
#    for link in Href['internals']:
#        try:
#            r = requests.get(link, timeout = 1)
#            if len(r.history) > 0:
#                count+=1
#        except:
#            continue
#    for link in Link['internals']:
#        try:
#            r = requests.get(link, timeout =1)
#            if len(r.history) > 0:
#                count+=1
#        except:
#            continue
#    for link in Media['internals']:
#        try:
#            r = requests.get(link, timeout =1)
#            if len(r.history) > 0:
#                count+=1
#        except:
#            continue
#    for link in Form['internals']:
#        try:
#            r = requests.get(link, timeout =1)
#            if len(r.history) > 0:
#                count+=1
#        except:
#            continue
#    for link in CSS['internals']:
#        try:
#            r = requests.get(link, timeout =1)
#            if len(r.history) > 0:
#                count+=1
#        except:
#            continue
#    for link in Favicon['internals']:
#        try:
#            r = requests.get(link, timeout =1)
#            if len(r.history) > 0:
#                count+=1
#        except:
#            continue
#    return count


def internal_redirection(
    Href: dict[str, Any],
    Link: dict[str, Any],
    Media: dict[str, Any],
    Form: dict[str, Any],
    CSS: dict[str, Any],
    Favicon: dict[str, Any],
    i_error: int,
):
    internals = h_internal(Href, Link, Media, Form, CSS, Favicon)
    if internals > 0:
        return (internals - i_error) / internals
    return 0


#################################################################################################################################
#               External redirections (Kumar Jain'18)
#################################################################################################################################


# def h_e_redirect(Href, Link, Media, Form, CSS, Favicon):
#    count = 0
#    for link in Href['externals']:
#        try:
#            r = requests.get(link, timeout =1)
#            if len(r.history) > 0:
#                count+=1
#        except:
#            continue
#    for link in Link['externals']:
#        try:
#            r = requests.get(link, timeout =1)
#            if len(r.history) > 0:
#                count+=1
#        except:
#            continue
#    for link in Media['externals']:
#        try:
#            r = requests.get(link, timeout =1)
#            if len(r.history) > 0:
#                count+=1
#        except:
#            continue
#    for link in Form['externals']:
#        try:
#            r = requests.get(link, timeout =1)
#            if len(r.history) > 0:
#                count+=1
#        except:
#            continue
#    for link in CSS['externals']:
#        try:
#            r = requests.get(link, timeout =1)
#            if len(r.history) > 0:
#                count+=1
#        except:
#            continue
#    for link in Favicon['externals']:
#        try:
#            r = requests.get(link, timeout =1)
#            if len(r.history) > 0:
#                count+=1
#        except:
#            continue
#    return count


def external_redirection(
    Href: dict[str, Any],
    Link: dict[str, Any],
    Media: dict[str, Any],
    Form: dict[str, Any],
    CSS: dict[str, Any],
    Favicon: dict[str, Any],
    e_error: int,
):
    externals = h_external(Href, Link, Media, Form, CSS, Favicon)
    if externals > 0:
        return (externals - e_error) / externals
    return 0


#################################################################################################################################
#               Generates external errors (Kumar Jain'18)
#################################################################################################################################


def h_e_error(
    Href: dict[str, Any],
    Link: dict[str, Any],
    Media: dict[str, Any],
    Form: dict[str, Any],
    CSS: dict[str, Any],
    Favicon: dict[str, Any],
):
    if h_external(Href, Link, Media, Form, CSS, Favicon) > 10:
        return 0
    count = 0
    for link in Href["externals"]:
        try:
            if requests.get(link, timeout=1).status_code >= 400:
                count += 1
        except:
            continue
    for link in Link["externals"]:
        try:
            if requests.get(link, timeout=1).status_code >= 400:
                count += 1
        except:
            continue
    for link in Media["externals"]:
        try:
            if requests.get(link, timeout=1).status_code >= 400:
                count += 1
        except:
            continue
    for link in Form["externals"]:
        try:
            if requests.get(link, timeout=1).status_code >= 400:
                count += 1
        except:
            continue
    for link in CSS["externals"]:
        try:
            if requests.get(link, timeout=1).status_code >= 400:
                count += 1
        except:
            continue
    for link in Favicon["externals"]:
        try:
            if requests.get(link, timeout=1).status_code >= 400:
                count += 1
        except:
            continue
    return count


def external_errors(
    Href: dict[str, Any],
    Link: dict[str, Any],
    Media: dict[str, Any],
    Form: dict[str, Any],
    CSS: dict[str, Any],
    Favicon: dict[str, Any],
    e_error: int,
):
    externals = h_external(Href, Link, Media, Form, CSS, Favicon)
    if externals > 0:
        return e_error / externals
    return 0


#################################################################################################################################
#               Having login form link (Kumar Jain'18)
#################################################################################################################################


def login_form(Form: dict[str, Any]):
    p = re.compile(r"([a-zA-Z0-9\_])+.php")
    if len(Form["externals"]) > 0 or len(Form["null"]) > 0:
        return 1
    for form in Form["internals"] + Form["externals"]:
        if p.match(form) is not None:
            return 1
    return 0


#################################################################################################################################
#               Having external favicon (Kumar Jain'18)
#################################################################################################################################


def external_favicon(Favicon: dict[str, Any]):
    if len(Favicon["externals"]) > 0:
        return 1
    return 0


#################################################################################################################################
#               Submitting to email
#################################################################################################################################


def submitting_to_email(Form: dict[str, Any]):
    for form in Form["internals"] + Form["externals"]:
        if "mailto:" in form or "mail()" in form:
            return 1
        else:
            return 0
    return 0


#################################################################################################################################
#               Percentile of internal media <= 61 : Request URL in Zaini'2019
#################################################################################################################################


def internal_media(Media: dict[str, Any]):
    total = len(Media["internals"]) + len(Media["externals"])
    internals = len(Media["internals"])
    try:
        percentile = internals / float(total) * 100
    except:
        return 0

    return percentile


#################################################################################################################################
#               Percentile of external media : Request URL in Zaini'2019
#################################################################################################################################


def external_media(Media: dict[str, Any]):
    total = len(Media["internals"]) + len(Media["externals"])
    externals = len(Media["externals"])
    try:
        percentile = externals / float(total) * 100
    except:
        return 0

    return percentile


#################################################################################################################################
#               Check for empty title
#################################################################################################################################


def empty_title(Title: str | None):
    if Title:
        return 0
    return 1


#################################################################################################################################
#               Percentile of safe anchor : URL_of_Anchor in Zaini'2019 (Kumar Jain'18)
#################################################################################################################################


def safe_anchor(Anchor: dict[str, Any]):
    total = len(Anchor["safe"]) + len(Anchor["unsafe"])
    unsafe = len(Anchor["unsafe"])
    try:
        percentile = unsafe / float(total) * 100
    except:
        return 0
    return percentile


#################################################################################################################################
#               Percentile of internal links : links_in_tags in Zaini'2019 but without <Meta> tag
#################################################################################################################################


def links_in_tags(Link: dict[str, Any]):
    total = len(Link["internals"]) + len(Link["externals"])
    internals = len(Link["internals"])
    try:
        percentile = internals / float(total) * 100
    except:
        return 0
    return percentile


#################################################################################################################################
#              IFrame Redirection
#################################################################################################################################


def iframe(IFrame: dict[str, Any]):
    if len(IFrame["invisible"]) > 0:
        return 1
    return 0


#################################################################################################################################
#              Pop up window
#################################################################################################################################


def popup_window(content: str):
    if "prompt(" in str(content).lower():
        return 1
    else:
        return 0


#################################################################################################################################
#              Domain in page title (Shirazi'18)
#################################################################################################################################


def domain_in_title(domain: str, title: str):
    try:
        if domain.lower() in title.lower():
            return 0
        return 1
    except:
        return 0


#################################################################################################################################
#              Domain after copyright logo (Shirazi'18)
#################################################################################################################################


def domain_with_copyright(domain: str, content: str):
    try:
        m = re.search(
            r"(\N{COPYRIGHT SIGN}|\N{TRADE MARK SIGN}|\N{REGISTERED SIGN})", content
        )
        if not m:
            return 0
        _copyright = content[m.span()[0] - 50 : m.span()[0] + 50]
        if domain.lower() in _copyright.lower():
            return 0
        else:
            return 1
    except:
        return 0


#################################################################################################################################
#               Domain registration age
#################################################################################################################################


def domain_registration_length(host: whois.WhoisEntry | None):
    try:
        if not host:
            return 0
        expiration_date = host.expiration_date
        today = time.strftime("%Y-%m-%d")
        today = datetime.strptime(today, "%Y-%m-%d")
        # Some domains do not have expiration dates. The application should not raise an error if this is the case.
        if expiration_date:
            if type(expiration_date) == list:
                expiration_date = min(expiration_date)
            return abs((expiration_date - today).days)
        else:
            return 0
    except:
        return -1


#################################################################################################################################
#               Domain recognized by WHOIS
#################################################################################################################################


def whois_registered_domain(host: whois.WhoisEntry | None, domain: str):
    try:
        if not host:
            return 0
        hostname = host.domain_name
        if type(hostname) == list:
            for host_ in hostname:
                if re.search(host_.lower(), domain):
                    return 0
            return 1
        else:
            if not hostname or re.search(hostname.lower(), domain):
                return 0
            else:
                return 1
    except:
        return 1


#################################################################################################################################
#               Domain age of a url
#################################################################################################################################


def domain_age(host: whois.WhoisEntry | None):
    try:
        if not host:
            return 0
        creation_date = host.creation_date
        expiration_date = host.expiration_date
        # Convert `creation_date` to a `datetime` if it's a list
        if isinstance(creation_date, list):
            creation_date = creation_date[0] if creation_date else None
        if isinstance(creation_date, str):
            try:
                creation_date = datetime.strptime(creation_date, "%Y-%m-%d")
            except ValueError:
                return 1

        # Convert `expiration_date` to a `datetime` if it's a list
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0] if expiration_date else None
        if isinstance(expiration_date, str):
            try:
                expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
            except ValueError:
                return 1

        # Check for any remaining None values after parsing
        if creation_date is None or expiration_date is None:
            return 1

        # Calculate the domain age in days
        age_of_domain = abs((expiration_date - creation_date).days)

        # Return 1 if the domain age is less than 6 months, otherwise return 0
        return 1 if (age_of_domain / 30) < 6 else 0

    except Exception as e:
        # Log or handle the exception as needed
        print(f"An error occurred: {e}")
        return -1


#################################################################################################################################
#               Google index
#################################################################################################################################


def google_index(url: str):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0"
        }

        google = "https://www.google.com/search?q=site:" + url + "&hl=en"
        response = requests.get(google, headers=headers, timeout=3)
        soup = BeautifulSoup(response.content, "html.parser")
        not_indexed = re.compile("did not match any documents")

        if soup(text=not_indexed):
            return 0
        else:
            return 1
    except:
        return 0


#################################################################################################################################
#               DNSRecord  expiration length
#################################################################################################################################


def dns_record(domain: str):
    try:
        nameservers = dns.resolver.resolve(domain, "NS")
        if len(nameservers) > 0:
            return 0
        else:
            return 1
    except:
        return 1


#################################################################################################################################
#               Page Rank from OPR
#################################################################################################################################


def page_rank(result: dict[str, Any] | None):
    if not result:
        print("warn: got empty result json")
        return 0
    try:
        result = result["response"][0]["page_rank_integer"]
        if result:
            return result
        else:
            return 0
    except:
        return -1


def rank(result: dict[str, Any] | None):
    if not result:
        print("warn: got empty result json")
        return 0
    try:
        result = result["response"][0]["rank"]
        if result:
            return result
        else:
            return 0
    except:
        return -1


def domainEnd(host: whois.WhoisEntry | None):
    try:
        if not host:
            return 0
        expiration_date = host.expiration_date
        if isinstance(expiration_date, str):
            try:
                expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
            except:
                return 1
        if expiration_date is None:
            return 1
        elif type(expiration_date) is list:
            return 1
        else:
            today = datetime.now()
            end = abs((expiration_date - today).days)
            if (end / 30) < 6:
                end = 0
            else:
                end = 1
        return end
    except:
        return -1


def is_URL_accessible(url: str):
    page = None
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
            "Referer": "https://targetwebsite.com/page1",
        }
        page = requests.get(url, headers=headers, timeout=10)
    except:
        pass
        # parsed = urlparse(url)
        # url = parsed.scheme+'://'+parsed.netloc
        # if not parsed.netloc.startswith('www'):
        #    url = parsed.scheme+'://www.'+parsed.netloc
        #    try:
        #        page = requests.get(url, timeout=10)
        #    except:
        #        page = None
        #        pass
    if page and page.status_code == 200 and page.content not in ["b''", "b' '"]:
        return url, page
    else:
        return None


#################################################################################################################################
#              Data Extraction Process
#################################################################################################################################


def extract_data_from_URL(
    hostname: str,
    content: bytes,
    domain: str,
    Href: dict[str, Any],
    Link: dict[str, Any],
    Anchor: dict[str, Any],
    Media: dict[str, Any],
    Form: dict[str, Any],
    CSS: dict[str, Any],
    Favicon: dict[str, Any],
    IFrame: dict[str, Any],
    Title: str,
    Text: str,
):
    Null_format = [
        "",
        "#",
        "#nothing",
        "#doesnotexist",
        "#null",
        "#void",
        "#whatever",
        "#content",
        "javascript::void(0)",
        "javascript::void(0);",
        "javascript::;",
        "javascript",
    ]

    soup = BeautifulSoup(content, "html.parser", from_encoding="iso-8859-1")

    # collect all external and internal hrefs from url
    for href in soup.find_all("a", href=True):
        dots = [x.start(0) for x in re.finditer(r"\.", href["href"])]
        if (
            hostname in href["href"]
            or domain in href["href"]
            or len(dots) == 1
            or not href["href"].startswith("http")
        ):
            if (
                "#" in href["href"]
                or "javascript" in href["href"].lower()
                or "mailto" in href["href"].lower()
            ):
                Anchor["unsafe"].append(href["href"])
            if not href["href"].startswith("http"):
                if not href["href"].startswith("/"):
                    Href["internals"].append(hostname + "/" + href["href"])
                elif href["href"] in Null_format:
                    Href["null"].append(href["href"])
                else:
                    Href["internals"].append(hostname + href["href"])
        else:
            Href["externals"].append(href["href"])
            Anchor["safe"].append(href["href"])

    # collect all media src tags
    for img in soup.find_all("img", src=True):
        dots = [x.start(0) for x in re.finditer(r"\.", img["src"])]
        if (
            hostname in img["src"]
            or domain in img["src"]
            or len(dots) == 1
            or not img["src"].startswith("http")
        ):
            if not img["src"].startswith("http"):
                if not img["src"].startswith("/"):
                    Media["internals"].append(hostname + "/" + img["src"])
                elif img["src"] in Null_format:
                    Media["null"].append(img["src"])
                else:
                    Media["internals"].append(hostname + img["src"])
        else:
            Media["externals"].append(img["src"])

    for audio in soup.find_all("audio", src=True):
        dots = [x.start(0) for x in re.finditer(r"\.", audio["src"])]
        if (
            hostname in audio["src"]
            or domain in audio["src"]
            or len(dots) == 1
            or not audio["src"].startswith("http")
        ):
            if not audio["src"].startswith("http"):
                if not audio["src"].startswith("/"):
                    Media["internals"].append(hostname + "/" + audio["src"])
                elif audio["src"] in Null_format:
                    Media["null"].append(audio["src"])
                else:
                    Media["internals"].append(hostname + audio["src"])
        else:
            Media["externals"].append(audio["src"])

    for embed in soup.find_all("embed", src=True):
        dots = [x.start(0) for x in re.finditer(r"\.", embed["src"])]
        if (
            hostname in embed["src"]
            or domain in embed["src"]
            or len(dots) == 1
            or not embed["src"].startswith("http")
        ):
            if not embed["src"].startswith("http"):
                if not embed["src"].startswith("/"):
                    Media["internals"].append(hostname + "/" + embed["src"])
                elif embed["src"] in Null_format:
                    Media["null"].append(embed["src"])
                else:
                    Media["internals"].append(hostname + embed["src"])
        else:
            Media["externals"].append(embed["src"])

    for i_frame in soup.find_all("iframe", src=True):
        dots = [x.start(0) for x in re.finditer(r"\.", i_frame["src"])]
        if (
            hostname in i_frame["src"]
            or domain in i_frame["src"]
            or len(dots) == 1
            or not i_frame["src"].startswith("http")
        ):
            if not i_frame["src"].startswith("http"):
                if not i_frame["src"].startswith("/"):
                    Media["internals"].append(hostname + "/" + i_frame["src"])
                elif i_frame["src"] in Null_format:
                    Media["null"].append(i_frame["src"])
                else:
                    Media["internals"].append(hostname + i_frame["src"])
        else:
            Media["externals"].append(i_frame["src"])

    # collect all link tags
    for link in soup.findAll("link", href=True):
        dots = [x.start(0) for x in re.finditer(r"\.", link["href"])]
        if (
            hostname in link["href"]
            or domain in link["href"]
            or len(dots) == 1
            or not link["href"].startswith("http")
        ):
            if not link["href"].startswith("http"):
                if not link["href"].startswith("/"):
                    Link["internals"].append(hostname + "/" + link["href"])
                elif link["href"] in Null_format:
                    Link["null"].append(link["href"])
                else:
                    Link["internals"].append(hostname + link["href"])
        else:
            Link["externals"].append(link["href"])

    for script in soup.find_all("script", src=True):
        dots = [x.start(0) for x in re.finditer(r"\.", script["src"])]
        if (
            hostname in script["src"]
            or domain in script["src"]
            or len(dots) == 1
            or not script["src"].startswith("http")
        ):
            if not script["src"].startswith("http"):
                if not script["src"].startswith("/"):
                    Link["internals"].append(hostname + "/" + script["src"])
                elif script["src"] in Null_format:
                    Link["null"].append(script["src"])
                else:
                    Link["internals"].append(hostname + script["src"])
        else:
            try:
                Link["externals"].append(script["href"])
            except:
                pass

    # collect all css
    for link in soup.find_all("link", rel="stylesheet"):
        dots = [x.start(0) for x in re.finditer(r"\.", link["href"])]
        if (
            hostname in link["href"]
            or domain in link["href"]
            or len(dots) == 1
            or not link["href"].startswith("http")
        ):
            if not link["href"].startswith("http"):
                if not link["href"].startswith("/"):
                    CSS["internals"].append(hostname + "/" + link["href"])
                elif link["href"] in Null_format:
                    CSS["null"].append(link["href"])
                else:
                    CSS["internals"].append(hostname + link["href"])
        else:
            CSS["externals"].append(link["href"])

    for style in soup.find_all("style", type="text/css"):
        try:
            start = str(style[0]).index("@import url(")
            end = str(style[0]).index(")")
            css = str(style[0])[start + 12 : end]
            dots = [x.start(0) for x in re.finditer(r"\.", css)]
            if (
                hostname in css
                or domain in css
                or len(dots) == 1
                or not css.startswith("http")
            ):
                if not css.startswith("http"):
                    if not css.startswith("/"):
                        CSS["internals"].append(hostname + "/" + css)
                    elif css in Null_format:
                        CSS["null"].append(css)
                    else:
                        CSS["internals"].append(hostname + css)
            else:
                CSS["externals"].append(css)
        except:
            continue

    # collect all form actions
    for form in soup.findAll("form", action=True):
        dots = [x.start(0) for x in re.finditer(r"\.", form["action"])]
        if (
            hostname in form["action"]
            or domain in form["action"]
            or len(dots) == 1
            or not form["action"].startswith("http")
        ):
            if not form["action"].startswith("http"):
                if not form["action"].startswith("/"):
                    Form["internals"].append(hostname + "/" + form["action"])
                elif form["action"] in Null_format or form["action"] == "about:blank":
                    Form["null"].append(form["action"])
                else:
                    Form["internals"].append(hostname + form["action"])
        else:
            Form["externals"].append(form["action"])

    # collect all link tags
    for head in soup.find_all("head"):
        for head.link in soup.find_all("link", href=True):
            dots = [x.start(0) for x in re.finditer(r"\.", head.link["href"])]
            if (
                hostname in head.link["href"]
                or len(dots) == 1
                or domain in head.link["href"]
                or not head.link["href"].startswith("http")
            ):
                if not head.link["href"].startswith("http"):
                    if not head.link["href"].startswith("/"):
                        Favicon["internals"].append(hostname + "/" + head.link["href"])
                    elif head.link["href"] in Null_format:
                        Favicon["null"].append(head.link["href"])
                    else:
                        Favicon["internals"].append(hostname + head.link["href"])
            else:
                Favicon["externals"].append(head.link["href"])

        for head.link in soup.findAll("link", {"href": True, "rel": True}):
            isicon = False
            if isinstance(head.link["rel"], list):
                for e_rel in head.link["rel"]:
                    if e_rel.endswith("icon"):
                        isicon = True
            else:
                if head.link["rel"].endswith("icon"):
                    isicon = True

            if isicon:
                dots = [x.start(0) for x in re.finditer(r"\.", head.link["href"])]
                if (
                    hostname in head.link["href"]
                    or len(dots) == 1
                    or domain in head.link["href"]
                    or not head.link["href"].startswith("http")
                ):
                    if not head.link["href"].startswith("http"):
                        if not head.link["href"].startswith("/"):
                            Favicon["internals"].append(
                                hostname + "/" + head.link["href"]
                            )
                        elif head.link["href"] in Null_format:
                            Favicon["null"].append(head.link["href"])
                        else:
                            Favicon["internals"].append(hostname + head.link["href"])
                else:
                    Favicon["externals"].append(head.link["href"])

    # collect i_frame
    for i_frame in soup.find_all("iframe", width=True, height=True, frameborder=True):
        if (
            i_frame["width"] == "0"
            and i_frame["height"] == "0"
            and i_frame["frameborder"] == "0"
        ):
            IFrame["invisible"].append(i_frame)
        else:
            IFrame["visible"].append(i_frame)
    for i_frame in soup.find_all("iframe", width=True, height=True, border=True):
        if (
            i_frame["width"] == "0"
            and i_frame["height"] == "0"
            and i_frame["border"] == "0"
        ):
            IFrame["invisible"].append(i_frame)
        else:
            IFrame["visible"].append(i_frame)
    for i_frame in soup.find_all("iframe", width=True, height=True, style=True):
        if (
            i_frame["width"] == "0"
            and i_frame["height"] == "0"
            and i_frame["style"] == "border:none;"
        ):
            IFrame["invisible"].append(i_frame)
        else:
            IFrame["visible"].append(i_frame)

    # get page title
    try:
        if soup.title and soup.title.string:
            Title = soup.title.string
    except:
        pass

    # get content text
    Text = soup.get_text()

    return Href, Link, Anchor, Media, Form, CSS, Favicon, IFrame, Title, Text


def extract_features(urls: list[str], url: str):
    def get_domain(url: str):
        o = urllib.parse.urlsplit(url)
        # TODO: o.netloc (str) or o.hostname (str | None)?
        return o.netloc, tldextract.extract(url).domain, o.path

    def words_raw_extraction(domain: str, subdomain: str, path: str):
        w_domain = re.split(r"\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", domain.lower())
        w_subdomain = re.split(r"\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", subdomain.lower())
        w_path = re.split(r"\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", path.lower())
        raw_words = w_domain + w_path + w_subdomain
        w_host = w_domain + w_subdomain
        raw_words = list(filter(None, raw_words))
        return raw_words, list(filter(None, w_host)), list(filter(None, w_path))

    Href = {"internals": [], "externals": [], "null": []}
    Link = {"internals": [], "externals": [], "null": []}
    Anchor = {"safe": [], "unsafe": [], "null": []}
    Media = {"internals": [], "externals": [], "null": []}
    Form = {"internals": [], "externals": [], "null": []}
    CSS = {"internals": [], "externals": [], "null": []}
    Favicon = {"internals": [], "externals": [], "null": []}
    IFrame = {"visible": [], "invisible": [], "null": []}
    Title = ""
    Text = ""
    accessible_url = is_URL_accessible(url)
    if accessible_url:
        iurl, page = accessible_url
        content = page.content
        hostname, domain, path = get_domain(url)
        extracted_domain = tldextract.extract(url)
        domain = extracted_domain.domain + "." + extracted_domain.suffix
        subdomain = extracted_domain.subdomain
        tmp = url[url.find(extracted_domain.suffix) : len(url)]
        pth = tmp.partition("/")
        path = pth[1] + pth[2]
        words_raw, words_raw_host, words_raw_path = words_raw_extraction(
            extracted_domain.domain, subdomain, pth[2]
        )
        tld = extracted_domain.suffix
        parsed = urlparse(url)
        scheme = parsed.scheme

        try:
            host = whois.whois(domain)
        except:
            host = None

        try:
            key = "c4skc4o8kswocso0og84w4gk44so048k8og44000"
            rank_domain = (
                "https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D=" + domain
            )
            request = requests.get(rank_domain, headers={"API-OPR": key}, timeout=5)
            result_json = request.json()
        except:
            result_json = None

        (
            Href,
            Link,
            Anchor,
            Media,
            Form,
            CSS,
            Favicon,
            IFrame,
            Title,
            Text,
        ) = extract_data_from_URL(
            hostname,
            content,
            domain,
            Href,
            Link,
            Anchor,
            Media,
            Form,
            CSS,
            Favicon,
            IFrame,
            Title,
            Text,
        )
        e_error = h_e_error(Href, Link, Media, Form, CSS, Favicon)
        i_error = h_i_error(Href, Link, Media, Form, CSS, Favicon)
        row = {
            "url": url,
            # url-based features
            "length_url": url_length(url),
            "length_hostname": url_length(hostname),
            "ip": having_ip_address(url),
            "nb_dots": count_dots(url),
            "nb_hyphens": count_hyphens(url),
            "nb_at": count_at(url),
            "nb_qm": count_exclamation(url),
            "nb_and": count_and(url),
            "nb_or": count_or(url),
            "nb_eq": count_equal(url),
            "nb_underscore": count_underscore(url),
            "nb_tilde": count_tilde(url),
            "nb_percent": count_percentage(url),
            "nb_slash": count_slash(url),
            "nb_star": count_star(url),
            "nb_colon": count_colon(url),
            "nb_comma": count_comma(url),
            "nb_semicolon": count_semicolon(url),
            "nb_dollar": count_dollar(url),
            "nb_space": count_space(url),
            "nb_www": check_www(words_raw),
            "nb_com": check_com(words_raw),
            "nb_dslash": count_double_slash(url),
            "http_in_path": count_http_token(path),
            "https_token": https_token(scheme),
            "ratio_digits_url": count_digits(url),
            "ratio_digits_host": ratio_digits(hostname),
            "punycode": punycode(url),
            "port": port(url),
            "tld_in_path": tld_in_path(tld, path),
            "tld_in_subdomain": tld_in_subdomain(tld, subdomain),
            "abnormal_subdomain": abnormal_subdomain(url),
            "nb_subdomains": count_subdomain(url),
            "prefix_suffix": prefix_suffix(url),
            # TODO: fix random_domain
            # "random_domain": random_domain(url),
            "shortening_service": shortening_service(url),
            "path_extension": path_extension(path),
            "nb_redirection": count_redirection(page),
            "nb_external_redirection": count_external_redirection(page, domain),
            "length_words_raw": length_word_raw(words_raw),
            "char_repeat": char_repeat(words_raw),
            "shortest_words_raw": shortest_word_length(words_raw),
            "shortest_word_host": shortest_word_length(words_raw_host),
            "shortest_word_path": shortest_word_length(words_raw_path),
            "longest_words_raw": longest_word_length(words_raw),
            "longest_word_host": longest_word_length(words_raw_host),
            "longest_word_path": longest_word_length(words_raw_path),
            "avg_words_raw": average_word_length(words_raw),
            "avg_word_host": average_word_length(words_raw_host),
            "avg_word_path": average_word_length(words_raw_path),
            "phish_hints": phish_hints(url),
            "domain_in_brand": domain_in_brand(extracted_domain.domain, urls),
            "brand_in_subdomain": brand_in_path(
                extracted_domain.domain, subdomain, urls
            ),
            "brand_in_path": brand_in_path(extracted_domain.domain, path, urls),
            "suspecious_tld": suspicious_tld(tld),
            "statistical_report": statistical_report(url, domain),
            # # # content-based features
            "nb_hyperlinks": nb_hyperlinks(Href, Link, Media, Form, CSS, Favicon),
            "ratio_intHyperlinks": internal_hyperlinks(
                Href, Link, Media, Form, CSS, Favicon
            ),
            "ratio_extHyperlinks": external_hyperlinks(
                Href, Link, Media, Form, CSS, Favicon
            ),
            # TODO: fix null hyperlinks
            # "ratio_nullHyperlinks": null_hyperlinks(
            #     Href, Link, Media, Form, CSS, Favicon
            # ),
            "nb_extCSS": external_css(CSS),
            "ratio_intRedirection": internal_redirection(
                Href, Link, Media, Form, CSS, Favicon, i_error
            ),
            "ratio_extRedirection": external_redirection(
                Href, Link, Media, Form, CSS, Favicon, e_error
            ),
            # TODO: fix internal errors
            # "ratio_intErrors": internal_errors(
            #     Href, Link, Media, Form, CSS, Favicon, i_error
            # ),
            "ratio_extErrors": external_errors(
                Href, Link, Media, Form, CSS, Favicon, e_error
            ),
            "login_form": login_form(Form),
            "external_favicon": external_favicon(Favicon),
            "links_in_tags": links_in_tags(Link),
            "submit_email": submitting_to_email(Form),
            "ratio_intMedia": internal_media(Media),
            "ratio_extMedia": external_media(Media),
            #  # additional content-based features
            "iframe": iframe(IFrame),
            "popup_window": popup_window(Text),
            "safe_anchor": safe_anchor(Anchor),
            "empty_title": empty_title(Title),
            "domain_in_title": domain_in_title(extracted_domain.domain, Title),
            "domain_with_copyright": domain_with_copyright(
                extracted_domain.domain, Text
            ),
            # # # # third-party-based features
            "whois_registered_domain": whois_registered_domain(host, domain),
            "domain_registration_length": domain_registration_length(host),
            "domain_age": domain_age(host),
            "dns_record": dns_record(domain),
            "google_index": google_index(url),
            "page_rank": page_rank(result_json),
            "rank": rank(result_json),
            "domainEnd": domainEnd(host),
        }
        return tuple(row.values())
    else:
        return (url,)


def addingCSV():
    with open("active_urls.txt", "r", encoding="utf-8") as f:
        urls = [line.rstrip() for line in f.readlines()]

    # Create a DataFrame with the URLs
    df = pd.DataFrame({"url": urls})

    # Apply the feature extraction to each URL and store results in a list of dictionaries
    mapped_data = [extract_features(urls, url) for url in urls]

    # Create a DataFrame from the mapped data
    df_result = pd.DataFrame(
        mapped_data,
        columns=[
            "url",
            "length_url",
            "length_hostname",
            "ip",
            "nb_dots",
            "nb_hyphens",
            "nb_at",
            "nb_qm",
            "nb_and",
            "nb_or",
            "nb_eq",
            "nb_underscore",
            "nb_tilde",
            "nb_percent",
            "nb_slash",
            "nb_star",
            "nb_colon",
            "nb_comma",
            "nb_semicolon",
            "nb_dollar",
            "nb_space",
            "nb_www",
            "nb_com",
            "nb_dslash",
            "http_in_path",
            "https_token",
            "ratio_digits_url",
            "ratio_digits_host",
            "punycode",
            "port",
            "tld_in_path",
            "tld_in_subdomain",
            "abnormal_subdomain",
            "nb_subdomains",
            "prefix_suffix",
            # "random_domain",
            "shortening_service",
            "path_extension",
            "nb_redirection",
            "nb_external_redirection",
            "length_words_raw",
            "char_repeat",
            "shortest_words_raw",
            "shortest_word_host",
            "shortest_word_path",
            "longest_words_raw",
            "longest_word_host",
            "longest_word_path",
            "avg_words_raw",
            "avg_word_host",
            "avg_word_path",
            "phish_hints",
            "domain_in_brand",
            "brand_in_subdomain",
            "brand_in_path",
            "suspecious_tld",
            "statistical_report",
            "nb_hyperlinks",
            "ratio_intHyperlinks",
            "ratio_extHyperlinks",
            # "ratio_nullHyperlinks",
            "nb_extCSS",
            "ratio_intRedirection",
            "ratio_extRedirection",
            # "ratio_intErrors",
            "ratio_extErrors",
            "login_form",
            "external_favicon",
            "links_in_tags",
            "submit_email",
            "ratio_intMedia",
            "ratio_extMedia",
            "iframe",
            "popup_window",
            "safe_anchor",
            "empty_title",
            "domain_in_title",
            "domain_with_copyright",
            "whois_registered_domain",
            "domain_registration_length",
            "domain_age",
            "dns_record",
            "google_index",
            "page_rank",
            "rank",
            "domainEnd",
        ],
    )

    df_result["status"] = "phishing"
    # Display the resulting DataFrame
    print(df_result)
    # df_result.to_csv("output1.csv", index=False, encoding="utf-8")

    # Tải tệp CSV hiện có nếu nó tồn tại
    try:
        df_existing = pd.read_csv("output.csv")
    except FileNotFoundError:
        df_existing = (
            pd.DataFrame()
        )  # Nếu tệp không tồn tại, bắt đầu với một DataFrame rỗng

    # Nối DataFrame mới với DataFrame hiện có
    df_combined = pd.concat([df_existing, df_result], ignore_index=True)

    # Xóa các bản sao nếu cần thiết
    df_combined.drop_duplicates(subset=["url"], keep="last", inplace=True)

    # Lưu DataFrame đã cập nhật vào tệp CSV
    df_combined.to_csv("output.csv", index=False, encoding="utf-8")

    # Hiển thị DataFrame đã cập nhật
    print(df_combined)


def main():
    addingCSV()


if __name__ == "__main__":
    main()
