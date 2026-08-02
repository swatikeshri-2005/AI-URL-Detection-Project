import re
import ipaddress
from urllib.parse import urlparse


SUSPICIOUS_WORDS = [
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "secure",
    "security",
    "update",
    "confirm",
    "confirmation",
    "password",
    "bank",
    "paypal",
    "credential",
    "authenticate",
    "auth",
    "wallet",
    "payment",
    "billing",
    "invoice",
    "free",
    "bonus",
    "winner",
    "prize",
    "gift",
    "reward",
    "crypto",
    "bitcoin",
    "recover",
    "suspend",
    "unlock"
]


SUSPICIOUS_TLDS = [
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".top",
    ".xyz",
    ".click",
    ".download",
    ".zip",
    ".review",
    ".country",
    ".stream",
    ".win"
]


def safe_urlparse(url):
    """
    Safely parse a URL.

    Some URLs in large datasets can be malformed.
    This function prevents parsing errors from crashing
    the complete training process.
    """

    try:
        return urlparse(url)

    except ValueError:
        return None


def has_ip_address(url):
    """
    Check whether hostname is an IPv4/IPv6 address.
    """

    parsed = safe_urlparse(url)

    if parsed is None:
        return 0

    try:

        hostname = parsed.hostname

        if hostname:

            ipaddress.ip_address(
                hostname
            )

            return 1

    except (
        ValueError,
        TypeError
    ):
        pass

    return 0


def count_digits(text):
    return sum(
        char.isdigit()
        for char in text
    )


def count_letters(text):
    return sum(
        char.isalpha()
        for char in text
    )


def extract_features(url):

    # ------------------------------------------------------
    # Make sure URL is a string
    # ------------------------------------------------------

    if not isinstance(url, str):

        url = str(url)

    url = url.strip()

    # ------------------------------------------------------
    # Add protocol if missing
    # ------------------------------------------------------

    parsed_url = url

    if not re.match(
        r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
        url
    ):

        parsed_url = (
            "http://" + url
        )

    # ------------------------------------------------------
    # Safely parse URL
    # ------------------------------------------------------

    parsed = safe_urlparse(
        parsed_url
    )

    # ------------------------------------------------------
    # If URL is malformed
    # ------------------------------------------------------

    if parsed is None:

        hostname = ""
        path = ""
        query = ""

    else:

        try:
            hostname = parsed.hostname or ""
        except ValueError:
            hostname = ""

        path = parsed.path or ""
        query = parsed.query or ""

    lower_url = url.lower()

    # ------------------------------------------------------
    # Feature dictionary
    # ------------------------------------------------------

    features = {}

    # ======================================================
    # BASIC URL FEATURES
    # ======================================================

    features["url_length"] = len(url)

    features["hostname_length"] = len(
        hostname
    )

    features["path_length"] = len(
        path
    )

    features["query_length"] = len(
        query
    )

    features["num_dots"] = url.count(
        "."
    )

    features["num_slashes"] = url.count(
        "/"
    )

    features["num_backslashes"] = url.count(
        "\\"
    )

    features["num_dashes"] = url.count(
        "-"
    )

    features["num_underscores"] = url.count(
        "_"
    )

    features["num_digits"] = count_digits(
        url
    )

    features["num_letters"] = count_letters(
        url
    )

    features["num_special_chars"] = len(
        re.findall(
            r"[^a-zA-Z0-9]",
            url
        )
    )

    # ======================================================
    # PROTOCOL
    # ======================================================

    features["has_https"] = int(
        lower_url.startswith(
            "https://"
        )
    )

    features["has_http"] = int(
        lower_url.startswith(
            "http://"
        )
    )

    # ======================================================
    # SUSPICIOUS SYMBOLS
    # ======================================================

    features["has_at"] = int(
        "@" in url
    )

    features["has_hash"] = int(
        "#" in url
    )

    features["has_question_mark"] = int(
        "?" in url
    )

    features["has_equals"] = int(
        "=" in url
    )

    features["has_percent"] = int(
        "%" in url
    )

    features["has_ampersand"] = int(
        "&" in url
    )

    # Remove protocol before checking
    # for double slash

    without_protocol = re.sub(
        r"^[a-zA-Z]+://",
        "",
        url
    )

    features["has_double_slash"] = int(
        "//" in without_protocol
    )

    # ======================================================
    # IP ADDRESS
    # ======================================================

    features["has_ip"] = has_ip_address(
        parsed_url
    )

    # ======================================================
    # SUBDOMAINS
    # ======================================================

    if hostname:

        parts = hostname.split(".")

        features["num_subdomains"] = max(
            len(parts) - 2,
            0
        )

    else:

        features["num_subdomains"] = 0

    # ======================================================
    # SUSPICIOUS KEYWORDS
    # ======================================================

    keyword_count = 0

    for word in SUSPICIOUS_WORDS:

        if word in lower_url:

            keyword_count += 1

    features["keyword_count"] = (
        keyword_count
    )

    features["has_suspicious_keyword"] = int(
        keyword_count > 0
    )

    # ======================================================
    # SUSPICIOUS TLD
    # ======================================================

    features["has_suspicious_tld"] = int(
        any(
            tld in lower_url
            for tld in SUSPICIOUS_TLDS
        )
    )

    # ======================================================
    # URL ENCODING
    # ======================================================

    features["encoded_char_count"] = len(
        re.findall(
            r"%[0-9a-fA-F]{2}",
            url
        )
    )

    # ======================================================
    # REPEATED CHARACTERS
    # ======================================================

    features["has_repeated_dot"] = int(
        ".." in url
    )

    features["has_repeated_dash"] = int(
        "--" in url
    )

    # ======================================================
    # PORT
    # ======================================================

    if parsed is not None:

        try:

            features["has_port"] = int(
                parsed.port is not None
            )

        except ValueError:

            features["has_port"] = 0

    else:

        features["has_port"] = 0

    # ======================================================
    # LONG HOSTNAME
    # ======================================================

    features["long_hostname"] = int(
        len(hostname) > 40
    )

    # ======================================================
    # MANY SUBDOMAINS
    # ======================================================

    features["many_subdomains"] = int(
        features["num_subdomains"] >= 3
    )

    return features
