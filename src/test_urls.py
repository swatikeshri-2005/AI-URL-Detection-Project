import os
import sys
from unittest import result  # noqa: F401

# Project root
BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

sys.path.append(BASE_DIR)

from src.predict import predict_url  # noqa: E402, F401

TEST_URLS = [
      "https://www.google.com",
    "https://www.microsoft.com",
    "https://github.com",
    "https://www.wikipedia.org",
    "https://www.amazon.com",
    "https://www.apple.com",
    "https://www.python.org",
    "https://www.linkedin.com",
    "https://www.youtube.com",
    "https://www.reddit.com",
]

def main():
    print("=" * 80)
    print("AI CYBER THREAT DETECTOR")
    print(
        "       BENIGN URL SANITY TEST"
    )
    
    print("=" * 80)
    print()
    
    for url in TEST_URLS:

        try:

            result = predict_url(url)

            prediction = result[
                "prediction"
            ]

            benign_probability = (
                result[
                    "benign_probability"
                ] * 100
            )
            malicious_probability = (
                result[
                    "malicious_probability"
                ] * 100
            )

            risk_score = result[
                "risk_score"
            ]

            print("-" * 80)

            print(
                f"URL: {url}"
            )

            print(
                f"Prediction: {prediction}"
            )
            print(
                f"Benign Probability: "
                f"{benign_probability:.2f}%"
            )

            print(
                f"Malicious Probability: "
                f"{malicious_probability:.2f}%"
            )

            print(
                f"Risk Score: "
                f"{risk_score:.2f}/100"
            )

        except Exception as e:

            print(
                f"\nERROR: {url}"
            )

            print(e)
    print()

    print("=" * 80)

    print(
        "TEST COMPLETE"
    )

    print("=" * 80)


if __name__ == "__main__":

    main()