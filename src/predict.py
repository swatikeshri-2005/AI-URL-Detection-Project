import os
import sys
import joblib
import pandas as pd

from scipy.sparse import hstack, csr_matrix


# ============================================================
# PROJECT PATH
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

sys.path.append(BASE_DIR)


# ============================================================
# IMPORT FEATURE EXTRACTION
# ============================================================

from src.feature_extraction import extract_features  # noqa: E402


# ============================================================
# MODEL PATH
# ============================================================

MODEL_DIR = os.path.join(
    BASE_DIR,
    "models"
)


MODEL_PATH = os.path.join(
    MODEL_DIR,
    "url_classifier.pkl"
)


VECTORIZER_PATH = os.path.join(
    MODEL_DIR,
    "tfidf_vectorizer.pkl"
)


SCALER_PATH = os.path.join(
    MODEL_DIR,
    "feature_scaler.pkl"
)


# ============================================================
# LOAD MODELS
# ============================================================

def load_models():

    print("\nLoading trained models...")

    # --------------------------------------------------------
    # Check model files
    # --------------------------------------------------------

    if not os.path.exists(MODEL_PATH):

        raise FileNotFoundError(
            f"Model not found:\n{MODEL_PATH}\n\n"
            "Run train.py first."
        )

    if not os.path.exists(VECTORIZER_PATH):

        raise FileNotFoundError(
            f"Vectorizer not found:\n"
            f"{VECTORIZER_PATH}\n\n"
            "Run train.py first."
        )

    if not os.path.exists(SCALER_PATH):

        raise FileNotFoundError(
            f"Scaler not found:\n"
            f"{SCALER_PATH}\n\n"
            "Run train.py first."
        )

    # --------------------------------------------------------
    # Load
    # --------------------------------------------------------

    model = joblib.load(
        MODEL_PATH
    )

    vectorizer = joblib.load(
        VECTORIZER_PATH
    )

    scaler = joblib.load(
        SCALER_PATH
    )

    print(
        "Models loaded successfully."
    )

    return (
        model,
        vectorizer,
        scaler
    )


# ============================================================
# CALCULATE RISK SCORE
# ============================================================

def calculate_risk(
    malicious_probability,
    features
):

    # --------------------------------------------------------
    # Start with ML probability
    # --------------------------------------------------------

    score = (
        malicious_probability * 100
    )

    # --------------------------------------------------------
    # Additional security indicators
    # --------------------------------------------------------

    if features.get(
        "has_ip",
        0
    ):

        score += 8

    if features.get(
        "has_at",
        0
    ):

        score += 8

    if features.get(
        "has_suspicious_keyword",
        0
    ):

        score += 5

    if features.get(
        "has_suspicious_tld",
        0
    ):

        score += 5

    if features.get(
        "many_subdomains",
        0
    ):

        score += 4

    if features.get(
        "url_length",
        0
    ) > 100:

        score += 3

    # --------------------------------------------------------
    # Keep between 0 and 100
    # --------------------------------------------------------

    score = min(
        score,
        100
    )

    score = max(
        score,
        0
    )

    return score


# ============================================================
# GET RISK LEVEL
# ============================================================

def get_risk_level(
    risk_score
):

    if risk_score < 30:

        return "LOW"

    elif risk_score < 60:

        return "MEDIUM"

    else:

        return "HIGH"


# ============================================================
# PREDICT URL
# ============================================================

def predict_url(url):

    # --------------------------------------------------------
    # Clean input
    # --------------------------------------------------------

    url = str(url).strip()

    if not url:

        raise ValueError(
            "URL cannot be empty."
        )

    # --------------------------------------------------------
    # Load models
    # --------------------------------------------------------

    (
        model,
        vectorizer,
        scaler
    ) = load_models()

    # ========================================================
    # NLP FEATURES
    # ========================================================

    text_features = (
        vectorizer.transform(
            [url]
        )
    )

    # ========================================================
    # SECURITY FEATURES
    # ========================================================

    feature_dict = extract_features(
        url
    )

    security_df = pd.DataFrame(
        [feature_dict]
    )

    # ========================================================
    # SCALE FEATURES
    # ========================================================

    numeric_features = (
        scaler.transform(
            security_df
        )
    )

    numeric_features = csr_matrix(
        numeric_features
    )

    # ========================================================
    # COMBINE NLP + SECURITY FEATURES
    # ========================================================

    final_features = hstack(
        [
            text_features,
            numeric_features
        ]
    ).tocsr()

    # ========================================================
    # MODEL PREDICTION
    # ========================================================

    prediction = model.predict(
        final_features
    )[0]

    # ========================================================
    # MODEL PROBABILITY
    # ========================================================

    probabilities = model.predict_proba(
        final_features
    )[0]

    benign_probability = (
        probabilities[0]
    )

    malicious_probability = (
        probabilities[1]
    )

    # ========================================================
    # LABEL
    # ========================================================

    if prediction == 0:

        label = "Benign"

    else:

        label = "Malicious"

    # ========================================================
    # RISK SCORE
    # ========================================================

    risk_score = calculate_risk(
        malicious_probability,
        feature_dict
    )

    risk_level = get_risk_level(
        risk_score
    )

    # ========================================================
    # RETURN RESULT
    # ========================================================

    return {

        "url":
            url,

        "prediction":
            label,

        "benign_probability":
            benign_probability,

        "malicious_probability":
            malicious_probability,

        "risk_score":
            risk_score,

        "risk_level":
            risk_level,

        "features":
            feature_dict
    }


# ============================================================
# DISPLAY RESULT
# ============================================================

def display_result(result):

    print("\n")
    print("=" * 70)

    print(
        "                    RESULT"
    )

    print("=" * 70)

    # --------------------------------------------------------
    # URL
    # --------------------------------------------------------

    print(
        f"\nURL:"  # noqa: F541
    )

    print(
        result["url"]
    )

    # --------------------------------------------------------
    # Prediction
    # --------------------------------------------------------

    print(
        f"\nPrediction:"  # noqa: F541
    )

    print(
        result["prediction"]
    )

    # --------------------------------------------------------
    # Probability
    # --------------------------------------------------------

    print(
        f"\nBenign Probability:"
        f" {result['benign_probability'] * 100:.2f}%"
    )

    print(
        f"Malicious Probability:"
        f" {result['malicious_probability'] * 100:.2f}%"
    )

    # --------------------------------------------------------
    # Risk
    # --------------------------------------------------------

    print(
        f"\nRisk Score:"
        f" {result['risk_score']:.2f}/100"
    )

    print(
        f"Risk Level:"
        f" {result['risk_level']}"
    )

    # --------------------------------------------------------
    # Security features
    # --------------------------------------------------------

    print(
        "\nSecurity Features:"
    )

    print(
        "-" * 50
    )

    for key, value in result[
        "features"
    ].items():

        print(
            f"{key:30} : {value}"
        )

    print("\n")
    print("=" * 70)


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)

    print(
        "          🛡️ AI CYBER THREAT DETECTOR"
    )

    print(
        "          Phishing & Malicious URL Detection"
    )

    print("=" * 70)

    print(
        "\nEnter a URL to analyze."
    )

    print(
        "The URL will NOT be opened or visited."
    )

    print(
        "The system analyzes only the URL string."
    )

    # ========================================================
    # INPUT LOOP
    # ========================================================

    while True:

        url = input(
            "\nURL (type 'exit' to quit): "
        ).strip()

        # ----------------------------------------------------
        # Exit
        # ----------------------------------------------------

        if url.lower() in [
            "exit",
            "quit",
            "q"
        ]:

            print(
                "\nExiting AI Cyber Threat Detector..."
            )

            break

        # ----------------------------------------------------
        # Empty
        # ----------------------------------------------------

        if not url:

            print(
                "\nPlease enter a URL."
            )

            continue

        # ====================================================
        # PREDICTION
        # ====================================================

        try:

            result = predict_url(
                url
            )

            display_result(
                result
            )

        except Exception as e:

            print(
                "\n❌ Error while predicting URL:"
            )

            print(
                str(e)
            )


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    main()
