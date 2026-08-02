# `src/evaluate.py`
import os
import sys
import joblib
import pandas as pd
import matplotlib.pyplot as plt

from scipy.sparse import hstack, csr_matrix

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay
)

# ============================================================
# PROJECT PATH
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

sys.path.append(BASE_DIR)

from src.preprocessing import (  # noqa: E402
    load_dataset,
    clean_dataset,
    normalize_binary_labels
)

from src.feature_extraction import extract_features  # noqa: E402


DATA_PATH = os.path.join(
    BASE_DIR,
    "data",
    "phishing_site_urls.csv"
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "models"
)

OUTPUT_DIR = os.path.join(
    BASE_DIR,
    "outputs"
)

os.makedirs(
    OUTPUT_DIR,
    exist_ok=True
)


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("              AI CYBER THREAT DETECTOR")
    print("                    MODEL EVALUATION")
    print("=" * 70)

    # ========================================================
    # LOAD DATASET
    # ========================================================

    print("\nLoading dataset...")

    df = load_dataset(
        DATA_PATH
    )

    df = clean_dataset(
        df
    )

    df = normalize_binary_labels(
        df
    )

    df = df.dropna(
        subset=["target"]
    )

    X_urls = df["url"].values
    y = df["target"].values

    print(
        "\nDataset size:",
        len(X_urls)
    )

    # ========================================================
    # SAME TRAIN / TEST SPLIT
    # ========================================================

    (
        X_train_urls,
        X_test_urls,
        y_train,
        y_test
    ) = train_test_split(
        X_urls,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    print(
        "Testing samples:",
        len(X_test_urls)
    )

    # ========================================================
    # LOAD TRAINED MODEL
    # ========================================================

    print("\nLoading trained model...")

    model = joblib.load(
        os.path.join(
            MODEL_DIR,
            "url_classifier.pkl"
        )
    )

    vectorizer = joblib.load(
        os.path.join(
            MODEL_DIR,
            "tfidf_vectorizer.pkl"
        )
    )

    scaler = joblib.load(
        os.path.join(
            MODEL_DIR,
            "feature_scaler.pkl"
        )
    )

    print(
        "Models loaded successfully."
    )

    # ========================================================
    # HASHING NLP FEATURES
    # ========================================================

    print(
        "\nCreating NLP features..."
    )

    X_test_text = vectorizer.transform(
        X_test_urls
    )

    print(
        "NLP matrix:",
        X_test_text.shape
    )

    # ========================================================
    # SECURITY FEATURES
    # ========================================================

    print(
        "\nExtracting security features..."
    )

    test_features = pd.DataFrame(
        [
            extract_features(url)
            for url in X_test_urls
        ]
    )

    # ========================================================
    # SCALE SECURITY FEATURES
    # ========================================================

    X_test_numeric = scaler.transform(
        test_features
    )

    X_test_numeric = csr_matrix(
        X_test_numeric
    )

    # ========================================================
    # COMBINE FEATURES
    # ========================================================

    X_test = hstack(
        [
            X_test_text,
            X_test_numeric
        ]
    ).tocsr()

    print(
        "Final test matrix:",
        X_test.shape
    )

    # ========================================================
    # PREDICTIONS
    # ========================================================

    print(
        "\nGenerating predictions..."
    )

    y_pred = model.predict(
        X_test
    )

    # ========================================================
    # PROBABILITIES
    # ========================================================

    y_probability = model.predict_proba(  # noqa: F841
        X_test
    )[:, 1]

    # ========================================================
    # METRICS
    # ========================================================

    accuracy = accuracy_score(
        y_test,
        y_pred
    )

    precision = precision_score(
        y_test,
        y_pred,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        y_pred,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        y_pred,
        zero_division=0
    )

    # ========================================================
    # DISPLAY RESULTS
    # ========================================================

    print("\n")
    print("=" * 70)
    print("                     RESULTS")
    print("=" * 70)

    print(
        f"\nAccuracy : {accuracy:.4f}"
    )

    print(
        f"Precision: {precision:.4f}"
    )

    print(
        f"Recall   : {recall:.4f}"
    )

    print(
        f"F1 Score : {f1:.4f}"
    )

    print(
        "\nClassification Report:"
    )

    report = classification_report(
        y_test,
        y_pred,
        target_names=[
            "Benign",
            "Malicious"
        ],
        zero_division=0
    )

    print(report)

    # ========================================================
    # CONFUSION MATRIX
    # ========================================================

    print(
        "Creating confusion matrix..."
    )

    cm = confusion_matrix(
        y_test,
        y_pred
    )

    print("\nConfusion Matrix:")

    print(cm)

    display = ConfusionMatrixDisplay(
        confusion_matrix=cm,
        display_labels=[
            "Benign",
            "Malicious"
        ]
    )

    display.plot()

    plt.title(
        "AI URL Threat Detector - Confusion Matrix"
    )

    plt.tight_layout()

    confusion_path = os.path.join(
        OUTPUT_DIR,
        "confusion_matrix.png"
    )

    plt.savefig(
        confusion_path,
        dpi=150
    )

    plt.close()

    print(
        "\nConfusion matrix saved:"
    )

    print(
        confusion_path
    )

    # ========================================================
    # SAVE METRICS
    # ========================================================

    metrics_path = os.path.join(
        OUTPUT_DIR,
        "metrics.txt"
    )

    with open(
        metrics_path,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "AI CYBER THREAT DETECTOR\n"
        )

        file.write(
            "=======================\n\n"
        )

        file.write(
            f"Dataset Size: {len(X_urls)}\n"
        )

        file.write(
            f"Test Size: {len(X_test_urls)}\n\n"
        )

        file.write(
            f"Accuracy : {accuracy:.4f}\n"
        )

        file.write(
            f"Precision: {precision:.4f}\n"
        )

        file.write(
            f"Recall   : {recall:.4f}\n"
        )

        file.write(
            f"F1 Score : {f1:.4f}\n\n"
        )

        file.write(
            "Classification Report\n"
        )

        file.write(
            "---------------------\n"
        )

        file.write(report)

    print(
        "Metrics saved:"
    )

    print(
        metrics_path
    )

    print("\n")
    print("=" * 70)
    print("                  EVALUATION COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
