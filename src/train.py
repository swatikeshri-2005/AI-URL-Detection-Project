# `src/train.py`
import os
import sys
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from scipy.sparse import hstack, csr_matrix

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    precision_score,
    recall_score,
    f1_score
)


# ============================================================
# PROJECT PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

sys.path.append(BASE_DIR)


from src.preprocessing import (load_dataset,clean_dataset,normalize_binary_labels)  # noqa: E402

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

os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("        AI CYBER THREAT DETECTOR")
    print("        MEMORY-EFFICIENT TRAINING")
    print("=" * 70)

    # ========================================================
    # LOAD DATASET
    # ========================================================

    df = load_dataset(DATA_PATH)

    # ========================================================
    # CLEAN DATA
    # ========================================================

    df = clean_dataset(df)

    # ========================================================
    # NORMALIZE LABELS
    # ========================================================

    df = normalize_binary_labels(df)

    df = df.dropna(
        subset=["target"]
    )

    X_urls = df["url"].values
    y = df["target"].values

    print("\nFinal dataset size:", len(X_urls))

    print("\nClass distribution:")

    print(
        pd.Series(y).value_counts()
    )

    # ========================================================
    # TRAIN / TEST SPLIT
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
        "\nTraining samples:",
        len(X_train_urls)
    )

    print(
        "Testing samples:",
        len(X_test_urls)
    )

    # ========================================================
    # NLP FEATURE EXTRACTION
    # ========================================================

    print("\nCreating memory-efficient NLP features...")

    vectorizer = HashingVectorizer(
        analyzer="char",
        ngram_range=(2, 4),
        n_features=2**16,
        alternate_sign=False,
        norm="l2"
    )

    print(
        "HashingVectorizer configuration:"
    )

    print(
        "n_features =",
        2**16
    )

    print(
        "ngram_range = (2, 4)"
    )

    X_train_text = vectorizer.transform(
        X_train_urls
    )

    print(
        "NLP training matrix:",
        X_train_text.shape
    )

    X_test_text = vectorizer.transform(
        X_test_urls
    )

    print(
        "NLP testing matrix:",
        X_test_text.shape
    )

    # ========================================================
    # SECURITY FEATURES
    # ========================================================

    print(
        "\nExtracting URL security features..."
    )

    train_features = pd.DataFrame(
        [
            extract_features(url)
            for url in X_train_urls
        ]
    )

    test_features = pd.DataFrame(
        [
            extract_features(url)
            for url in X_test_urls
        ]
    )

    print(
        "Security features:",
        train_features.shape[1]
    )

    print(
        "\nSecurity feature names:"
    )

    print(
        train_features.columns.tolist()
    )

    # ========================================================
    # SCALE SECURITY FEATURES
    # ========================================================

    print(
        "\nScaling security features..."
    )

    scaler = StandardScaler()

    X_train_numeric = scaler.fit_transform(
        train_features
    )

    X_test_numeric = scaler.transform(
        test_features
    )

    X_train_numeric = csr_matrix(
        X_train_numeric
    )

    X_test_numeric = csr_matrix(
        X_test_numeric
    )

    # ========================================================
    # COMBINE NLP + SECURITY FEATURES
    # ========================================================

    print(
        "\nCombining NLP + security features..."
    )

    X_train = hstack(
        [
            X_train_text,
            X_train_numeric
        ]
    ).tocsr()

    X_test = hstack(
        [
            X_test_text,
            X_test_numeric
        ]
    ).tocsr()

    print(
        "Final training matrix:",
        X_train.shape
    )

    print(
        "Final testing matrix:",
        X_test.shape
    )

    # ========================================================
    # TRAIN LOGISTIC REGRESSION
    # ========================================================

    print(
        "\nTraining Logistic Regression..."
    )

    model = LogisticRegression(
        max_iter=300,
        class_weight="balanced",
        solver="liblinear",
        random_state=42
    )

    model.fit(
        X_train,
        y_train
    )

    print(
        "Training completed successfully!"
    )

    # ========================================================
    # PREDICTION
    # ========================================================

    print(
        "\nGenerating predictions..."
    )

    y_pred = model.predict(
        X_test
    )

    # ========================================================
    # EVALUATION
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

    print("\n")
    print("=" * 70)
    print("                  MODEL PERFORMANCE")
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

    print(
        classification_report(
            y_test,
            y_pred,
            target_names=[
                "Benign",
                "Malicious"
            ],
            zero_division=0
        )
    )

    # ========================================================
    # SAVE MODEL
    # ========================================================

    print(
        "\nSaving models..."
    )

    model_path = os.path.join(
        MODEL_DIR,
        "url_classifier.pkl"
    )

    vectorizer_path = os.path.join(
        MODEL_DIR,
        "tfidf_vectorizer.pkl"
    )

    scaler_path = os.path.join(
        MODEL_DIR,
        "feature_scaler.pkl"
    )

    joblib.dump(
        model,
        model_path
    )

    joblib.dump(
        vectorizer,
        vectorizer_path
    )

    joblib.dump(
        scaler,
        scaler_path
    )

    print(
        "\nSaved:"
    )

    print(
        model_path
    )

    print(
        vectorizer_path
    )

    print(
        scaler_path
    )

    # ========================================================
    # SAVE FEATURE NAMES
    # ========================================================

    feature_names_path = os.path.join(
        MODEL_DIR,
        "security_feature_names.pkl"
    )

    security_feature_names = (
        train_features.columns.tolist()
    )

    joblib.dump(
        security_feature_names,
        feature_names_path
    )

    # ========================================================
    # SECURITY FEATURE IMPORTANCE
    # ========================================================

    print(
        "\nGenerating security feature importance..."
    )

    # Last N coefficients correspond to
    # handcrafted security features

    num_security_features = (
        len(security_feature_names)
    )

    coefficients = model.coef_[0]

    security_coefficients = coefficients[
        -num_security_features:
    ]

    importance_df = pd.DataFrame(
        {
            "feature":
                security_feature_names,

            "coefficient":
                security_coefficients,

            "absolute_importance":
                np.abs(
                    security_coefficients
                )
        }
    )

    importance_df = (
        importance_df
        .sort_values(
            "absolute_importance",
            ascending=False
        )
    )

    print(
        "\nTop security features:"
    )

    print(
        importance_df.head(15)
    )

    # ========================================================
    # PLOT
    # ========================================================

    top_features = (
        importance_df
        .head(15)
        .sort_values(
            "absolute_importance"
        )
    )

    plt.figure(
        figsize=(10, 7)
    )

    plt.barh(
        top_features["feature"],
        top_features["coefficient"]
    )

    plt.xlabel(
        "Model Coefficient"
    )

    plt.ylabel(
        "Security Feature"
    )

    plt.title(
        "Top URL Security Features"
    )

    plt.tight_layout()

    feature_path = os.path.join(
        OUTPUT_DIR,
        "feature_importance.png"
    )

    plt.savefig(
        feature_path,
        dpi=150
    )

    plt.close()

    print(
        "\nFeature importance saved:"
    )

    print(
        feature_path
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
            f"Training Size: {len(X_train_urls)}\n"
        )

        file.write(
            f"Testing Size: {len(X_test_urls)}\n\n"
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

        file.write(
            classification_report(
                y_test,
                y_pred,
                target_names=[
                    "Benign",
                    "Malicious"
                ],
                zero_division=0
            )
        )

    print(
        "\nMetrics saved:"
    )

    print(
        metrics_path
    )

    # ========================================================
    # FINISHED
    # ========================================================

    print("\n")
    print("=" * 70)
    print(
        "           TRAINING COMPLETED SUCCESSFULLY"
    )
    print("=" * 70)


if __name__ == "__main__":
    main()
