import os
import pandas as pd


def load_dataset(path):
    """
    Load URL dataset from CSV.
    """

    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Dataset not found: {path}"
        )

    df = pd.read_csv(path)

    print("\nDataset loaded successfully.")
    print("Shape:", df.shape)
    print("Columns:", list(df.columns))

    return df


def find_url_column(df):
    """
    Automatically detect URL column.
    """

    possible_columns = [
        "url",
        "URL",
        "Url",
        "link",
        "Link",
        "website",
        "Website"
    ]

    for column in possible_columns:
        if column in df.columns:
            return column

    # Fallback: first object/string column
    object_columns = df.select_dtypes(
        include=["object"]
    ).columns

    if len(object_columns) > 0:
        return object_columns[0]

    raise ValueError(
        "Could not find URL column."
    )


def find_label_column(df):
    """
    Automatically detect label column.
    """

    possible_columns = [
        "label",
        "Label",
        "LABEL",
        "class",
        "Class",
        "type",
        "Type",
        "category",
        "Category"
    ]

    for column in possible_columns:
        if column in df.columns:
            return column

    raise ValueError(
        "Could not find label column."
    )


def clean_dataset(df):
    """
    Clean URL dataset.
    """

    url_column = find_url_column(df)
    label_column = find_label_column(df)

    print("\nDetected URL column:", url_column)
    print("Detected label column:", label_column)

    df = df[[url_column, label_column]].copy()

    df.columns = ["url", "label"]

    # Remove missing values
    df = df.dropna(subset=["url", "label"])

    # Convert URL to string
    df["url"] = df["url"].astype(str).str.strip()

    # Remove empty URLs
    df = df[df["url"].str.len() > 0]

    # Remove duplicates
    df = df.drop_duplicates(subset=["url"])

    # Normalize labels
    df["label"] = df["label"].astype(str).str.strip()

    print("\nAfter cleaning:")
    print("Shape:", df.shape)

    print("\nLabel distribution:")
    print(df["label"].value_counts())

    return df


def normalize_binary_labels(df):
    """
    Convert common phishing/benign labels into:
    
    0 = Benign
    1 = Malicious
    """

    df = df.copy()

    unique_labels = df["label"].unique()

    print("\nOriginal labels:")
    print(unique_labels)

    # Common benign labels
    benign_values = {
        "benign",
        "good",
        "safe",
        "legitimate",
        "legit",
        "normal",
        "0"
    }

    def convert_label(label):

        label_clean = str(label).strip().lower()

        if label_clean in benign_values:
            return 0

        # Everything else is considered malicious
        return 1

    df["target"] = df["label"].apply(convert_label)

    print("\nConverted labels:")
    print("0 = Benign")
    print("1 = Malicious")

    print(df["target"].value_counts())

    return df