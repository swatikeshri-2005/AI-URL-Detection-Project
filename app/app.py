import os
import sys

import streamlit as st # type: ignore
import pandas as pd


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
# IMPORT PREDICTION FUNCTION
# ============================================================

from src.predict import predict_url  # noqa: E402


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="AI Cyber Threat Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    """
    <style>

    .main-title {
        font-size: 42px;
        font-weight: 700;
        text-align: center;
        margin-bottom: 5px;
    }

    .subtitle {
        text-align: center;
        font-size: 18px;
        margin-bottom: 30px;
    }

    .result-box {
        padding: 25px;
        border-radius: 15px;
        border: 1px solid #444;
        margin-top: 20px;
    }

    .safe {
        font-size: 30px;
        font-weight: 700;
    }

    .danger {
        font-size: 30px;
        font-weight: 700;
    }

    .metric-box {
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #555;
        text-align: center;
    }

    .small-text {
        font-size: 14px;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="main-title">'
    '🛡️ AI Cyber Threat Detector'
    '</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'AI-powered phishing and malicious URL detection '
    'using NLP and machine learning'
    '</div>',
    unsafe_allow_html=True
)


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.header(
        "🛡️ About"
    )

    st.write(
        """
        This application analyzes URLs and predicts
        whether they are potentially benign or malicious.

        The model uses:

        • Character-level NLP features

        • URL security features

        • Malicious keyword detection

        • IP address detection

        • Suspicious TLD detection

        • URL structure analysis

        • Logistic Regression
        """
    )

    st.divider()

    st.subheader(
        "📊 Model Performance"
    )

    st.metric(
        "Accuracy",
        "96.69%"
    )

    st.metric(
        "Malicious Recall",
        "95.08%"
    )

    st.metric(
        "F1 Score",
        "92.84%"
    )

    st.divider()

    st.caption(
        "⚠️ This tool is for educational and "
        "research purposes."
    )


# ============================================================
# URL INPUT
# ============================================================

st.subheader(
    "🔍 Analyze a URL"
)

url = st.text_input(
    "Enter URL",
    placeholder="https://example.com",
    help="Enter the URL as text. The application does not open the URL."
)


# ============================================================
# ANALYZE BUTTON
# ============================================================

analyze = st.button(
    "🔎 Analyze URL",
    type="primary",
    use_container_width=True
)


# ============================================================
# ANALYSIS
# ============================================================

if analyze:

    if not url.strip():

        st.warning(
            "⚠️ Please enter a URL first."
        )

    else:

        with st.spinner(
            "Analyzing URL..."
        ):

            try:

                result = predict_url(
                    url.strip()
                )

                # ==================================================
                # RESULT
                # ==================================================

                st.divider()

                st.subheader(
                    "🎯 Detection Result"
                )

                prediction = (
                    result["prediction"]
                )

                malicious_probability = (
                    result[
                        "malicious_probability"
                    ] * 100
                )

                benign_probability = (
                    result[
                        "benign_probability"
                    ] * 100
                )

                risk_score = (
                    result["risk_score"]
                )

                risk_level = (
                    result["risk_level"]
                )

                # ==================================================
                # PREDICTION DISPLAY
                # ==================================================

                if prediction == "Benign":

                    st.success(
                        "✅ BENIGN URL"
                    )

                    st.info(
                        "The model does not detect "
                        "strong malicious patterns in this URL."
                    )

                else:

                    st.error(
                        "🚨 MALICIOUS URL DETECTED"
                    )

                    st.warning(
                        "This URL contains patterns "
                        "associated with potentially malicious URLs."
                    )

                # ==================================================
                # METRICS
                # ==================================================

                col1, col2, col3, col4 = st.columns(4)

                with col1:

                    st.metric(
                        "Prediction",
                        prediction
                    )

                with col2:

                    st.metric(
                        "Benign Probability",
                        f"{benign_probability:.2f}%"
                    )

                with col3:

                    st.metric(
                        "Malicious Probability",
                        f"{malicious_probability:.2f}%"
                    )

                with col4:

                    st.metric(
                        "Risk Score",
                        f"{risk_score:.1f}/100"
                    )

                # ==================================================
                # RISK LEVEL
                # ==================================================

                st.subheader(
                    "⚠️ Risk Assessment"
                )

                if risk_level == "LOW":

                    st.success(
                        f"🟢 LOW RISK — {risk_score:.1f}/100"
                    )

                elif risk_level == "MEDIUM":

                    st.warning(
                        f"🟡 MEDIUM RISK — {risk_score:.1f}/100"
                    )

                else:

                    st.error(
                        f"🔴 HIGH RISK — {risk_score:.1f}/100"
                    )

                st.progress(
                    min(
                        int(risk_score),
                        100
                    )
                )

                # ==================================================
                # URL INFORMATION
                # ==================================================

                st.divider()

                st.subheader(
                    "🌐 URL Information"
                )

                st.code(
                    result["url"],
                    language="text"
                )

                # ==================================================
                # SECURITY FEATURES
                # ==================================================

                st.subheader(
                    "🔎 Security Feature Analysis"
                )

                features = result[
                    "features"
                ]

                feature_data = []

                for key, value in features.items():

                    feature_data.append(
                        {
                            "Feature": key,
                            "Value": value
                        }
                    )

                feature_df = pd.DataFrame(
                    feature_data
                )

                st.dataframe(
                    feature_df,
                    use_container_width=True,
                    hide_index=True
                )

                # ==================================================
                # SECURITY CHECKS
                # ==================================================

                st.subheader(
                    "🧪 Security Checks"
                )

                check_col1, check_col2 = (
                    st.columns(2)
                )

                with check_col1:

                    if features.get(
                        "has_https",
                        0
                    ):

                        st.success(
                            "✅ HTTPS detected"
                        )

                    else:

                        st.warning(
                            "⚠️ HTTPS not detected"
                        )

                    if features.get(
                        "has_ip",
                        0
                    ):

                        st.error(
                            "🚨 IP address detected"
                        )

                    else:

                        st.success(
                            "✅ No direct IP address"
                        )

                    if features.get(
                        "has_at",
                        0
                    ):

                        st.error(
                            "🚨 @ symbol detected"
                        )

                    else:

                        st.success(
                            "✅ No @ symbol"
                        )

                with check_col2:

                    if features.get(
                        "has_suspicious_keyword",
                        0
                    ):

                        st.warning(
                            "⚠️ Suspicious keywords detected"
                        )

                    else:

                        st.success(
                            "✅ No suspicious keywords"
                        )

                    if features.get(
                        "has_suspicious_tld",
                        0
                    ):

                        st.warning(
                            "⚠️ Suspicious TLD detected"
                        )

                    else:

                        st.success(
                            "✅ No suspicious TLD"
                        )

                    if features.get(
                        "many_subdomains",
                        0
                    ):

                        st.warning(
                            "⚠️ Multiple subdomains detected"
                        )

                    else:

                        st.success(
                            "✅ Normal subdomain structure"
                        )

            except Exception as e:

                st.error(
                    "❌ Error while analyzing URL."
                )

                st.exception(
                    e
                )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "AI Cyber Threat Detector • "
    "NLP + URL Feature Engineering + Machine Learning"
)

st.caption(
    "The URL is analyzed as text and is not opened by this application."
)

