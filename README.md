AI-URL-Threat-Detector
# 🛡️ AI Cyber Threat Detector

### Phishing & Malicious URL Detection using NLP and Machine Learning

An AI-powered cybersecurity application that analyzes URLs and predicts whether they are **Benign** or **Malicious**.

The system combines **character-level NLP**, **URL security feature extraction**, **malicious pattern detection**, and **Machine Learning** to identify potentially dangerous URLs.

A **Streamlit web application** provides an interactive interface for real-time URL analysis.

---

## 🚀 Features

- 🔍 Real-time URL threat detection
- 🧠 Character-level NLP feature extraction
- 🔐 URL security feature analysis
- 🚨 Malicious keyword detection
- 🌐 IP address detection
- ⚠️ Suspicious TLD detection
- 🔗 URL structure analysis
- 📊 Probability-based prediction
- 🎯 Risk score from 0–100
- 🟢 Low / 🟡 Medium / 🔴 High risk classification
- 📈 Confusion matrix and model evaluation
- 🖥️ Interactive Streamlit dashboard
- 💾 Trained ML model saved using Joblib
- ⚡ Memory-efficient NLP using HashingVectorizer

---

# 🧠 How It Works

The system follows this pipeline:

```text
                  URL Input
                      │
                      ▼
              Data Preprocessing
                      │
                      ▼
          ┌────────────────────────┐
          │   URL Feature Engine   │
          └────────────────────────┘
                 │           │
                 │           │
                 ▼           ▼
          NLP Features   Security Features
                 │           │
                 └─────┬─────┘
                       ▼
              Feature Combination
                       │
                       ▼
              Machine Learning Model
                       │
                       ▼
             Benign / Malicious
                       │
                       ▼
                Risk Assessment
                       │
                       ▼
             Streamlit Dashboard
📊 Dataset

The project uses a URL classification dataset containing approximately:

Original URLs:       549,346
Cleaned URLs:        507,192

Benign URLs:         392,897
Malicious URLs:      114,295
Labels
0 → Benign
1 → Malicious

The dataset contains URL strings and their corresponding labels.

⚠️ The dataset is not included in this repository if it is too large or has redistribution restrictions. Place your dataset inside the data/ directory before training.

🧪 Feature Engineering

The project extracts multiple security-related URL features.

URL Structure Features
URL length
Hostname length
Path length
Query length
Number of dots
Number of slashes
Number of dashes
Number of underscores
Number of digits
Number of letters
Number of special characters
Security Features
HTTPS detection
HTTP detection
IP address detection
@ symbol detection
# detection
? detection
= detection
% encoding detection
& detection
Double slash detection
Port detection
Suspicious Pattern Features

The system checks for suspicious words such as:

login
signin
verify
account
secure
update
confirm
password
bank
paypal
credential
authenticate
wallet
payment
billing
free
bonus
winner
prize
gift
reward
crypto
bitcoin
recover
suspend
unlock

It also detects potentially suspicious top-level domains such as:

.tk
.ml
.ga
.cf
.gq
.xyz
.top
.click
.download
🧠 NLP Processing

The project uses a character-level HashingVectorizer.

Configuration:

n_features = 65,536
ngram_range = (2, 4)

Character-level NLP is useful for URL analysis because malicious URLs often contain suspicious character patterns, obfuscation, unusual paths, and randomly generated strings.

The HashingVectorizer also helps reduce memory consumption when processing hundreds of thousands of URLs.

🤖 Machine Learning

The extracted NLP and security features are combined into a single feature matrix.

Example:

NLP features:
65,536

Security features:
32

Total:
65,568 features

The classification model is trained to predict:

0 → Benign
1 → Malicious

The model also provides probability estimates for the prediction.

📈 Model Performance

The current trained model achieved the following results on the test dataset:

Metric	Score
Accuracy	96.69%
Precision	90.70%
Recall	95.08%
F1 Score	92.84%
Classification Report
              precision    recall  f1-score

Benign          0.99       0.97      0.98
Malicious       0.91       0.95      0.93

Accuracy                              0.97
Confusion Matrix
                 Predicted
                 Benign   Malicious

Actual Benign     76351     2229
Actual Malicious   1124    21735

The model correctly detected 21,735 malicious URLs in the test set.

📁 Project Structure
AI-URL-Threat-Detector/
│
├── data/
│   └── urls.csv
│
├── models/
│   ├── url_classifier.pkl
│   ├── tfidf_vectorizer.pkl
│   └── feature_scaler.pkl
│
├── notebooks/
│   └── url_analysis.ipynb
│
├── src/
│   ├── __init__.py
│   ├── feature_extraction.py
│   ├── preprocessing.py
│   ├── train.py
│   ├── evaluate.py
│   ├── predict.py
│   └── test_urls.py
│
├── app/
│   └── app.py
│
├── outputs/
│   ├── confusion_matrix.png
│   ├── feature_importance.png
│   └── metrics.txt
│
├── requirements.txt
├── README.md
└── .gitignore
⚙️ Installation
1. Clone the Repository
git clone https://github.com/YOUR_USERNAME/AI-URL-Threat-Detector.git

Move into the project:

cd AI-URL-Threat-Detector
2. Create a Virtual Environment
Windows
python -m venv venv

Activate it:

venv\Scripts\activate
Linux / macOS
python3 -m venv venv

Activate:

source venv/bin/activate
📦 Install Dependencies
pip install -r requirements.txt

If you haven't created requirements.txt, use:

pandas
numpy
scikit-learn
scipy
joblib
matplotlib
streamlit

Then:

pip install -r requirements.txt
🗃️ Dataset Setup

Place your dataset inside:

data/
└── urls.csv

The dataset should contain URL and label columns.

Example:

URL,Label
https://www.google.com,good
https://example.com/login,good
http://malicious-example.xyz/verify,bad

The preprocessing pipeline automatically detects common URL and label column names.

🏋️ Train the Model

From the project root:

python src/train.py

The training process performs:

Dataset Loading
      ↓
Data Cleaning
      ↓
Label Conversion
      ↓
Train/Test Split
      ↓
HashingVectorizer
      ↓
URL Security Features
      ↓
Feature Scaling
      ↓
Feature Combination
      ↓
Model Training
      ↓
Model Saving

The trained files are stored in:

models/
├── url_classifier.pkl
├── tfidf_vectorizer.pkl
└── feature_scaler.pkl
📊 Evaluate the Model

Run:

python src/evaluate.py

The evaluation script calculates:

Accuracy
Precision
Recall
F1 Score
Classification Report
Confusion Matrix

Results are saved to:

outputs/
├── confusion_matrix.png
└── metrics.txt
🔍 Test a Single URL

Run:

python src/predict.py

Example:

======================================================================
          AI CYBER THREAT DETECTOR
======================================================================

Enter a URL to analyze.

URL: https://example.com

The program returns:

Prediction:
Benign

Benign Probability:
XX.XX%

Malicious Probability:
XX.XX%

Risk Score:
XX.XX/100

Risk Level:
LOW
🌐 Run the Streamlit Application

Start the application:

streamlit run app/app.py

The application will open in your browser.

Usually:

http://localhost:8501

The dashboard provides:

URL input
Threat prediction
Benign probability
Malicious probability
Risk score
Risk level
Security feature analysis
URL structure analysis
🖥️ Application Preview
┌─────────────────────────────────────────────┐
│        🛡️ AI Cyber Threat Detector          │
│                                             │
│ AI-powered phishing and malicious URL      │
│ detection using NLP and machine learning   │
│                                             │
│ Enter URL                                   │
│ ┌─────────────────────────────────────────┐ │
│ │ https://example.com                     │ │
│ └─────────────────────────────────────────┘ │
│                                             │
│          🔎 Analyze URL                     │
│                                             │
│ 🎯 Detection Result                         │
│                                             │
│ Prediction: Benign                          │
│                                             │
│ Benign Probability: 97.2%                   │
│ Malicious Probability: 2.8%                │
│                                             │
│ Risk Score: 8.4/100                         │
│ Risk Level: LOW                             │
│                                             │
│ 🔎 Security Feature Analysis                │
│                                             │
│ HTTPS                  ✅                    │
│ IP Address             ✅                    │
│ Suspicious Keywords   ✅                    │
│ Suspicious TLD         ✅                    │
└─────────────────────────────────────────────┘
🔐 Security Considerations

This application does not open or visit submitted URLs.

The system analyzes the URL as text and extracts features from the URL string.

It does not:

Open the URL
Download website content
Execute JavaScript
Submit credentials
Interact with websites

This reduces the risk of directly interacting with potentially malicious websites.

⚠️ Limitations

Machine learning predictions are not guaranteed to be correct.

Possible limitations include:

False positives
False negatives
Newly created phishing domains
URL obfuscation
Shortened URLs
Dataset bias
Distribution differences between training and real-world URLs
Adversarial URLs designed to evade ML models

Therefore, this project should be considered a security research and educational tool, not a replacement for enterprise security software.

🚀 Future Improvements

Planned improvements include:

 Improve benign URL generalization
 Add more phishing datasets
 Add URL reputation APIs
 Add domain age analysis
 Add DNS analysis
 Add WHOIS information
 Add SSL certificate analysis
 Add suspicious redirect detection
 Add SHAP explainability
 Add XGBoost comparison
 Add Random Forest comparison
 Add ensemble model
 Add URL history
 Add downloadable reports
 Improve Streamlit dashboard
 Deploy online
 Add Docker support
 Add automated model retraining
🧰 Technologies Used
Programming
Python
Machine Learning
Scikit-learn
Logistic Regression
HashingVectorizer
Feature Scaling
NLP
Character-level n-grams
URL text analysis
Data Processing
Pandas
NumPy
Visualization
Matplotlib
Web Application
Streamlit
Model Persistence
Joblib
Scientific Computing
SciPy
📚 Learning Outcomes

This project demonstrates practical experience with:

Python
   ↓
Data Cleaning
   ↓
Feature Engineering
   ↓
NLP
   ↓
Machine Learning
   ↓
Model Evaluation
   ↓
Cybersecurity
   ↓
Streamlit
   ↓
Deployment

It is a practical example of combining Machine Learning + NLP + Cybersecurity + Web Deployment.

👩‍💻 Author

Swati Keshri

B.Tech Computer Science Engineering

⭐ Support

If you find this project useful, consider giving the repository a ⭐ on GitHub.

⚠️ Disclaimer

This project is intended for educational, research, and defensive cybersecurity purposes only.

The predictions generated by this application should not be treated as definitive proof that a URL is safe or malicious.

Always use additional security tools and professional analysis when dealing with potentially dangerous URLs.


### One important GitHub step

Since your dataset has **507K+ URLs**, I recommend **not committing the full `urls.csv` to GitHub** unless its license permits redistribution and the file size is suitable.

Your `.gitignore` should include:

```gitignore
# Python
__pycache__/
*.py[cod]
venv/
.env

# Jupyter
.ipynb_checkpoints/

# Dataset
data/*.csv

# Generated models
models/*.pkl

# Generated outputs
outputs/*.png
outputs/*.txt

# Streamlit
.streamlit/

# OS
.DS_Store
Thumbs.db

