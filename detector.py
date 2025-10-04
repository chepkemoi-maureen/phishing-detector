
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.ensemble import RandomForestClassifier

# === Step 1: Load sample email data ===
data = [
    {"Subject": "Urgent: Account Suspended", "Body": "Click here to verify your account", "Label": 1},
    {"Subject": "Meeting Reminder", "Body": "Let's meet at 3pm today", "Label": 0},
    {"Subject": "Win a free iPhone", "Body": "Just enter your details here", "Label": 1},
    {"Subject": "Project Update", "Body": "Attached is the latest report", "Label": 0},
]

df = pd.DataFrame(data)
df["Text"] = df["Subject"] + " " + df["Body"]

# === Step 2: Vectorize text ===
vectorizer = CountVectorizer(stop_words="english")
X = vectorizer.fit_transform(df["Text"])
y = df["Label"]

# === Step 3: Train model ===
model = RandomForestClassifier()
model.fit(X, y)

# === Step 4: Prediction function ===
def predict_phishing(subject, body):
    text = subject + " " + body
    vector = vectorizer.transform([text])
    prediction = model.predict(vector)
    return "🚨 Phishing Alert!" if prediction[0] == 1 else "✅ Safe Email"

# === Step 5: Test it ===
if __name__ == "__main__":
    subject = input("Enter email subject: ")
    body = input("Enter email body: ")
    result = predict_phishing(subject, body)
    print(result)
import re

def is_suspicious_link(link):
    if re.search(r"http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", link):
        return True
    if "bit.ly" in link or "tinyurl" in link:
        return True
    suspicious_keywords = ["login", "verify", "update", "secure"]
    for keyword in suspicious_keywords:
        if keyword in link.lower():
            return True
    return False

def is_suspicious_sender(sender):
    trusted_domains = ["gmail.com", "company.com", "bankofamerica.com"]
    domain = sender.split("@")[-1]
    return domain not in trusted_domains
if __name__ == "__main__":
    subject = input("Enter email subject: ")
    body = input("Enter email body: ")
    sender = input("Enter sender email: ")
    link = input("Enter link (if any): ")

    result = predict_phishing(subject, body)
    print(result)

    if is_suspicious_sender(sender):
        print("🚨 Suspicious Sender Detected")
    else:
        print("✅ Sender Looks Safe")

    if is_suspicious_link(link):
        print("🚨 Suspicious Link Detected")
    else:
        print("✅ Link Looks Safe")
