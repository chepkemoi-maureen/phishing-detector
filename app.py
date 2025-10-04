from flask import Flask, render_template_string, request
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.ensemble import RandomForestClassifier
import re

app = Flask(__name__)

# === Training the model ===
data = [
    {"Subject": "Urgent: Account Suspended", "Body": "Click here to verify your account", "Label": 1},
    {"Subject": "Meeting Reminder", "Body": "Let's meet at 3pm today", "Label": 0},
    {"Subject": "Win a free iPhone", "Body": "Just enter your details here", "Label": 1},
    {"Subject": "Project Update", "Body": "Attached is the latest report", "Label": 0},
]
df = pd.DataFrame(data)
df["Text"] = df["Subject"] + " " + df["Body"]
vectorizer = CountVectorizer(stop_words="english")
X = vectorizer.fit_transform(df["Text"])
y = df["Label"]
model = RandomForestClassifier()
model.fit(X, y)

# === Helper functions ===
def predict_phishing(subject, body):
    text = subject + " " + body
    vector = vectorizer.transform([text])
    prediction = model.predict(vector)
    return "Phishing" if prediction[0] == 1 else "Safe"

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
HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Phishing Detector</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
  <div class="container mt-5">
    <div class="card shadow">
      <div class="card-body">
        <h2 class="card-title text-center mb-4">Phishing Detector</h2>
        <form method="post">
          <div class="mb-3">
            <label class="form-label">Subject</label>
            <input type="text" name="subject" class="form-control" required>
          </div>
          <div class="mb-3">
            <label class="form-label">Body</label>
            <textarea name="body" rows="4" class="form-control" required></textarea>
          </div>
          <div class="mb-3">
            <label class="form-label">Sender Email</label>
            <input type="text" name="sender" class="form-control" required>
          </div>
          <div class="mb-3">
            <label class="form-label">Link (if any)</label>
            <input type="text" name="link" class="form-control">
          </div>
          <button type="submit" class="btn btn-primary w-100">Analyze</button>
        </form>

        {% if result %}
        <div class="mt-4">
          <h4>Result:</h4>
          <ul class="list-group">
            <li class="list-group-item">Email: <strong>{{ result }}</strong></li>
            <li class="list-group-item">Sender: <strong>{{ sender_flag }}</strong></li>
            <li class="list-group-item">Link: <strong>{{ link_flag }}</strong></li>
          </ul>
        </div>
        {% endif %}
      </div>
    </div>
  </div>
</body>
</html>
"""
def is_suspicious_sender(sender):
    trusted_domains = ["gmail.com", "company.com", "bankofamerica.com"]
    domain = sender.split("@")[-1]
    return domain not in trusted_domains

# === Web interface ===
HTML = """
<!doctype html>
<title>Phishing Detector</title>
<h2>Phishing Detector</h2>
<form method=post>
  Subject: <input type=text name=subject><br><br>
  Body: <textarea name=body rows=4 cols=50></textarea><br><br>
  Sender Email: <input type=text name=sender><br><br>
  Link (if any): <input type=text name=link><br><br>
  <input type=submit value=Analyze>
</form>
{% if result %}
  <h3>Result:</h3>
  <ul>
    <li>Email: {{ result }}</li>
    <li>Sender: {{ sender_flag }}</li>
    <li>Link: {{ link_flag }}</li>
  </ul>
{% endif %}
"""

@app.route("/", methods=["GET", "POST"])
def home():
    result = sender_flag = link_flag = None
    if request.method == "POST":
        subject = request.form["subject"]
        body = request.form["body"]
        sender = request.form["sender"]
        link = request.form["link"]

        result = predict_phishing(subject, body)
        sender_flag = "Suspicious" if is_suspicious_sender(sender) else "Safe"
        link_flag = "Suspicious" if is_suspicious_link(link) else "Safe"

    return render_template_string(HTML, result=result, sender_flag=sender_flag, link_flag=link_flag)

if __name__ == "__main__":
    app.run(debug=True)
