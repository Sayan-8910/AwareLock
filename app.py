from flask import Flask, request, render_template
from zxcvbn import zxcvbn
import hashlib
import requests
import re
import random
import string
import os

app = Flask(__name__)

def check_pwned(password):
    sha1pwd = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1pwd[:5]
    suffix = sha1pwd[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    res = requests.get(url)

    if res.status_code != 200:
        return "⚠️ Error checking breach status."

    hashes = (line.split(':') for line in res.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return f"⚠️ Found in breaches {count} times!"
    return "✅ Not found in known breaches."

def check_common_password(password):
    try:
        with open("rockyou.txt", "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                if password.strip() == line.strip():
                    return "⚠️ This is a very common password!"
        return "✅ Not found in common password list."
    except FileNotFoundError:
        return "⚠️ rockyou.txt not found."

def validate_password_policy(password):
    return {
        "Password must be at least 10 characters long.": len(password) >= 10,
        "Include at least 2 uppercase letters.": len(re.findall(r'[A-Z]', password)) >= 2,
        "Include at least 2 lowercase letters.": len(re.findall(r'[a-z]', password)) >= 2,
        "Include at least 2 digits.": len(re.findall(r'\d', password)) >= 2,
        "Include at least 2 special characters.": len(re.findall(r'[!@#$%^&*(),.?\":{}|<>]', password)) >= 2,
        "Include at least 2 operators (+ - * / =).": len(re.findall(r'[+\-*/=]', password)) >= 2
    }

def generate_strong_password(length=12):
    if length < 10:
        length = 12
    uppercase = random.choices(string.ascii_uppercase, k=2)
    lowercase = random.choices(string.ascii_lowercase, k=2)
    digits = random.choices(string.digits, k=2)
    specials = random.choices('!@#$%^&*(),.?":{}|<>', k=2)
    operators = random.choices('+-*/=', k=2)
    remaining = random.choices(string.ascii_letters + string.digits + '!@#$%^&*()+-*/=', k=length - 10)
    password_chars = uppercase + lowercase + digits + specials + operators + remaining
    random.shuffle(password_chars)
    return ''.join(password_chars)

@app.route("/", methods=["GET", "POST"])
def check_password():
    if request.method == "POST":
        pwd = request.form["pwd"]
        strength = zxcvbn(pwd)
        breach_status = check_pwned(pwd)
        common_status = check_common_password(pwd)

        policy_results = validate_password_policy(pwd)
        feedback_lines = []
        for rule, passed in policy_results.items():
            symbol = "✅" if passed else "❌"
            feedback_lines.append(f"{symbol} {rule}")
        policy_feedback = "\n".join(feedback_lines)

        suggested_password = None
        if not all(policy_results.values()):
            suggested_password = generate_strong_password()

        return render_template(
            "index.html",
            strength=strength,
            breach_status=breach_status,
            common_status=common_status,
            policy_feedback=policy_feedback,
            suggested_password=suggested_password
        )
    return render_template("index.html")

@app.route("/suggest")
def suggest_password():
    return generate_strong_password()



if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
