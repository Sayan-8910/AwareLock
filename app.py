from flask import Flask, request, render_template, send_from_directory
from zxcvbn import zxcvbn
import hashlib
import requests
import re
import random
import os

app = Flask(__name__)

# -------------------- Helper Functions --------------------

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
        "Include at least 3 special characters.": len(re.findall(r'[!@#$%^&*(),.?+-/\":{}|<>]', password)) >= 3,
    }

def generate_strong_password():
    adjectives = ["Blue", "Smart", "Fast", "Silent", "Happy", "Brave", "Clever", "Mighty", "Fierce", "Crazy"]
    nouns = ["Tiger", "Panda", "Dragon", "Eagle", "Shark", "Lion", "Wolf", "Falcon", "Bear", "Cheetah"]
    verbs = ["Runs", "Jumps", "Flies", "Climbs", "Fights", "Wins", "Rises", "Roars", "Dances", "Shines"]

    phrase = random.choice(adjectives) + random.choice(nouns) + random.choice(verbs)
    digits = "".join(random.choices("0123456789", k=2))
    specials = "".join(random.sample("!@#$%^&*+-/", 3))
    return phrase + digits + specials

# -------------------- Core Routes --------------------

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/password", methods=["GET", "POST"])
def password_page():
    if request.method == "POST":
        pwd = request.form["pwd"]
        strength = zxcvbn(pwd)
        breach_status = check_pwned(pwd)
        common_status = check_common_password(pwd)

        guesses = strength["guesses"]
        crack_times_display = strength["crack_times_display"]
        crack_times_seconds = strength["crack_times_seconds"]

        policy_results = validate_password_policy(pwd)
        feedback_lines = [("✅" if passed else "❌") + " " + rule for rule, passed in policy_results.items()]
        policy_feedback = "\n".join(feedback_lines)

        suggested_password = None
        if not all(policy_results.values()):
            suggested_password = generate_strong_password()

        return render_template(
            "password.html",
            strength=strength,
            breach_status=breach_status,
            common_status=common_status,
            policy_feedback=policy_feedback,
            suggested_password=suggested_password,
            guesses=guesses,
            crack_times_display=crack_times_display,
            crack_times_seconds=crack_times_seconds
        )
    return render_template("password.html")

@app.route("/suggest")
def suggest_password():
    return generate_strong_password()

# -------------------- Awareness Modules --------------------

@app.route("/simulations")
def simulations():
    return render_template("simulations.html")

@app.route("/simulations/qr-scam")
def qr_scam_demo():
    return render_template("qr_scam.html")

@app.route("/simulations/invest-scam")
def invest_scam_demo():
    return render_template("invest_scam.html")

@app.route("/simulations/digital-arrest-scam")
def digital_arrest_scam_demo():
    return render_template("digital_arscam.html")
@app.route("/learn-reporting")
def learn_reporting():
    return render_template("learn&report.html")

@app.route("/aware_score")
def aware_score():
    return render_template("aware_score.html")

@app.route("/simulations/sms")
def sms_spyware_demo():
    return render_template("sms_spyware.html")

@app.route("/kyc-update")
def kyc_fake_page():
    return render_template("kyc_fake.html")

@app.route("/voucher")
def voucher_fake_page():
    return render_template("voucher_fake.html")

@app.route("/login")
def login_fake_page():
    return render_template("login_fake.html")

@app.route("/delivery")
def delivery_fake_page():
    return render_template("delivery_fake.html")


@app.route("/score")
def score():
    return render_template("score.html")

@app.route("/resources")
def resources():
    return render_template("resources.html")

@app.route("/phishing")
def phishing():
    return render_template("phishing.html")


# -------------------- Verification & SEO --------------------

@app.route('/googlef24112691c94f445.html')
def serve_google_verification():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'googlef24112691c94f445.html')

@app.route('/sitemap.xml')
def sitemap():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'sitemap.xml')

# -------------------- Main Entry --------------------

if __name__ == "__main__":
    app.debug = True  # Optional: enable debug mode for development
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)