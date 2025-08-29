from flask import Flask, request, render_template
from flask import send_from_directory
from zxcvbn import zxcvbn
import hashlib
import requests
import re
import random
import string
import os
import requests

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
    # Word lists for phrase
    adjectives = ["Blue", "Smart", "Fast", "Silent", "Happy", "Brave", "Clever", "Mighty", "Fierce", "Crazy"]
    nouns = ["Tiger", "Panda", "Dragon", "Eagle", "Shark", "Lion", "Wolf", "Falcon", "Bear", "Cheetah"]
    verbs = ["Runs", "Jumps", "Flies", "Climbs", "Fights", "Wins", "Rises", "Roars", "Dances", "Shines"]

    # Generate phrase
    phrase = random.choice(adjectives) + random.choice(nouns) + random.choice(verbs)

    # Add requirements
    digits = "".join(random.choices("0123456789", k=2))
    specials = "".join(random.sample("!@#$%^&*+-/", 3))

    # Final password (no extra randomness)
    password = phrase + digits + specials 
    return password

# -------------------- Routes --------------------

@app.route("/", methods=["GET", "POST"])
def check_password():
    if request.method == "POST":
        pwd = request.form["pwd"]
        strength = zxcvbn(pwd)
        breach_status = check_pwned(pwd)
        common_status = check_common_password(pwd)

        # Extract entropy & crack-time details
        guesses = strength["guesses"]
        crack_times_display = strength["crack_times_display"]
        crack_times_seconds = strength["crack_times_seconds"]

        # Apply policy checks
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
            suggested_password=suggested_password,
            guesses=guesses,
            crack_times_display=crack_times_display,
            crack_times_seconds=crack_times_seconds
        )
    return render_template("index.html")


@app.route("/suggest")
def suggest_password():
    return generate_strong_password()

@app.route('/')
def home():
    return render_template('index.html')

@app.route("/how-it-works")
def how_it_works():
    return render_template("how_it_works.html")

@app.route('/googlef24112691c94f445.html')
def serve_google_verification():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'googlef24112691c94f445.html') 

@app.route('/sitemap.xml')  
def sitemap():  
    return send_from_directory(
        os.path.join(app.root_path, 'static'),  # The folder where sitemap.xml is stored
        'sitemap.xml'  # The file name
    )


# -------------------- Main Entry --------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
