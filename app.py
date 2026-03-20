from flask import Flask, render_template, jsonify
import json
import os

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ALERTS_FILE = os.path.join(BASE_DIR, "alerts.json")

@app.route("/")
def index():
    """Renders the main SOC Dashboard page."""
    return render_template("index.html")

@app.route("/api/alerts")
def get_alerts():
    """API endpoint for the dashboard frontend to fetch live alerts."""
    if not os.path.exists(ALERTS_FILE):
        return jsonify([])
    try:
        with open(ALERTS_FILE, "r") as f:
            alerts = json.load(f)
            # Return alerts in reverse chronological order (newest at the top)
            return jsonify(alerts[::-1])
    except:
        return jsonify([])

if __name__ == "__main__":
    print("==================================================")
    print("🌐 Custom SIEM - Web Dashboard Started 🌐")
    print("[*] Open your browser and go to: http://127.0.0.1:5000")
    print("==================================================")
    app.run(debug=True, port=5000)
