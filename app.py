from flask import Flask, render_template, request, jsonify
from detector.engine import analyze, MAX_MESSAGE_LENGTH

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze_route():
    """
    Accept a JSON body  {"message": "..."}  and return analysis results.

    Messages are processed locally and are never stored or forwarded.
    """
    data = request.get_json(silent=True)

    if not data or not isinstance(data.get("message"), str):
        return jsonify({"error": "No message provided."}), 400

    message = data["message"].strip()

    if not message:
        return jsonify({"error": "Message is empty. Please paste some text."}), 400

    if len(message) > MAX_MESSAGE_LENGTH:
        return jsonify(
            {"error": f"Message is too long (max {MAX_MESSAGE_LENGTH:,} characters)."}
        ), 400

    result = analyze(message)
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True)
