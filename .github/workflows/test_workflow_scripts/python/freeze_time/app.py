import os
from datetime import datetime, timezone

from flask import Flask, jsonify


app = Flask(__name__)


@app.get("/health")
def health():
    return "ok", 200


@app.get("/now")
def now():
    current = datetime.now(timezone.utc)
    expected_raw = os.getenv("EXPECTED_RECORD_NOW")
    if expected_raw:
        expected = datetime.fromisoformat(expected_raw)
        delta = abs((current - expected).total_seconds())
        if delta > 2:
            return jsonify({
                "now": current.isoformat(timespec="microseconds"),
                "expected": expected.isoformat(timespec="microseconds"),
                "deltaSeconds": delta,
            }), 500
    return jsonify({"now": current.isoformat(timespec="microseconds")})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8091)
