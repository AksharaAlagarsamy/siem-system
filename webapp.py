from flask import Flask, jsonify
import pandas as pd
from sklearn.ensemble import IsolationForest

app = Flask(__name__)

@app.route("/")
def home():
    data = {"event_count": [10, 12, 9, 300, 8, 400]}
    df = pd.DataFrame(data)

    model = IsolationForest(contamination=0.2)
    df["anomaly"] = model.fit_predict(df)

    return jsonify(df.to_dict())

if __name__ == "__main__":
    app.run(debug=True)
