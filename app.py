from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
from datetime import datetime

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/')
def home():
    return jsonify({"status": "M3 CAR Server Live 1000+ order bos!"})

@app.route('/api/upload', methods=['POST','GET','OPTIONS'])
def upload():
    try:
        file = request.files.get('file')
        if not file:
            return jsonify({"success": False}), 400
        filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
        file.save(os.path.join(UPLOAD_FOLDER, filename))
        return jsonify({"success": True, "url": f"/uploads/{filename}"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/uploads/<filename>')
def get_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/api/tarif', methods=['GET','POST','OPTIONS'])
def tarif():
    return jsonify({"success": True, "tarif": 5000})

@app.route('/api/orders/close', methods=['POST','OPTIONS'])
def order_close():
    return jsonify({"success": True, "status": "close"})

@app.route('/api/orders/far', methods=['POST','OPTIONS'])
def order_far():
    return jsonify({"success": True, "status": "far"})

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "live"})
