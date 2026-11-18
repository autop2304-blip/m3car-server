from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os, hashlib, json
from datetime import datetime

app = Flask(__name__)

# Import recovery kalau ada
try:
    from recovery_routes import register_recovery_routes
    register_recovery_routes(
        app,
        drivers_json_path=os.path.join(os.getcwd(), "drivers.json")
    )
except Exception as e:
    print(f"recovery_routes tidak ada: {e}")

CORS(app, resources={r"/*": {"origins": "*"}})

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

@app.route('/')
def home():
    return jsonify({"status": "Server M3 CAR Live bos!", "logo_url": "/uploads/logo.png"})

@app.route('/encrypt', methods=['GET','POST','OPTIONS'])
def encrypt():
    if request.method == 'OPTIONS':
        return '', 200
    try:
        data = request.get_json(silent=True) or {}
        pwd = data.get('password') or data.get('pwd') or request.args.get('password') or ""
        if not pwd:
            try:
                pwd = request.data.decode('utf-8')
            except:
                pwd = "test"
        encrypted = hashlib.sha256(pwd.encode()).hexdigest()
        return jsonify({"status": "ok", "encrypted": encrypted})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/upload', methods=['POST','OPTIONS'])
def upload():
    if request.method == 'OPTIONS':
        return '', 200
    file = request.files.get('file')
    if not file:
        return jsonify({"success": False, "error": "no file"}), 400
    filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
    file.save(os.path.join(UPLOAD_FOLDER, filename))
    return jsonify({"success": True, "url": f"/uploads/{filename}"})

# INI YANG BARU BUAT LOGO - PAKAI SERVER SENDIRI
@app.route('/api/upload-logo', methods=['POST','OPTIONS'])
def upload_logo():
    if request.method == 'OPTIONS':
        return '', 200
    file = request.files.get('file')
    if not file:
        return jsonify({"success": False, "error": "no file"}), 400
    file.save(os.path.join(UPLOAD_FOLDER, 'logo.png'))
    return jsonify({"success": True, "url": "/uploads/logo.png", "message": "Logo tersimpan di server sendiri"})

@app.route('/uploads/<filename>')
def get_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/api/health')
def health():
    return jsonify({"status": "live", "time": str(datetime.now())})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)