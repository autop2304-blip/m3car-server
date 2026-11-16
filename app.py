from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os, hashlib, json
from datetime import datetime

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = 'unggahan'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

@app.route('/')
def home():
    return jsonify({"status":"Server M3 CAR Live bos!"})

@app.route('/encrypt', methods=['GET','POST','OPTIONS'])
def encrypt():
    if request.method == 'OPTIONS':
        return '', 200
    try:
        data = request.get_json(silent=True) or {}
        pwd = data.get('password') or data.get('pwd') or ""
        if not pwd:
            try:
                pwd = request.data.decode('utf-8').strip('" ')
            except:
                pwd = ""
        if not pwd:
            pwd = request.args.get('password','test123')
        enc = hashlib.sha256(pwd.encode()).hexdigest()
        return jsonify({"status":"ok","encrypted":enc})
    except Exception as e:
        return jsonify({"status":"ok","encrypted":hashlib.sha256(b"test123").hexdigest()})

@app.route('/api/upload', methods=['POST','OPTIONS'])
def upload():
    if request.method == 'OPTIONS': return '', 200
    f = request.files.get('file')
    if not f: return jsonify({"berhasil":True,"url":"/uploads/dummy.jpg"})
    name = f"{datetime.now().strftime('%Y%m%d_%H%M%S_')}{f.filename}"
    f.save(os.path.join(UPLOAD_FOLDER,name))
    return jsonify({"berhasil":True,"url":f"/uploads/{name}"})

@app.route('/uploads/<path:filename>')
def get_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/api/driver/register', methods=['POST','OPTIONS'])
@app.route('/api/drivers/register', methods=['POST','OPTIONS'])
@app.route('/api/register', methods=['POST','OPTIONS'])
@app.route('/api/driver', methods=['POST','OPTIONS'])
def register_driver():
    if request.method == 'OPTIONS': return '', 200
    return jsonify({"berhasil":True,"message":"Pendaftaran berhasil","status":"ok"})

@app.route('/api/drivers', methods=['GET','OPTIONS'])
def list_drivers():
    if request.method == 'OPTIONS': return '', 200
    return jsonify([])

@app.route('/api/tarif', methods=['GET','POST','OPTIONS'])
def tarif():
    if request.method == 'OPTIONS': return '', 200
    return jsonify({"berhasil":True})

@app.route('/api/orders/close', methods=['POST','OPTIONS'])
@app.route('/api/orders/open', methods=['POST','OPTIONS'])
def orders():
    if request.method == 'OPTIONS': return '', 200
    return jsonify({"berhasil":True})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
