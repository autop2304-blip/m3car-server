from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import hashlib
from datetime import datetime

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

UPLOAD_FOLDER = 'unggahan'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/')
def berada():
    return jsonify({"status":"Server M3 CAR Live 1000+ pesanan bos!"})

# INI YANG BIKIN ERROR TADI BOS! PINTU ENKRIPSI BOS!
@app.route('/encrypt', methods=['POST','GET','OPTIONS'])
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
                pwd = ""
        if not pwd:
            pwd = "test123"
        encrypted = hashlib.sha256(pwd.encode()).hexdigest()
        return jsonify({"status":"ok","encrypted":encrypted})
    except Exception as e:
        return jsonify({"status":"error","message":str(e)}), 500

@app.route('/api/upload', methods=['POST','GET','OPTIONS'])
def unggah():
    try:
        berkas = request.files.get('file')
        if not berkas:
            return jsonify({"berhasil":False}),400
        nama_file = f"{datetime.now().strftime('%Y%m%d_%H%M%S_')}{berkas.filename}"
        berkas.save(os.path.join(UPLOAD_FOLDER,nama_file))
        return jsonify({"berhasil":True,"url":f"/uploads/{nama_file}"})
    except Exception as e:
        return jsonify({"berhasil":False,"kesalahan":str(e)}),500

@app.route('/uploads/<filename>')
def get_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/api/tarif', methods=['GET','POST','OPTIONS'])
def tarif():
    return jsonify({"berhasil":True,"tarif":5000})

@app.route('/api/orders/close', methods=['POST','OPTIONS'])
def order_close():
    return jsonify({"berhasil":True})

@app.route('/api/orders/open', methods=['POST','OPTIONS'])
def order_open():
    return jsonify({"berhasil":True})

@app.route('/health')
def health():
    return jsonify({"status":"ok"})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
