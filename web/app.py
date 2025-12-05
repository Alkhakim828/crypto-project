
import sys, os, tempfile
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from flask import Flask, request, send_file, render_template
import uuid
from src.crypto.manager import encrypt_file, decrypt_file, sign_file, verify_signature

app = Flask(__name__)
TMP = tempfile.gettempdir()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/encrypt", methods=["POST"])
def encrypt():
    try:
        f = request.files["file"]
        password = request.form.get("password")
        inpath = os.path.join(TMP, str(uuid.uuid4()))
        outpath = os.path.join(TMP, str(uuid.uuid4()) + ".bin")
        f.save(inpath)
        encrypt_file(inpath, outpath, "keys/public.pem", password)
        return send_file(outpath, as_attachment=True)
    except Exception as e:
        return render_template("index.html", error="Encryption failed: " + str(e))

@app.route("/decrypt", methods=["POST"])
def decrypt():
    try:
        f = request.files["file"]
        password = request.form.get("password")
        inpath = os.path.join(TMP, str(uuid.uuid4()))
        outpath = os.path.join(TMP, str(uuid.uuid4()))
        f.save(inpath)
        decrypt_file(inpath, outpath, "keys/private.pem", password)
        return send_file(outpath, as_attachment=True)
    except Exception:
        return render_template("index.html", error="Decryption failed: incorrect password or corrupted file.")

@app.route("/sign", methods=["POST"])
def sign():
    try:
        f = request.files["file"]
        inpath = os.path.join(TMP, str(uuid.uuid4()))
        sigpath = os.path.join(TMP, str(uuid.uuid4()) + ".sig")
        f.save(inpath)
        sign_file(inpath, sigpath, "keys/private.pem")
        return send_file(sigpath, as_attachment=True)
    except Exception as e:
        return render_template("index.html", error="Signing failed: " + str(e))

@app.route("/verify", methods=["POST"])
def verify():
    try:
        f = request.files["file"]
        s = request.files["signature"]
        inpath = os.path.join(TMP, str(uuid.uuid4()))
        sigpath = os.path.join(TMP, str(uuid.uuid4()))
        f.save(inpath)
        s.save(sigpath)
        ok = verify_signature(inpath, sigpath, "keys/public.pem")
        return render_template("index.html", verify_result=("VALID" if ok else "INVALID"))
    except Exception as e:
        return render_template("index.html", error="Verification failed: " + str(e))

if __name__ == "__main__":
    app.run(port=5000)
