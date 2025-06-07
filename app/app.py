from flask import Flask, render_template, request, redirect, url_for, session, send_file
import os
from werkzeug.utils import secure_filename
from endesive.pdf import cms

app = Flask(__name__)
app.secret_key = 'your_secret_key'

UPLOAD_FOLDER = 'signed_pdfs'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

users = {}

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if username in users:
            return "Username already exists!"
        users[username] = password
        return redirect(url_for("login"))
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        role = request.form["role"]

        username = request.form["username"]
        password = request.form["password"]
        if users.get(username) == password:
            session["user"] = username
            session["role"] = role
        if role == "management":
            return redirect(url_for("upload_certs"))
        return redirect(url_for("index"))
        return "Invalid credentials"
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

@app.route("/", methods=["GET", "POST"])
def index():
    if "user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        pdf = request.files["pdf"]
        cert_files = request.files.getlist("certs")
        password = request.form["password"]

        pdf_path = os.path.join(UPLOAD_FOLDER, secure_filename(pdf.filename))
        pdf.save(pdf_path)

        cert_list = []
        for idx, cert in enumerate(cert_files):
            cert_path = os.path.join(UPLOAD_FOLDER, f"cert_{idx}_{secure_filename(cert.filename)}")
            cert.save(cert_path)
            cert_list.append(cert_path)

        return render_template("select_cert.html", cert_list=cert_list, pdf_path=pdf_path, password=password)

    return render_template("index.html")

@app.route("/sign", methods=["POST"])
def sign():
    if "user" not in session:
        return redirect(url_for("login"))

    cert_path = request.form["cert_path"]
    pdf_path = request.form["pdf_path"]
    password = request.form["password"]

    with open(pdf_path, 'rb') as f:
        pdf_data = f.read()

    pdf_data = cms.sign(pdf_data, {
        'sigflags': 3,
        'contact': 'admin@example.com',
        'location': 'India',
        'signingdate': b"D:20250607120000+05'30'",
        'reason': f'Signed by {session["user"]}',
        'signaturebox': (470, 50, 570, 150),
    }, cert_path, password.encode('utf-8'))

    signed_pdf_path = pdf_path.replace(".pdf", "_signed.pdf")
    with open(signed_pdf_path, 'wb') as f:
        f.write(pdf_data)

    return send_file(signed_pdf_path, as_attachment=True)
@app.route("/upload-certs", methods=["GET", "POST"])
def upload_certs():
    if "user" not in session:
        return redirect(url_for("login"))

    user_folder = os.path.join(UPLOAD_FOLDER, session["user"])
    os.makedirs(user_folder, exist_ok=True)

    if request.method == "POST":
        cert_files = request.files.getlist("cert_files")
        for cert in cert_files:
            cert_path = os.path.join(user_folder, secure_filename(cert.filename))
            cert.save(cert_path)
        return "Certificates uploaded successfully. <a href='/'>Go back</a>"

    return render_template("upload_certs.html")

def parse_cert_info(cert_path, password=b""):
    try:
        with open(cert_path, "rb") as f:
            data = f.read()
        private_key, cert, additional_certs = pkcs12.load_key_and_certificates(data, password, backend=default_backend())
        if cert:
            subject = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            expiry = cert.not_valid_after.strftime("%Y-%m-%d")
            return subject, expiry
    except Exception as e:
        return "N/A", "Invalid or Encrypted"
    return "N/A", "Unknown"

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    user_folder = os.path.join(UPLOAD_FOLDER, session["user"])
    certs = []
    if os.path.exists(user_folder):
        for fname in os.listdir(user_folder):
            if fname.endswith(".pfx") or fname.endswith(".p12"):
                fpath = os.path.join(user_folder, fname)
                cn, expiry = parse_cert_info(fpath)
                certs.append({
                    "filename": fname,
                    "cn": cn,
                    "expiry": expiry
                })
    return render_template("dashboard.html", certs=certs)

@app.route("/delete-cert", methods=["POST"])
def delete_cert():
    if "user" not in session:
        return redirect(url_for("login"))
    filename = request.form["filename"]
    user_folder = os.path.join(UPLOAD_FOLDER, session["user"])
    cert_path = os.path.join(user_folder, filename)
    if os.path.exists(cert_path):
        os.remove(cert_path)
    return redirect(url_for("dashboard"))