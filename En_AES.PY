from flask import Flask, request, send_file, render_template_string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import sha256
import os

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads_encrypt'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>File Encryptor</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body {
      background: linear-gradient(135deg, #667eea, #764ba2);
      min-height: 100vh;
      color: #fff;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    .card {
      background: rgba(255, 255, 255, 0.1);
      border-radius: 1rem;
      padding: 30px;
      max-width: 450px;
      width: 100%;
      box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
      backdrop-filter: blur(8px);
      -webkit-backdrop-filter: blur(8px);
      border: 1px solid rgba(255, 255, 255, 0.18);
    }
    h2 {
      font-weight: 700;
      margin-bottom: 25px;
      text-align: center;
      color: #e0e0e0;
      text-shadow: 0 1px 3px rgba(0,0,0,0.5);
    }
    label {
      color: #ddd;
    }
    .form-text {
      color: #bbb;
    }
    .btn-primary {
      background-color: #5a67d8;
      border: none;
    }
    .btn-primary:hover {
      background-color: #434190;
    }
    .alert-success a {
      color: #2d3748;
      font-weight: 600;
    }
  </style>
</head>
<body>
  <div class="card">
    <h2>AES File Encryptor</h2>
    <form method="post" enctype="multipart/form-data" class="mb-4">
      <div class="mb-3">
        <label for="file" class="form-label">Upload file to encrypt</label>
        <input class="form-control" type="file" id="file" name="file" required>
      </div>
      <div class="mb-3">
        <label for="key" class="form-label">Enter key (any length)</label>
        <input class="form-control" type="text" id="key" name="key" required>
        <div class="form-text">Key will be hashed to AES-256 key.</div>
      </div>
      <button class="btn btn-primary w-100" type="submit">Encrypt</button>
    </form>

    {% if error %}
      <div class="alert alert-danger" role="alert">{{ error }}</div>
    {% endif %}

    {% if download_url %}
      <div class="alert alert-success" role="alert">
        <strong>Encryption done!</strong> <a href="{{ download_url }}" class="alert-link">Download encrypted file</a>
      </div>
    {% endif %}
  </div>
</body>
</html>
"""

def get_key(user_key: str) -> bytes:
    return sha256(user_key.encode('utf-8')).digest()

@app.route('/', methods=['GET', 'POST'])
def index():
    error = None
    download_url = None
    if request.method == 'POST':
        uploaded_file = request.files['file']
        user_key = request.form['key']

        if not user_key:
            error = "Key cannot be empty."
            return render_template_string(HTML_TEMPLATE, error=error)

        file_data = uploaded_file.read()
        key = get_key(user_key)

        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_data = iv + cipher.encrypt(pad(file_data, AES.block_size))

        filename = f"encrypted_{uploaded_file.filename}"
        path = os.path.join(UPLOAD_FOLDER, filename)
        with open(path, 'wb') as f:
            f.write(encrypted_data)

        download_url = f"/download/{filename}"

    return render_template_string(HTML_TEMPLATE, error=error, download_url=download_url)

@app.route('/download/<filename>')
def download(filename):
    path = os.path.join(UPLOAD_FOLDER, filename)
    return send_file(path, as_attachment=True)

if __name__ == '__main__':
    app.run(port=5001, debug=True)
