import os
import hashlib
from datetime import datetime
from flask import Flask, request, render_template, send_from_directory, redirect, url_for, session, flash
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
CORS(app)

app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = 'uploads'
PRIVATE_KEYS_FOLDER = 'private_keys'
PUBLIC_KEYS_FOLDER = 'public_keys'
for folder in [UPLOAD_FOLDER, PRIVATE_KEYS_FOLDER, PUBLIC_KEYS_FOLDER]:
    os.makedirs(folder, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['PRIVATE_KEYS_FOLDER'] = PRIVATE_KEYS_FOLDER
app.config['PUBLIC_KEYS_FOLDER'] = PUBLIC_KEYS_FOLDER

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    has_keys = db.Column(db.Boolean, default=False)
    files_uploaded = db.relationship('File', foreign_keys='File.uploader_id', backref='uploader', lazy=True)
    files_received = db.relationship('File', foreign_keys='File.recipient_id', backref='recipient', lazy=True)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_sha256 = db.Column(db.String(64), nullable=False)
    signature = db.Column(db.LargeBinary, nullable=False)
    sent_to_username = db.Column(db.String(80), nullable=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

# ---------------------- Utility Functions --------------------------
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    return private_key, private_key.public_key()

def save_private_key(private_key, username):
    path = os.path.join(PRIVATE_KEYS_FOLDER, f'{username}_private.pem')
    with open(path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

def save_public_key(public_key, username):
    path = os.path.join(PUBLIC_KEYS_FOLDER, f'{username}_public.pem')
    with open(path, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_private_key(username):
    path = os.path.join(PRIVATE_KEYS_FOLDER, f'{username}_private.pem')
    if not os.path.exists(path): return None
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

def load_public_key(username):
    path = os.path.join(PUBLIC_KEYS_FOLDER, f'{username}_public.pem')
    if not os.path.exists(path): return None
    with open(path, 'rb') as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())

def sign_data(private_key, data_hash):
    return private_key.sign(
        data_hash.encode('utf-8'),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def verify_signature(public_key, data_hash, signature):
    try:
        public_key.verify(
            signature,
            data_hash.encode('utf-8'),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def calculate_sha256(file_path):
    sha = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for block in iter(lambda: f.read(4096), b""):
            sha.update(block)
    return sha.hexdigest()

def ensure_user_keys_exist(user):
    if not os.path.exists(os.path.join(PRIVATE_KEYS_FOLDER, f'{user.username}_private.pem')):
        private_key, public_key = generate_rsa_keys()
        save_private_key(private_key, user.username)
        save_public_key(public_key, user.username)
        user.has_keys = True
        db.session.commit()

# ---------------------- Database Initialization --------------------------
def init_db():
    with app.app_context():
        db.create_all()

# ---------------------- Routes --------------------------
@app.route('/')
def index():
    if 'user_id' not in session: return redirect('/login')
    user = User.query.get(session['user_id'])
    ensure_user_keys_exist(user)
    user_files = File.query.filter_by(uploader_id=user.id).all()
    received_files = File.query.filter_by(recipient_id=user.id).all()
    all_users = [u.username for u in User.query.filter(User.id != user.id).all() if u.has_keys]
    return render_template('index.html', username=user.username, has_keys=user.has_keys, 
                         user_files=user_files, received_files=received_files, 
                         public_keys_available=all_users)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password_hash, request.form['password']):
            session['user_id'] = user.id
            return redirect('/')
        flash('Sai tài khoản hoặc mật khẩu!', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if User.query.filter_by(username=request.form['username']).first():
            flash('Tên tài khoản đã tồn tại!', 'danger')
        else:
            user = User(username=request.form['username'], password_hash=generate_password_hash(request.form['password']))
            db.session.add(user)
            db.session.commit()
            flash('Tạo tài khoản thành công!', 'success')
            return redirect('/login')
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Đăng xuất thành công!', 'info')
    return redirect('/login')

@app.route('/generate_my_keys', methods=['POST'])
def generate_my_keys():
    if 'user_id' not in session: return redirect('/login')
    user = User.query.get(session['user_id'])
    
    # Generate keys
    private_key, public_key = generate_rsa_keys()
    save_private_key(private_key, user.username)
    save_public_key(public_key, user.username)
    
    # Update user record
    user.has_keys = True
    db.session.commit()
    
    flash('Tạo khóa RSA thành công!', 'success')
    return redirect('/')

@app.route('/upload', methods=['POST'])
def upload():
    if 'user_id' not in session: return redirect('/login')
    user = User.query.get(session['user_id'])
    file = request.files.get('file')
    if not file: 
        flash('Vui lòng chọn file!', 'danger')
        return redirect('/')
    
    # Save file
    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)
    
    # Calculate hash and create signature
    sha256 = calculate_sha256(filepath)
    signature = sign_data(load_private_key(user.username), sha256)
    
    # Save to database
    f = File(filename=filename, original_filename=file.filename, uploader_id=user.id, 
             file_sha256=sha256, signature=signature)
    db.session.add(f)
    db.session.commit()
    
    flash('File đã được ký và tải lên!', 'success')
    return redirect('/')

@app.route('/send_file/<int:file_id>', methods=['POST'])
def send_file(file_id):
    if 'user_id' not in session: return redirect('/login')
    
    file = File.query.get_or_404(file_id)
    recipient_username = request.form['recipient_username']
    recipient = User.query.filter_by(username=recipient_username).first()
    
    if not recipient:
        flash('Người nhận không tồn tại!', 'danger')
        return redirect('/')
    
    # Update file record
    file.sent_to_username = recipient_username
    file.recipient_id = recipient.id
    db.session.commit()
    
    flash(f'File đã được gửi đến {recipient_username}!', 'success')
    return redirect('/')

@app.route('/download/<filename>')
def download(filename):
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)

@app.route('/serve_public_key/<filename>')
def serve_public_key(filename):
    return send_from_directory(PUBLIC_KEYS_FOLDER, filename, as_attachment=True)

@app.route('/verify/<int:file_id>')
def verify(file_id):
    file = File.query.get_or_404(file_id)
    public_key = load_public_key(file.uploader.username)
    
    if not public_key:
        flash('Không tìm thấy khóa công khai!', 'danger')
        return redirect('/')
    
    # Verify file integrity and signature
    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    if not os.path.exists(filepath):
        flash('File không tồn tại!', 'danger')
        return redirect('/')
    
    actual_sha256 = calculate_sha256(filepath)
    signature_valid = verify_signature(public_key, file.file_sha256, file.signature)
    
    if signature_valid and file.file_sha256 == actual_sha256:
        flash('Xác minh thành công! File hợp lệ và chữ ký đúng.', 'success')
    else:
        flash('Xác minh thất bại! File có thể đã bị thay đổi hoặc chữ ký không hợp lệ.', 'danger')
    
    return redirect('/')

if __name__ == '__main__':
    init_db()  # Initialize database before running
    app.run(debug=True)