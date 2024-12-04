import os
import base64
from flask import Flask, request, send_file, render_template, jsonify, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import mimetypes
import sqlite3

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Important for session management

# Configuration
UPLOAD_FOLDER = 'uploads'
DATABASE = 'users.db'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Login Manager Setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# User Model
class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

def init_db():
    """Initialize database and create tables"""
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_descriptions (
                filename TEXT PRIMARY KEY,
                description TEXT,
                user_id INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        conn.commit()

def get_db_connection():
    """Create a database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

@login_manager.user_loader
def load_user(user_id):
    """User loader for Flask-Login"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return User(user['id'], user['username'], user['password_hash'])
    return None

def get_file_details(filepath, user_id):
    """Get details of a file from its path"""
    filename = os.path.basename(filepath)
    
    # Check if file is previewable
    previewable_types = [
        'image/jpeg', 'image/png', 'image/gif', 'image/webp',
        'text/plain', 'application/pdf',
        'text/html', 'text/csv', 'application/json'
    ]
    
    # Determine mime type
    mime_type = mimetypes.guess_type(filepath)[0] or 'application/octet-stream'
    
    # Get description from database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT description FROM file_descriptions WHERE filename = ? AND user_id = ?", (filename, user_id))
    description_row = cursor.fetchone()
    description = description_row['description'] if description_row else ''
    conn.close()
    
    return {
        'filename': filename,
        'filepath': filepath,
        'description': description,
        'upload_date': datetime.fromtimestamp(os.path.getctime(filepath)).isoformat(),
        'filesize': os.path.getsize(filepath),
        'mime_type': mime_type,
        'is_previewable': mime_type in previewable_types
    }

@app.route('/')
@login_required
def index():
    """Render the main page"""
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login route"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            flask_user = User(user['id'], user['username'], user['password_hash'])
            login_user(flask_user)
            return redirect(url_for('index'))
        
        flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if username already exists
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            flash('Username already exists')
            conn.close()
            return render_template('register.html')
        
        # Hash the password
        password_hash = generate_password_hash(password)
        
        # Insert new user
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", 
                       (username, password_hash))
        conn.commit()
        conn.close()
        
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    """Logout route"""
    logout_user()
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    """Handle file upload"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    description = request.form.get('description', '')
    
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    # Secure the filename to prevent directory traversal
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    # Save the file
    file.save(filepath)
    
    # Save description in database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO file_descriptions 
        (filename, description, user_id) VALUES (?, ?, ?)
    """, (filename, description, current_user.id))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'File uploaded successfully'}), 200

@app.route('/files', methods=['GET'])
@login_required
def list_files():
    """Retrieve list of uploaded files for the current user"""
    files = []
    for filename in os.listdir(UPLOAD_FOLDER):
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        
        # Skip description files
        if filepath.endswith('.desc'):
            continue
        
        # Skip if it's not a file
        if not os.path.isfile(filepath):
            continue
        
        # Get file details
        file_details = get_file_details(filepath, current_user.id)
        
        files.append(file_details)
    
    # Sort files by upload date (most recent first)
    files.sort(key=lambda x: x['upload_date'], reverse=True)
    
    return jsonify(files)

@app.route('/download/<path:filename>')
@login_required
def download_file(filename):
    """Download a specific file"""
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    
    # Verify the file exists and belongs to the current user
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM file_descriptions WHERE filename = ? AND user_id = ?", 
                   (filename, current_user.id))
    file_record = cursor.fetchone()
    conn.close()
    
    if not file_record or not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404
    
    mime_type = mimetypes.guess_type(filepath)[0] or 'application/octet-stream'
    
    return send_file(
        filepath, 
        download_name=filename, 
        as_attachment=True,
        mimetype=mime_type
    )

@app.route('/view/<path:filename>')
@login_required
def view_file(filename):
    """View file contents"""
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    
    # Verify the file belongs to the current user
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM file_descriptions WHERE filename = ? AND user_id = ?", 
                   (filename, current_user.id))
    file_record = cursor.fetchone()
    conn.close()
    
    if not file_record or not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404
    
    # Previewable image types
    image_types = ['image/jpeg', 'image/png', 'image/gif', 'image/webp']
    
    # Text-based file types
    text_types = [
        'text/plain', 'text/html', 'text/csv', 
        'application/json', 'application/xml'
    ]
    
    mime_type = mimetypes.guess_type(filepath)[0] or 'application/octet-stream'
    
    try:
        # For image files
        if mime_type in image_types:
            with open(filepath, 'rb') as f:
                encoded_image = base64.b64encode(f.read()).decode('utf-8')
            return jsonify({
                'type': 'image',
                'content': encoded_image,
                'mime_type': mime_type
            })
        
        # For text-based files
        elif mime_type in text_types:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            return jsonify({
                'type': 'text',
                'content': content,
                'mime_type': mime_type
            })
        
        # For PDF files
        elif mime_type == 'application/pdf':
            with open(filepath, 'rb') as f:
                encoded_pdf = base64.b64encode(f.read()).decode('utf-8')
            return jsonify({
                'type': 'pdf',
                'content': encoded_pdf
            })
        
        # Unsupported file type
        return jsonify({
            'type': 'unsupported',
            'message': 'File type not supported for preview'
        }), 400
    
    except Exception as e:
        return jsonify({
            'type': 'error',
            'message': str(e)
        }), 500

@app.route('/delete/<path:filename>', methods=['DELETE'])
@login_required
def delete_file(filename):
    """Delete a file"""
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    
    # Verify the file belongs to the current user
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM file_descriptions WHERE filename = ? AND user_id = ?", 
                   (filename, current_user.id))
    file_record = cursor.fetchone()
    conn.close()
    
    if not file_record:
        return jsonify({'error': 'File not found'}), 404
    
    # Remove file from filesystem
    try:
        os.remove(filepath)
        
        # Remove description from database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM file_descriptions WHERE filename = ? AND user_id = ?", 
                       (filename, current_user.id))
        conn.commit()
        conn.close()
    except FileNotFoundError:
        return jsonify({'error': 'File not found'}), 404
    
    return jsonify({'message': 'File deleted successfully'}), 200

if __name__ == '__main__':
    init_db()  # Initialize database before running
    app.run(debug=True)