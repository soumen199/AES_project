from flask import Flask, render_template, request, redirect, url_for, session
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Temporary storage for user data
users = {}

# PKCS7 padding function
def pad(text):
    block_size = AES.block_size
    padding = block_size - len(text) % block_size
    return text + bytes([padding] * padding)

# PKCS7 unpadding function
def unpad(text):
    padding = text[-1]
    return text[:-padding]

# Encryption function using CBC mode
def encrypt(plaintext, key):
    iv = get_random_bytes(16)  # Initialization Vector (IV)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode()))
    return iv + ciphertext

# Decryption function using CBC mode
def decrypt(ciphertext, key):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext))
    return plaintext.decode()

@app.route('/')
def index():
    if 'username' in session:
        user = users[session['username']]
        return render_template('index.html', notes=user['notes'])
    else:
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username]['password'] == password:
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return "Invalid login credentials."
    return render_template('login.html')

@app.route('/add_note', methods=['POST'])
def add_note():
    if 'username' in session:
        user = users[session['username']]
        note = request.form['note']
        encrypted_note = encrypt(note, user['password'])
        user['notes'].append(encrypted_note)
    return redirect(url_for('index'))

@app.route('/view_note/<int:index>')
def view_note(index):
    if 'username' in session:
        user = users[session['username']]
        if 0 <= index < len(user['notes']):
            decrypted_note = decrypt(user['notes'][index], user['password'])
            return decrypted_note
    return "Note not found."

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)

