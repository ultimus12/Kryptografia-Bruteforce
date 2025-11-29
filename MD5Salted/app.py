import sqlite3
import hashlib
import os
from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)
app.secret_key = "inny_sekretny_klucz"
DATABASE = 'db_salted.db'

# PEPPER: Stała wartość ukryta w kodzie (nie w bazie danych)
PEPPER = "TajnySkladnik_Chroniac_Przed_RainbowTables"

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # Tabela przechowuje hash ORAZ unikalną sól dla każdego usera
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users_salted (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL
            );
        ''')
        db.commit()
        db.close()
        print(f"[{DATABASE}] Baza danych zainicjalizowana (MD5 + Salt + Pepper).")

# --- TRASY ---

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # 1. Generujemy losową sól (16 bajtów zamienione na hex)
        user_salt = os.urandom(16).hex()

        # 2. Tworzymy silniejszy ciąg: Hasło + Sól + Pieprz
        combined_data = password + user_salt + PEPPER
        
        # 3. Hashujemy całość (nadal MD5, ale wsad jest unikalny)
        hashed_password = hashlib.md5(combined_data.encode()).hexdigest()

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users_salted (username, password_hash, salt) VALUES (?, ?, ?)",
                (username, hashed_password, user_salt)
            )
            db.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            error = "Użytkownik już istnieje."
        finally:
            db.close()
            
    return render_template('register.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        user = db.execute("SELECT * FROM users_salted WHERE username = ?", (username,)).fetchone()
        db.close()

        if user:
            # 1. Pobieramy sól z bazy danych dla tego konkretnego użytkownika
            stored_salt = user['salt']
            stored_hash = user['password_hash']
            
            # 2. Odtwarzamy proces hashowania
            check_combined = password + stored_salt + PEPPER
            check_hash = hashlib.md5(check_combined.encode()).hexdigest()
            
            if check_hash == stored_hash:
                return f"GRATULACJE! Zalogowano użytkownika {username} (Metoda: MD5 + Salt + Pepper)."
            else:
                error = "Błędne hasło"
        else:
            error = "Brak użytkownika"

    return render_template('login.html', error=error)

if __name__ == '__main__':
    init_db()
    # Uruchamiamy na porcie 5002
    app.run(debug=True, port=5002)