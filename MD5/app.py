import sqlite3
import hashlib
import binascii
import os
from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)
app.secret_key = "sekret"
DATABASE = 'db_weak.db'

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users_weak (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            );
        ''')
        db.commit()
        db.close()
        print("--- Baza danych gotowa ---")

def smart_hash(password_input):
    """
    Wersja ulepszona: usuwa białe znaki i informuje w konsoli co robi.
    """
    # 1. Usuwamy spacje i entery z początku/końca
    clean_input = password_input.strip()
    
    # 2. Logika wykrywania HEX
    try:
        # Sprawdzamy czy wygląda jak długi hex string
        if len(clean_input) > 64: 
            binary_data = binascii.unhexlify(clean_input)
            
            # Jeśli tu doszliśmy, to znaczy że to poprawny HEX!
            print(f"[DEBUG] Wykryto tryb HEX! Długość bajtów: {len(binary_data)}")
            final_hash = hashlib.md5(binary_data).hexdigest()
            print(f"[DEBUG] Wyliczony hash MD5: {final_hash}")
            return final_hash
            
    except (binascii.Error, ValueError) as e:
        print(f"[DEBUG] To NIE jest poprawny hex (Błąd: {e}). Hashuję jako tekst.")
    
    # 3. Fallback: Hashowanie zwykłego tekstu (dla Hydry itp.)
    return hashlib.md5(password_input.encode()).hexdigest()

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = smart_hash(password)

        db = get_db()
        try:
            db.execute("INSERT INTO users_weak (username, password_hash) VALUES (?, ?)", (username, hashed_password))
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
        
        print(f"\n--- PRÓBA LOGOWANIA USERA: {username} ---")
        input_hash = smart_hash(password)
        
        db = get_db()
        user = db.execute("SELECT * FROM users_weak WHERE username = ?", (username,)).fetchone()
        db.close()

        if user:
            print(f"[DEBUG] Hash w bazie: {user['password_hash']}")
            print(f"[DEBUG] Hash wejścia: {input_hash}")
            
            if user['password_hash'] == input_hash:
                print("[SUKCES] Hashe pasują!")
                return f"<h1 style='color:green; text-align:center; margin-top:50px;'>WŁAMANIE UDANE! (KOLIZJA MD5)</h1><p style='text-align:center'>Zalogowano jako: {username}</p>"
            else:
                print("[FAIL] Hashe są różne.")
                error = "Błędne hasło"
        else:
            error = "Brak użytkownika"

    return render_template('login.html', error=error)

if __name__ == '__main__':
    # Usuwamy starą bazę żeby nie było śmieci
    if os.path.exists(DATABASE):
        os.remove(DATABASE)
    init_db()
    app.run(debug=True, port=5001)