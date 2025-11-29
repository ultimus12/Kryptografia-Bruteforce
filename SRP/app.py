import sqlite3
import srp
import binascii
import os
from flask import Flask, request, jsonify, session

app = Flask(__name__)
app.secret_key = os.urandom(24)
DATABASE = 'db_srp_final.db'

# Pamięć podręczna dla trwających sesji logowania (Handshake jest wieloetapowy)
# W produkcji użyłbyś tu Redisa, tutaj wystarczy słownik w pamięci RAM.
# Klucz: username, Wartość: obiekt SRP Verifier
LOGIN_SESSIONS = {}

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    with app.app_context():
        db = get_db()
        # Tabela nie ma kolumny password! Tylko salt i verifier.
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                salt TEXT NOT NULL,
                verifier TEXT NOT NULL
            );
        ''')
        db.commit()

# --- 1. REJESTRACJA ZERO KNOWLEDGE ---
@app.route('/register', methods=['POST'])
def register():
    # Klient przesyła JUŻ obliczone Salt i Verifier. 
    # Serwer nie zna hasła, z którego one powstały.
    data = request.json
    username = data.get('username')
    salt_hex = data.get('salt')
    verifier_hex = data.get('verifier')

    if not username or not salt_hex or not verifier_hex:
        return jsonify({'error': 'Brak danych'}), 400

    db = get_db()
    try:
        db.execute("INSERT INTO users (username, salt, verifier) VALUES (?, ?, ?)",
                   (username, salt_hex, verifier_hex))
        db.commit()
        return jsonify({'message': 'Zarejestrowano pomyślnie (Server never saw the password)'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Użytkownik istnieje'}), 409
    finally:
        db.close()

# --- 2. LOGOWANIE ETAP A: Start Handshake ---
@app.route('/handshake/start', methods=['POST'])
def handshake_start():
    data = request.json
    username = data.get('username')
    A_hex = data.get('A') # Klucz publiczny klienta

    # 1. Pobierz salt i verifier z bazy
    db = get_db()
    row = db.execute("SELECT salt, verifier FROM users WHERE username = ?", (username,)).fetchone()
    db.close()

    if not row:
        return jsonify({'error': 'User not found'}), 404

    # Zamiana hex na bytes
    salt = binascii.unhexlify(row['salt'])
    verifier = binascii.unhexlify(row['verifier'])
    A = binascii.unhexlify(A_hex)

    # 2. Inicjalizacja weryfikatora SRP
    svr = srp.Verifier(username, salt, verifier, A)
    
    # Wygenerowanie wyzwania (B)
    # Obsługa różnych wersji biblioteki srp
    if hasattr(svr, 'get_challenge'):
        s, B = svr.get_challenge()
    else:
        s, B = svr.challenge()

    if s is None or B is None:
        return jsonify({'error': 'SRP Error'}), 500

    # 3. Zapisz obiekt sesji w pamięci RAM, żeby użyć go w kroku 2
    LOGIN_SESSIONS[username] = svr

    # 4. Wyślij Sól i B do klienta
    return jsonify({
        'salt': binascii.hexlify(s).decode(),
        'B': binascii.hexlify(B).decode()
    })

# --- 3. LOGOWANIE ETAP B: Weryfikacja Dowodu ---
@app.route('/handshake/verify', methods=['POST'])
def handshake_verify():
    data = request.json
    username = data.get('username')
    M_hex = data.get('M') # Dowód obliczony przez klienta

    if username not in LOGIN_SESSIONS:
        return jsonify({'error': 'Session expired or invalid'}), 400

    svr = LOGIN_SESSIONS[username]
    M = binascii.unhexlify(M_hex)

    # Weryfikacja
    if hasattr(svr, 'verify_session'):
        HAMK = svr.verify_session(M)
    else:
        HAMK = svr.verify(M)

    if HAMK:
        # SUKCES! Serwer uwierzytelnił klienta.
        # Teraz serwer odsyła SWÓJ dowód (HAMK), żeby klient uwierzytelnił serwer.
        del LOGIN_SESSIONS[username] # Czyścimy sesję SRP
        return jsonify({
            'success': True,
            'HAMK': binascii.hexlify(HAMK).decode(),
            'message': 'Logged in securely via SRP'
        })
    else:
        return jsonify({'error': 'Invalid Proof (Wrong Password)'}), 401

if __name__ == '__main__':
    if os.path.exists(DATABASE): os.remove(DATABASE)
    init_db()
    app.run(debug=True, port=5000)