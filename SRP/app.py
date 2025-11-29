import sqlite3
import time
import os
import srp
import binascii
from flask import Flask, render_template, request, redirect, url_for, session
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(24)
DATABASE = 'database_srp.db'

# --- Benchmark Decorator (do pomiarów w raporcie) ---
def benchmark(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        start_time = time.perf_counter()
        result = f(*args, **kwargs)
        end_time = time.perf_counter()
        elapsed = (end_time - start_time) * 1000  # milisekundy
        print(f"[BENCHMARK] {f.__name__}: {elapsed:.4f} ms")
        return result
    return decorated_function

# --- Baza Danych ---
def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # Tabela specyficzna dla SRP: nie ma hasha, jest salt i verifier
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                salt TEXT NOT NULL,
                verifier TEXT NOT NULL
            );
        ''')
        db.commit()
        db.close()

# --- Trasy ---

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
@benchmark # Mierzymy czas rejestracji (generowanie dużych liczb)
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # 1. SRP: Generowanie soli i weryfikatora
        # To jest operacja kosztowna matematycznie: v = g^x mod N
        salt, vkey = srp.create_salted_verification_key(username, password)
        
        # Konwersja na hex do zapisu w bazie
        salt_hex = binascii.hexlify(salt).decode('utf-8')
        vkey_hex = binascii.hexlify(vkey).decode('utf-8')

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, salt, verifier) VALUES (?, ?, ?)",
                (username, salt_hex, vkey_hex)
            )
            db.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            error = "Użytkownik już istnieje."
        finally:
            db.close()

    return render_template('register.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
@benchmark # Mierzymy czas logowania (handshake)
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        db.close()

        if user:
            # 1. Pobieramy dane z bazy (to co ukradł haker)
            salt = binascii.unhexlify(user['salt'])
            verifier = binascii.unhexlify(user['verifier'])
            
            # 2. Symulacja Handshake SRP (normalnie klient/serwer są osobno)
            
            # KROK A: Klient (User)
            usr = srp.User(username, password)
            uname, A = usr.start_authentication()
            
            # KROK B: Serwer (Verifier)
            svr = srp.Verifier(username, salt, verifier, A)
            s, B = svr.get_challenge()
            
            if s and B:
                # KROK C: Klient oblicza dowód sesji M
                M = usr.process_challenge(s, B)
                
                # KROK D: Serwer weryfikuje dowód M
                HAMK = svr.verify_session(M)
                
                if HAMK:
                    session['username'] = username
                    return redirect(url_for('witaj'))
                else:
                    error = "Błąd weryfikacji SRP (złe hasło)."
            else:
                error = "Błąd protokołu SRP."
        else:
            error = "Nie znaleziono użytkownika."

    return render_template('login.html', error=error)

@app.route('/witaj')
def witaj():
    return f"Witaj {session.get('username', 'Nieznajomy')}! Zalogowano bezpiecznie przez SRP."

if __name__ == '__main__':
    # if os.path.exists(DATABASE):
    #     os.remove(DATABASE) 
    init_db()
    app.run(debug=True, port=5000)