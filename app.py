import json
import os
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
from flask import Flask, redirect, url_for, render_template, request, flash, abort, app
from flask_login import (
    LoginManager, UserMixin,
    login_user, login_required,
    logout_user, current_user
)
from flask_dance.contrib.google import make_google_blueprint, google
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# Konfiguracja
DATA_FILE = 'users.json'
AVAILABLE_ROLES = ['Reader', 'Writer']
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'replace-with-secure-random')

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Model użytkownika 
class User(UserMixin):
    def __init__(self, id_, username, email, roles):
        self.id = id_
        self.username = username
        self.email = email
        self.roles = roles

USERS = {}   # username -> User
CREDS = {}   # username -> password_hash
ROLES = {}   # username -> [role1, role2]

def load_users():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            data = json.load(f)
        for u, entry in data.items():
            CREDS[u] = entry['password']
            ROLES[u] = entry.get('roles', [])

def save_users():
    data = {
        u: {'password': CREDS[u], 'roles': ROLES[u]}
        for u in CREDS
    }
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=2)

load_users()

@login_manager.user_loader
def load_single_user(user_id):
    if user_id in CREDS:
        roles = ROLES.get(user_id, [])
        user = User(user_id, user_id, None, roles)
        USERS[user_id] = user
        return user
    return None

# Google OAuth2

app.config['GOOGLE_OAUTH_CLIENT_ID']     = '478792325715-3e1cvgf7po7km0q1drf3bdshhb5nebbl.apps.googleusercontent.com'
app.config['GOOGLE_OAUTH_CLIENT_SECRET'] = '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'


google_bp = make_google_blueprint(
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email"
    ],
    redirect_url="/google/authorized"
)

app.register_blueprint(google_bp, url_prefix='/login')

@app.route('/google/authorized')
def google_auth():
    resp = google.get('/oauth2/v2/userinfo')
    email = resp.json()['email']
    user = User(email, email, email, [])
    USERS[email] = user
    CREDS[email] = None
    login_user(user)

    if not ROLES.get(email):
        return redirect(url_for('choose_roles'))
    return redirect(url_for('index'))

# RBAC
def role_required(*needed_roles):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated(*args, **kwargs):
            if not set(current_user.roles) & set(needed_roles):
                return abort(403)
            return f(*args, **kwargs)
        return decorated
    return decorator

# rejestracja
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        u = request.form['username'].strip()
        pw = request.form['password']
        roles = request.form.getlist('roles')
        if not u or not pw:
            flash('Username i hasło są wymagane', 'danger')
        elif u in CREDS:
            flash('Użytkownik już istnieje', 'danger')
        elif not set(roles) <= set(AVAILABLE_ROLES):
            flash('Nieprawidłowe role', 'danger')
        else:
            hash_pw = generate_password_hash(pw)
            CREDS[u] = hash_pw
            ROLES[u] = roles
            save_users()
            user = User(u, u, None, roles)
            USERS[u] = user
            login_user(user)
            flash('Zarejestrowano i zalogowano', 'success')
            return redirect(url_for('index'))
    return render_template('register.html', roles=AVAILABLE_ROLES)

# login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = request.form['username'].strip()
        pw = request.form['password']
        h = CREDS.get(u)
        if h and check_password_hash(h, pw):
            user = User(u, u, None, ROLES.get(u, []))
            USERS[u] = user
            login_user(user)
            flash('Zalogowano', 'success')
            return redirect(url_for('index'))
        flash('Błędne dane', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Views
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/gallery')
@login_required
def gallery():
    if 'Reader' in current_user.roles:
        images = os.listdir('static')
    else:
        images = []
    return render_template('gallery.html', images=images)


@app.route('/upload', methods=['GET','POST'])
@role_required('Writer')
def upload():
    if request.method == 'POST':
        f = request.files['photo']
        f.save(os.path.join('static', f.filename))
        flash('Dodano zdjęcie', 'success')
    return render_template('upload.html')


@app.route('/choose_roles', methods=['GET','POST'])
@login_required
def choose_roles():
    if request.method == 'POST':
        selected = request.form.getlist('roles')
        ROLES[current_user.id] = selected
        save_users()
        return redirect(url_for('index'))
    return render_template('choose_roles.html', roles=AVAILABLE_ROLES)

if __name__ == '__main__':
    app.run(debug=True)