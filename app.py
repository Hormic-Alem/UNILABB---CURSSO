from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
import json
import os
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime


# ======================================================
# CONFIGURACIÓN DE LA APP
# ======================================================

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.getenv('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
)

QUESTIONS_FILE = 'data/questions.json'
USERS_FILE = 'data/users.json'
STATS_FILE = 'data/stats.json'

QUESTIONS_PER_PAGE = 3


def is_admin_session():
    return session.get('role') == 'admin'


def csrf_token():
    token = session.get('_csrf_token')
    if not token:
        token = secrets.token_hex(16)
        session['_csrf_token'] = token
    return token


app.jinja_env.globals['csrf_token'] = csrf_token


def validate_csrf_or_abort():
    session_token = session.get('_csrf_token')
    form_token = request.form.get('csrf_token')
    if not session_token or not form_token or not secrets.compare_digest(session_token, form_token):
        abort(400, description='CSRF token inválido.')

# ======================================================
# ---------------------- UTILIDADES --------------------
# ======================================================

def load_questions():
    if not os.path.exists(QUESTIONS_FILE):
        return []
    with open(QUESTIONS_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_questions(questions):
    with open(QUESTIONS_FILE, 'w', encoding='utf-8') as f:
        json.dump(questions, f, indent=4, ensure_ascii=False)

def load_users():
    if not os.path.exists(USERS_FILE):
        return []
    with open(USERS_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, indent=4, ensure_ascii=False)


def load_categories():
    questions = load_questions()
    return sorted(set(q.get('category', '') for q in questions if q.get('category')))

# ======================================================
# ---------- ESTADÍSTICAS GLOBALES NUEVAS -------------
# ======================================================

def load_stats():
    if not os.path.exists(STATS_FILE):
        return {}
    with open(STATS_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_stats(stats):
    with open(STATS_FILE, 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=4, ensure_ascii=False)

def register_answer(question_id, is_correct):
    stats = load_stats()

    if question_id not in stats:
        stats[question_id] = {"correct": 0, "wrong": 0}

    if is_correct:
        stats[question_id]["correct"] += 1
    else:
        stats[question_id]["wrong"] += 1

    save_stats(stats)

# ======================================================
# --------- PROGRESO DEL ALUMNO (ROBUSTO) --------------
# ======================================================

def normalize_user_progress(user):
    if 'progress' not in user or not isinstance(user['progress'], dict):
        user['progress'] = {}

    if 'completed_questions' not in user['progress'] or not isinstance(
        user['progress']['completed_questions'], list
    ):
        user['progress']['completed_questions'] = []

    if 'by_category' not in user['progress'] or not isinstance(
        user['progress']['by_category'], dict
    ):
        user['progress']['by_category'] = {}

def mark_question_completed(user, question_id, category=None):
    normalize_user_progress(user)

    if question_id not in user['progress']['completed_questions']:
        user['progress']['completed_questions'].append(question_id)

    if category:
        user['progress']['by_category'].setdefault(category, [])
        if question_id not in user['progress']['by_category'][category]:
            user['progress']['by_category'][category].append(question_id)

def calculate_progress_data(user, category=None):
    normalize_user_progress(user)

    questions = load_questions()

    if category:
        filtered = [q for q in questions if q['category'] == category]
        total = len(filtered)
        completed = len(user['progress']['by_category'].get(category, []))
    else:
        total = len(questions)
        completed = len(user['progress']['completed_questions'])

    percentage = int((completed / total) * 100) if total > 0 else 0
    return completed, total, percentage

# ======================================================
# ---------------------- HOME --------------------------
# ======================================================

@app.route('/')
def index():
    return redirect(url_for('landing'))


@app.route('/home')
def home():
    if 'username' not in session:
        return redirect(url_for('landing'))

    users = load_users()
    user = next(u for u in users if u['username'] == session['username'])
    normalize_user_progress(user)

    questions = load_questions()
    categories = sorted(set(q['category'] for q in questions))

    progress_by_category = {}
    chart_labels = []
    chart_values = []

    for cat in categories:
        completed, total, percent = calculate_progress_data(user, cat)
        progress_by_category[cat] = {
            'completed': completed,
            'total': total,
            'percent': percent
        }

        chart_labels.append(cat.capitalize())
        chart_values.append(percent)

    total_completed = sum(v['completed'] for v in progress_by_category.values())
    total_questions = sum(v['total'] for v in progress_by_category.values())
    total_percent = int((total_completed / total_questions) * 100) if total_questions > 0 else 0

    avatar_url = user.get('avatar_url', None)
    if not avatar_url:
        avatar_url = None

    # ======================================================
    # NUEVO: ESTADÍSTICAS GLOBALES PARA HOME
    # ======================================================

    stats = load_stats()
    global_stats = []

    for q in questions:
        qid = q["id"]
        correct = stats.get(qid, {}).get("correct", 0)
        wrong = stats.get(qid, {}).get("wrong", 0)
        total = correct + wrong
        error_percent = int((wrong / total) * 100) if total > 0 else 0

        global_stats.append({
            "question": q["question"],
            "correct": correct,
            "wrong": wrong,
            "error_percent": error_percent
        })

    return render_template(
        'home.html',
        categories=categories,
        progress_by_category=progress_by_category,
        total_percent=total_percent,
        avatar_url=avatar_url,
        chart_labels=chart_labels,
        chart_values=chart_values,
        global_stats=global_stats
    )

# ======================================================
# ---------------- DASHBOARD ADMIN ---------------------
# ======================================================

@app.route('/dashboard')
def dashboard():
    if 'username' not in session or not is_admin_session():
        return redirect(url_for('login'))

    questions = load_questions()
    return render_template('dashboard.html', questions=questions)

# ======================================================
# ---------------- CRUD PREGUNTAS ----------------------
# ======================================================

@app.route('/add', methods=['GET', 'POST'])
def add_question():
    if 'username' not in session or not is_admin_session():
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_question = {
            'id': os.urandom(4).hex(),
            'category': request.form['category'],
            'question': request.form['question'],
            'options': [
                request.form['option1'],
                request.form['option2'],
                request.form['option3']
            ],
            'answer': request.form['answer']
        }

        questions = load_questions()
        questions.append(new_question)
        save_questions(questions)

        return redirect(url_for('dashboard'))

    return render_template('add_question.html')

@app.route('/delete/<question_id>', methods=['POST'])
def delete_question(question_id):
    if 'username' not in session or not is_admin_session():
        return redirect(url_for('login'))

    validate_csrf_or_abort()

    questions = load_questions()
    questions = [q for q in questions if q['id'] != question_id]
    save_questions(questions)

    return redirect(url_for('dashboard'))


# ======================================================
# -------------- 📦 IMPORTACIÓN MASIVA -----------------
# ======================================================

from werkzeug.utils import secure_filename
import pandas as pd

@app.route('/import_questions', methods=['POST'])
def import_questions():
    if 'username' not in session or not is_admin_session():
        return redirect(url_for('login'))

    file = request.files.get('file')
    if not file:
        flash('❌ No se seleccionó archivo.', 'danger')
        return redirect(url_for('dashboard'))

    filename = secure_filename(file.filename)

    # Determinar tipo
    ext = filename.split(".")[-1].lower()

    try:
        if ext == "csv":
            df = pd.read_csv(file)
        elif ext in ["xlsx", "xls"]:
            df = pd.read_excel(file)
        else:
            flash('❌ Tipo de archivo no soportado (usa CSV o Excel).', 'danger')
            return redirect(url_for('dashboard'))
    except Exception as e:
        flash(f'❌ Error al leer archivo: {e}', 'danger')
        return redirect(url_for('dashboard'))

    required_cols = ["category", "question", "option1", "option2", "option3", "answer"]
    for col in required_cols:
        if col not in df.columns:
            flash(f'❌ Falta columna obligatoria: {col}', 'danger')
            return redirect(url_for('dashboard'))

    questions = load_questions()

    # Crear categorías nuevas automáticamente
    existing_categories = {q["category"] for q in questions}

    new_questions = []

    for _, row in df.iterrows():
        new_q = {
            "id": os.urandom(4).hex(),
            "category": str(row["category"]).strip(),
            "question": str(row["question"]).strip(),
            "options": [
                str(row["option1"]).strip(),
                str(row["option2"]).strip(),
                str(row["option3"]).strip(),
            ],
            "answer": str(row["answer"]).strip()
        }
        new_questions.append(new_q)

        # Registrar categoría si es nueva
        existing_categories.add(new_q["category"])

    # Guardar todas las preguntas nuevas
    questions.extend(new_questions)
    save_questions(questions)

    flash(f'✅ {len(new_questions)} preguntas importadas correctamente.', 'success')
    return redirect(url_for('dashboard'))


# ======================================================
# ---------------------- LOGIN -------------------------
# ======================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    message = ''

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        users = load_users()

        # Buscar usuario
        user = next((u for u in users if u['username'] == username), None)

        # ❌ credenciales incorrectas
        if not user or not check_password_hash(user['password'], password):
            message = 'Credenciales incorrectas.'

        # ❌ usuario existe pero no está activo
        elif not user.get('active'):
            message = 'Tu cuenta aún no ha sido activada por el administrador.'

        # ✅ login correcto
        else:
            session.clear()

            # ===== SESIÓN COMPLETA =====
            session['username'] = user['username']
            session['email'] = user['email']     # 🔥 NUEVO (clave para pagos/landing)
            session['role'] = user.get('role')   # opcional pero útil para admin

            # Redirección
            if user.get('role') == 'admin':
                return redirect(url_for('dashboard'))
            else:
                return redirect(url_for('home'))

    return render_template('login.html', message=message)
###

@app.route('/logout')
def logout():
    session.clear()
    flash('Has cerrado sesión correctamente.', 'info')
    return redirect(url_for('login'))

# ======================================================
# ---------------------- QUIZ GLOBAL -------------------
# ======================================================

@app.route('/quiz', methods=['GET', 'POST'])
def quiz():
    return redirect(url_for('home'))

# ======================================================
# ------------------ QUIZ POR CATEGORÍA ----------------
# ======================================================

@app.route('/quiz/<category>', methods=['GET', 'POST'])
def quiz_by_category(category):
    if 'username' not in session:
        return redirect(url_for('login'))

    all_questions = load_questions()
    questions = [q for q in all_questions if q['category'] == category]
    total_questions = len(questions)

    users = load_users()
    user = next(u for u in users if u['username'] == session['username'])
    normalize_user_progress(user)

    session.setdefault('page', 0)
    session.setdefault('score', 0)

    page = session['page']
    start_idx = page * QUESTIONS_PER_PAGE
    end_idx = start_idx + QUESTIONS_PER_PAGE
    questions_page = questions[start_idx:end_idx]

    if request.method == 'POST':
        for i, q in enumerate(questions_page):
            key = f'question_{start_idx + i}'
            selected = request.form.get(key)

            # ================================================
            # NUEVO: REGISTRAR ESTADÍSTICAS GLOBALES
            # ================================================
            register_answer(q["id"], selected == q["answer"])

            # Puntaje del usuario
            if selected == q['answer']:
                session['score'] += 1

            # Progreso personal
            mark_question_completed(user, q['id'], category)

        save_users(users)
        session['page'] += 1

        if end_idx >= total_questions:
            score = session.pop('score', 0)
            session.pop('page', None)

            completed, total, percentage = calculate_progress_data(user, category)

            return render_template(
                'quiz_result.html',
                score=score,
                total=total,
                progress=percentage,
                category=category
            )

        return redirect(url_for('quiz_by_category', category=category))

    completed, total, percentage = calculate_progress_data(user, category)

    return render_template(
        'quiz_multiple.html',
        questions=questions_page,
        page=page + 1,
        total_pages=(total_questions + QUESTIONS_PER_PAGE - 1) // QUESTIONS_PER_PAGE,
        progress=percentage,
        category=category
    )


#########################################
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']

        users = load_users()

        # ---------------- VALIDACIONES ----------------
        if any(u['username'] == username for u in users):
            flash('❌ El nombre de usuario ya existe.', 'danger')
            return redirect(url_for('register'))

        if any(u['email'] == email for u in users):
            flash('❌ El correo ya está registrado.', 'danger')
            return redirect(url_for('register'))

        # ---------------- CREAR USUARIO ----------------
        new_user = {
            'username': username,
            'email': email,
            'password': generate_password_hash(password),
            'active': False,
            'role': 'user',
            'progress': {
                'completed_questions': [],
                'by_category': {}
            },
            'avatar_url': None
        }

        users.append(new_user)
        save_users(users)

        # =================================================
        # 🔥 NUEVO: CREAR TICKET AUTOMÁTICO AL REGISTRAR
        # =================================================
        tickets = load_tickets()

        ticket = {
            "id": os.urandom(4).hex(),
            "email": email,
            "plan": "pro",
            "amount": 499,
            "payment_method": "mercado_pago_manual",
            "status": "pending",
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        tickets.append(ticket)
        save_tickets(tickets)

        flash('✅ Cuenta creada. Ahora completa tu pago para activar el acceso.', 'success')

        return redirect(url_for('post_pago'))

    return render_template('register.html')



        


# ======================================================
# ---------------------- ADMIN USERS -------------------
# ======================================================

@app.route('/admin_users')
def admin_users():
    if 'username' not in session or not is_admin_session():
        return redirect(url_for('login'))

    users = load_users()
    return render_template('admin_users.html', users=users)

@app.route('/toggle_user/<username>', methods=['POST'])
def toggle_user(username):
    if 'username' not in session or not is_admin_session():
        return redirect(url_for('login'))

    validate_csrf_or_abort()

    users = load_users()
    for user in users:
        if user['username'] == username:
            user['active'] = not user.get('active', False)
            break

    save_users(users)
    return redirect(url_for('admin_users'))

# ======================================================
# -------------- 🔥 NUEVO: RESET POR CATEGORÍA ---------
# ======================================================

@app.route('/reset/<category>', methods=['POST'])
def reset_category(category):
    if 'username' not in session:
        return redirect(url_for('login'))

    users = load_users()
    user = next(u for u in users if u['username'] == session['username'])
    normalize_user_progress(user)

    questions = load_questions()
    ids_categoria = [q['id'] for q in questions if q['category'] == category]

    user['progress']['by_category'][category] = []

    user['progress']['completed_questions'] = [
        qid for qid in user['progress']['completed_questions']
        if qid not in ids_categoria
    ]

    save_users(users)

    return redirect(url_for('home'))
##############################################


##############################################
##############################################
# LANDING PAGE (pública)
##############################################
@app.route("/landing")
def landing():
    categories = load_categories()

    # En caso extremo, si load_categories falla, ponemos dummy realistas
    if not categories:
        categories = [
            "Inglés a2",
            "Pensamiento científico",
            "Pensamiento matemático",
            "Redacción indirecta"
        ]

    return render_template("landing.html", categories=categories)


   
# ======================================================
# ------------------ TICKETS DE COMPRA ----------------
# ======================================================

TICKETS_FILE = 'data/tickets.json'


def load_tickets():
    if not os.path.exists(TICKETS_FILE):
        return []
    with open(TICKETS_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_tickets(tickets):
    with open(TICKETS_FILE, 'w', encoding='utf-8') as f:
        json.dump(tickets, f, indent=4, ensure_ascii=False)


# ======================================================
# CREAR TICKET (MANUAL) → REDIRIGE A POST-PAGO
# ======================================================

from datetime import datetime


@app.route('/create_ticket', methods=['POST'])
def create_ticket():
    email = request.form.get('email')

    if not email:
        flash('❌ Debes ingresar un correo válido.', 'danger')
        return redirect(url_for('landing'))

    ticket = {
        "id": os.urandom(4).hex(),
        "email": email.lower(),
        "plan": "pro",
        "amount": 499,
        "payment_method": "mercado_pago_manual",
        "status": "pending",
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    tickets = load_tickets()
    tickets.append(ticket)
    save_tickets(tickets)

    # 👉 ahora muestra instrucciones de pago
    return redirect(url_for('post_pago'))


# ======================================================
# PANTALLA INSTRUCCIONES DE PAGO
# ======================================================

@app.route("/post-pago")
def post_pago():
    return render_template("post_pago.html")


# ======================================================
# RUTAS PAGOS (ADMIN)
# ======================================================

@app.route("/admin/payments")
def admin_payments():
    if 'username' not in session or not is_admin_session():
        return redirect(url_for('login'))

    tickets = load_tickets()
    return render_template("admin_payments.html", tickets=tickets)


@app.route("/admin/mark-paid/<ticket_id>", methods=['POST'])
def admin_mark_paid(ticket_id):
    if 'username' not in session or not is_admin_session():
        return redirect(url_for('login'))

    validate_csrf_or_abort()

    tickets = load_tickets()
    users = load_users()

    ticket_found = None

    # 1️⃣ Marcar ticket como pagado + fecha/hora
    for t in tickets:
        if t["id"] == ticket_id:
            t["status"] = "paid"
            t["paid_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ticket_found = t
            break

    # 2️⃣ Auto-activar usuario por email (MVP)
    if ticket_found:
        for u in users:
            if u["email"].lower() == ticket_found["email"].lower():
                u["active"] = True
                break

    save_tickets(tickets)
    save_users(users)

    return redirect(url_for("admin_payments"))

# ======================================================
# ---------------------- EJECUCIÓN ----------------------
# ======================================================

if __name__ == '__main__':
    app.run(debug=os.getenv('FLASK_DEBUG', 'false').lower() == 'true')
