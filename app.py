from datetime import datetime
import csv
import io
import os
import secrets

from dotenv import load_dotenv
from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy

from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(32))

database_url = os.environ.get("DATABASE_URL")
if not database_url:
    raise RuntimeError("DATABASE_URL no está configurada.")

database_url = database_url.strip().strip('"').strip("'")
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

try:
    make_url(database_url)
except ArgumentError as exc:
    raise RuntimeError(f"DATABASE_URL inválida para SQLAlchemy: {database_url!r}") from exc
 

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"


db = SQLAlchemy(app)

QUESTIONS_PER_PAGE = 3


class Question(db.Model):
    id = db.Column(db.String(32), primary_key=True)
    category = db.Column(db.String(255), nullable=False, index=True)
    question = db.Column(db.Text, nullable=False)
    option1 = db.Column(db.Text, nullable=False)
    option2 = db.Column(db.Text, nullable=False)
    option3 = db.Column(db.Text, nullable=False)
    answer = db.Column(db.Text, nullable=False)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password = db.Column(db.Text, nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    progress = db.Column(db.JSON, nullable=False, default=dict)
    avatar_url = db.Column(db.Text, nullable=True)


class QuestionStat(db.Model):
    question_id = db.Column(db.String(32), primary_key=True)
    correct = db.Column(db.Integer, nullable=False, default=0)
    wrong = db.Column(db.Integer, nullable=False, default=0)


class Ticket(db.Model):
    id = db.Column(db.String(32), primary_key=True)
    email = db.Column(db.String(255), nullable=False, index=True)
    plan = db.Column(db.String(50), nullable=False, default='pro')
    amount = db.Column(db.Integer, nullable=False, default=499)
    payment_method = db.Column(db.String(100), nullable=False, default='mercado_pago_manual')
    status = db.Column(db.String(20), nullable=False, default='pending')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    paid_at = db.Column(db.DateTime, nullable=True)


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


def normalize_user_progress(user_dict):
    if 'progress' not in user_dict or not isinstance(user_dict['progress'], dict):
        user_dict['progress'] = {}
    if 'completed_questions' not in user_dict['progress'] or not isinstance(user_dict['progress']['completed_questions'], list):
        user_dict['progress']['completed_questions'] = []
    if 'by_category' not in user_dict['progress'] or not isinstance(user_dict['progress']['by_category'], dict):
        user_dict['progress']['by_category'] = {}


def question_to_dict(question):
    return {
        'id': question.id,
        'category': question.category,
        'question': question.question,
        'options': [question.option1, question.option2, question.option3],
        'answer': question.answer,
    }


def user_to_dict(user):
    progress = user.progress or {}
    data = {
        'username': user.username,
        'email': user.email,
        'password': user.password,
        'active': user.active,
        'role': user.role,
        'progress': progress,
        'avatar_url': user.avatar_url,
    }
    normalize_user_progress(data)
    return data


def ticket_to_dict(ticket):
    payload = {
        'id': ticket.id,
        'email': ticket.email,
        'plan': ticket.plan,
        'amount': ticket.amount,
        'payment_method': ticket.payment_method,
        'status': ticket.status,
        'created_at': ticket.created_at.strftime('%Y-%m-%d %H:%M:%S'),
    }
    if ticket.paid_at:
        payload['paid_at'] = ticket.paid_at.strftime('%Y-%m-%d %H:%M:%S')
    return payload


def load_questions():
    return [question_to_dict(q) for q in Question.query.order_by(Question.category, Question.id).all()]


def save_questions(questions):
    Question.query.delete()
    db.session.flush()
    for q in questions:
        options = q.get('options', ['', '', ''])
        db.session.add(Question(
            id=q['id'],
            category=q['category'],
            question=q['question'],
            option1=options[0],
            option2=options[1],
            option3=options[2],
            answer=q['answer'],
        ))
    db.session.commit()


def load_users():
    return [user_to_dict(u) for u in User.query.order_by(User.username).all()]


def save_users(users):
    existing = {u.username: u for u in User.query.all()}
    incoming = set()
    for user in users:
        incoming.add(user['username'])
        row = existing.get(user['username'])
        if row is None:
            row = User(username=user['username'])
            db.session.add(row)
        row.email = user['email']
        row.password = user['password']
        row.active = bool(user.get('active', False))
        row.role = user.get('role', 'user')
        row.avatar_url = user.get('avatar_url')
        progress = user.get('progress') or {}
        normalize_user_progress({'progress': progress})
        row.progress = progress

    for username, row in existing.items():
        if username not in incoming:
            db.session.delete(row)

    db.session.commit()


def load_categories():
    return [row[0] for row in db.session.query(Question.category).distinct().order_by(Question.category).all() if row[0]]


def load_stats():
    return {s.question_id: {'correct': s.correct, 'wrong': s.wrong} for s in QuestionStat.query.all()}


def save_stats(stats):
    QuestionStat.query.delete()
    db.session.flush()
    for question_id, value in stats.items():
        db.session.add(QuestionStat(question_id=question_id, correct=value.get('correct', 0), wrong=value.get('wrong', 0)))
    db.session.commit()


def register_answer(question_id, is_correct):
    stat = db.session.get(QuestionStat, question_id)
    if not stat:
        stat = QuestionStat(question_id=question_id, correct=0, wrong=0)
        db.session.add(stat)
    if is_correct:
        stat.correct += 1
    else:
        stat.wrong += 1
    db.session.commit()


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
        progress_by_category[cat] = {'completed': completed, 'total': total, 'percent': percent}
        chart_labels.append(cat.capitalize())
        chart_values.append(percent)

    total_completed = sum(v['completed'] for v in progress_by_category.values())
    total_questions = sum(v['total'] for v in progress_by_category.values())
    total_percent = int((total_completed / total_questions) * 100) if total_questions > 0 else 0

    avatar_url = user.get('avatar_url', None) or None

    stats = load_stats()
    global_stats = []
    for q in questions:
        qid = q['id']
        correct = stats.get(qid, {}).get('correct', 0)
        wrong = stats.get(qid, {}).get('wrong', 0)
        total = correct + wrong
        error_percent = int((wrong / total) * 100) if total > 0 else 0
        global_stats.append({'question': q['question'], 'correct': correct, 'wrong': wrong, 'error_percent': error_percent})

    return render_template('home.html', categories=categories, progress_by_category=progress_by_category, total_percent=total_percent, avatar_url=avatar_url, chart_labels=chart_labels, chart_values=chart_values, global_stats=global_stats)


@app.route('/dashboard')
def dashboard():
    if 'username' not in session or not is_admin_session():
        return redirect(url_for('login'))
    questions = load_questions()
    return render_template('dashboard.html', questions=questions)


@app.route('/add', methods=['GET', 'POST'])
def add_question():
    if 'username' not in session or not is_admin_session():
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_question = {
            'id': os.urandom(4).hex(),
            'category': request.form['category'],
            'question': request.form['question'],
            'options': [request.form['option1'], request.form['option2'], request.form['option3']],
            'answer': request.form['answer'],
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

    stat = db.session.get(QuestionStat, question_id)
    if stat:
        db.session.delete(stat)
        db.session.commit()

    return redirect(url_for('dashboard'))


@app.route('/import_questions', methods=['POST'])
def import_questions():
    if 'username' not in session or not is_admin_session():
        return redirect(url_for('login'))

    file = request.files.get('file')
    if not file:
        flash('❌ No se seleccionó archivo.', 'danger')
        return redirect(url_for('dashboard'))

    filename = secure_filename(file.filename)
    ext = filename.split('.')[-1].lower()

    if ext != 'csv':
        flash('❌ Tipo de archivo no soportado (usa CSV).', 'danger')
        return redirect(url_for('dashboard'))

    try:
        content = file.stream.read().decode('utf-8-sig')
        reader = csv.DictReader(io.StringIO(content))
        rows = list(reader)
    except Exception as e:
        flash(f'❌ Error al leer archivo CSV: {e}', 'danger')
        return redirect(url_for('dashboard'))

    required_cols = ['category', 'question', 'option1', 'option2', 'option3', 'answer']
    if not rows or any(col not in reader.fieldnames for col in required_cols):
        missing = [col for col in required_cols if col not in (reader.fieldnames or [])]
        flash(f"❌ Faltan columnas obligatorias: {', '.join(missing)}", 'danger')
        return redirect(url_for('dashboard'))

    questions = load_questions()
    new_questions = []

    for row in rows:
        new_q = {
            'id': os.urandom(4).hex(),
            'category': str(row['category']).strip(),
            'question': str(row['question']).strip(),
            'options': [str(row['option1']).strip(), str(row['option2']).strip(), str(row['option3']).strip()],
            'answer': str(row['answer']).strip(),
        }
        new_questions.append(new_q)

    questions.extend(new_questions)
    save_questions(questions)

    flash(f'✅ {len(new_questions)} preguntas importadas correctamente.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    message = ''

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        users = load_users()
        user = next((u for u in users if u['username'] == username), None)

        if not user or not check_password_hash(user['password'], password):
            message = 'Credenciales incorrectas.'
        elif not user.get('active'):
            message = 'Tu cuenta aún no ha sido activada por el administrador.'
        else:
            session.clear()
            session['username'] = user['username']
            session['email'] = user['email']
            session['role'] = user.get('role')
            if user.get('role') == 'admin':
                return redirect(url_for('dashboard'))
            return redirect(url_for('home'))

    return render_template('login.html', message=message)


@app.route('/logout')
def logout():
    session.clear()
    flash('Has cerrado sesión correctamente.', 'info')
    return redirect(url_for('login'))


@app.route('/quiz', methods=['GET', 'POST'])
def quiz():
    return redirect(url_for('home'))


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
            register_answer(q['id'], selected == q['answer'])
            if selected == q['answer']:
                session['score'] += 1
            mark_question_completed(user, q['id'], category)

        save_users(users)
        session['page'] += 1

        if end_idx >= total_questions:
            score = session.pop('score', 0)
            session.pop('page', None)
            completed, total, percentage = calculate_progress_data(user, category)
            return render_template('quiz_result.html', score=score, total=total, progress=percentage, category=category)

        return redirect(url_for('quiz_by_category', category=category))

    completed, total, percentage = calculate_progress_data(user, category)
    return render_template('quiz_multiple.html', questions=questions_page, page=page + 1, total_pages=(total_questions + QUESTIONS_PER_PAGE - 1) // QUESTIONS_PER_PAGE, progress=percentage, category=category)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']

        users = load_users()

        if any(u['username'] == username for u in users):
            flash('❌ El nombre de usuario ya existe.', 'danger')
            return redirect(url_for('register'))

        if any(u['email'] == email for u in users):
            flash('❌ El correo ya está registrado.', 'danger')
            return redirect(url_for('register'))

        new_user = {
            'username': username,
            'email': email,
            'password': generate_password_hash(password),
            'active': False,
            'role': 'user',
            'progress': {'completed_questions': [], 'by_category': {}},
            'avatar_url': None,
        }

        users.append(new_user)
        save_users(users)

        tickets = load_tickets()
        tickets.append({
            'id': os.urandom(4).hex(),
            'email': email,
            'plan': 'pro',
            'amount': 499,
            'payment_method': 'mercado_pago_manual',
            'status': 'pending',
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        })
        save_tickets(tickets)

        flash('✅ Cuenta creada. Ahora completa tu pago para activar el acceso.', 'success')
        return redirect(url_for('post_pago'))

    return render_template('register.html')


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
    user['progress']['completed_questions'] = [qid for qid in user['progress']['completed_questions'] if qid not in ids_categoria]

    save_users(users)
    return redirect(url_for('home'))


@app.route('/landing')
def landing():
    categories = load_categories()
    if not categories:
        categories = ['Inglés a2', 'Pensamiento científico', 'Pensamiento matemático', 'Redacción indirecta']
    return render_template('landing.html', categories=categories)


def load_tickets():
    return [ticket_to_dict(t) for t in Ticket.query.order_by(Ticket.created_at.desc()).all()]


def save_tickets(tickets):
    Ticket.query.delete()
    db.session.flush()
    for t in tickets:
        created_at = t.get('created_at')
        paid_at = t.get('paid_at')
        db.session.add(Ticket(
            id=t['id'],
            email=t['email'],
            plan=t.get('plan', 'pro'),
            amount=int(t.get('amount', 499)),
            payment_method=t.get('payment_method', 'mercado_pago_manual'),
            status=t.get('status', 'pending'),
            created_at=datetime.strptime(created_at, '%Y-%m-%d %H:%M:%S') if isinstance(created_at, str) else (created_at or datetime.utcnow()),
            paid_at=datetime.strptime(paid_at, '%Y-%m-%d %H:%M:%S') if isinstance(paid_at, str) else paid_at,
        ))
    db.session.commit()


@app.route('/create_ticket', methods=['POST'])
def create_ticket():
    email = request.form.get('email')

    if not email:
        flash('❌ Debes ingresar un correo válido.', 'danger')
        return redirect(url_for('landing'))

    tickets = load_tickets()
    tickets.append({
        'id': os.urandom(4).hex(),
        'email': email.lower(),
        'plan': 'pro',
        'amount': 499,
        'payment_method': 'mercado_pago_manual',
        'status': 'pending',
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    })
    save_tickets(tickets)

    return redirect(url_for('post_pago'))


@app.route('/post-pago')
def post_pago():
    return render_template('post_pago.html')


@app.route('/admin/payments')
def admin_payments():
    if 'username' not in session or not is_admin_session():
        return redirect(url_for('login'))

    tickets = load_tickets()
    return render_template('admin_payments.html', tickets=tickets)


@app.route('/admin/mark-paid/<ticket_id>', methods=['POST'])
def admin_mark_paid(ticket_id):
    if 'username' not in session or not is_admin_session():
        return redirect(url_for('login'))

    validate_csrf_or_abort()

    tickets = load_tickets()
    users = load_users()

    ticket_found = None
    for t in tickets:
        if t['id'] == ticket_id:
            t['status'] = 'paid'
            t['paid_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            ticket_found = t
            break

    if ticket_found:
        for u in users:
            if u['email'].lower() == ticket_found['email'].lower():
                u['active'] = True
                break

    save_tickets(tickets)
    save_users(users)

    return redirect(url_for('admin_payments'))


with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "false").lower() == "true")

