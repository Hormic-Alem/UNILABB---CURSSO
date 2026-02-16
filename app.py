from datetime import datetime
import csv
import io
import os
import secrets
import zipfile
from xml.etree import ElementTree as ET

from dotenv import load_dotenv
from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

load_dotenv()

app = Flask(__name__)

# Configurar SECRET_KEY correctamente desde Railway
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")

if not app.config["SECRET_KEY"]:
    raise RuntimeError("SECRET_KEY no está configurada en Railway.")

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

# Configuración de sesión estable para Railway (HTTPS)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True

db = SQLAlchemy(app)


QUESTIONS_PER_PAGE = 3



class Simulator(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False, index=True)


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


def validate_csrf_or_redirect(endpoint='dashboard'):
    session_token = session.get('_csrf_token')
    form_token = request.form.get('csrf_token')
    if not session_token or not form_token or not secrets.compare_digest(session_token, form_token):
        flash('⚠️ Sesión expirada. Recarga la página e inténtalo nuevamente.', 'warning')
        return redirect(url_for(endpoint))
    return None


def normalize_user_progress(user_dict):
    if 'progress' not in user_dict or not isinstance(user_dict['progress'], dict):
        user_dict['progress'] = {}
    if 'completed_questions' not in user_dict['progress'] or not isinstance(user_dict['progress']['completed_questions'], list):
        user_dict['progress']['completed_questions'] = []
    if 'by_category' not in user_dict['progress'] or not isinstance(user_dict['progress']['by_category'], dict):
        user_dict['progress']['by_category'] = {}


def normalize_username(value):
    return (value or '').strip()


def normalize_email(value):
    return (value or '').strip().lower()


def verify_password(stored_password, incoming_password):
    if not stored_password:
        return False, False

    try:
        if check_password_hash(stored_password, incoming_password):
            return True, False
    except ValueError:
        pass

    legacy_match = secrets.compare_digest(str(stored_password), str(incoming_password))
    return legacy_match, legacy_match


def parse_xlsx(file_storage):
    data = file_storage.read()
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        ns = {
            'x': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main',
            'r': 'http://schemas.openxmlformats.org/officeDocument/2006/relationships',
            'rel': 'http://schemas.openxmlformats.org/package/2006/relationships',
        }

        shared_strings = []
        if 'xl/sharedStrings.xml' in zf.namelist():
            root = ET.fromstring(zf.read('xl/sharedStrings.xml'))
            for si in root.findall('x:si', ns):
                text_parts = [t.text or '' for t in si.findall('.//x:t', ns)]
                shared_strings.append(''.join(text_parts))

        workbook_path = 'xl/workbook.xml'
        if workbook_path not in zf.namelist():
            raise ValueError('El archivo XLSX no contiene workbook.xml')

        workbook_root = ET.fromstring(zf.read(workbook_path))
        first_sheet = workbook_root.find('x:sheets/x:sheet', ns)
        if first_sheet is None:
            raise ValueError('El archivo XLSX no contiene hojas con datos')

        rel_id = first_sheet.attrib.get('{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id')
        if not rel_id:
            raise ValueError('No se encontró la relación de la hoja principal')

        rels_path = 'xl/_rels/workbook.xml.rels'
        if rels_path not in zf.namelist():
            raise ValueError('El archivo XLSX no contiene workbook.xml.rels')

        rels_root = ET.fromstring(zf.read(rels_path))
        target = None
        for rel in rels_root.findall('rel:Relationship', ns):
            if rel.attrib.get('Id') == rel_id:
                target = rel.attrib.get('Target')
                break

        if not target:
            raise ValueError('No se pudo resolver la hoja principal del XLSX')

        target = target.lstrip('/')
        sheet_xml = f'xl/{target}' if not target.startswith('xl/') else target
        if sheet_xml not in zf.namelist():
            raise ValueError(f'No se encontró la hoja principal: {sheet_xml}')

        root = ET.fromstring(zf.read(sheet_xml))

        rows = []
        max_col = 0
        for row in root.findall('.//x:sheetData/x:row', ns):
            row_map = {}
            for cell in row.findall('x:c', ns):
                ref = cell.attrib.get('r', '')
                col_letters = ''.join(ch for ch in ref if ch.isalpha())
                col_idx = 0
                for ch in col_letters:
                    col_idx = col_idx * 26 + (ord(ch.upper()) - 64)
                if col_idx <= 0:
                    continue

                value = ''
                cell_type = cell.attrib.get('t')
                if cell_type == 'inlineStr':
                    value = ''.join((t.text or '') for t in cell.findall('.//x:is/x:t', ns))
                else:
                    v_elem = cell.find('x:v', ns)
                    if v_elem is not None and v_elem.text is not None:
                        raw = v_elem.text
                        if cell_type == 's':
                            idx = int(raw)
                            value = shared_strings[idx] if 0 <= idx < len(shared_strings) else ''
                        else:
                            value = raw

                row_map[col_idx] = str(value)
                max_col = max(max_col, col_idx)

            rows.append([row_map.get(i, '') for i in range(1, max_col + 1)])

        return rows


def parse_excel_xlsx(file_storage):
    # Compatibilidad con despliegues que referencian el nombre nuevo.
    return parse_xlsx(file_storage)


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


def query_questions():
    """Carga preguntas exclusivamente desde SQLAlchemy (sin JSON legacy)."""
    return [question_to_dict(q) for q in Question.query.order_by(Question.category, Question.id).all()]


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


def query_simulator_names():
    """Carga simuladores exclusivamente desde SQLAlchemy (sin JSON legacy)."""
    return [s.name for s in Simulator.query.order_by(Simulator.name).all()]


def ensure_simulator_exists(category_name):
    name = (category_name or '').strip()
    if not name:
        return

    exists = Simulator.query.filter(db.func.lower(Simulator.name) == name.lower()).first()
    if exists:
        return

    db.session.add(Simulator(name=name))


def ensure_simulators_for_questions():
    categories = [row[0] for row in db.session.query(Question.category).distinct().all() if row[0]]
    for category in categories:
        existing = Simulator.query.filter(db.func.lower(Simulator.name) == category.lower()).first()
        if not existing:
            db.session.add(Simulator(name=category))

    db.session.commit()


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
    questions = query_questions()
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

    questions = query_questions()
    categories = query_simulator_names()

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
    questions = query_questions()
    simulators = Simulator.query.all()
    return render_template('dashboard.html', questions=questions, simulators=simulators)


@app.route('/add', methods=['GET', 'POST'])
def add_question():
    if 'username' not in session or not is_admin_session():
        return redirect(url_for('login'))

    if request.method == 'POST':
        validate_csrf_or_abort()

        category = normalize_username(request.form['category'])
        question_text = normalize_username(request.form['question'])
        option1 = normalize_username(request.form['option1'])
        option2 = normalize_username(request.form['option2'])
        option3 = normalize_username(request.form['option3'])
        answer = normalize_username(request.form['answer'])

        ensure_simulator_exists(category)

        db.session.add(Question(
            id=os.urandom(4).hex(),
            category=category,
            question=question_text,
            option1=option1,
            option2=option2,
            option3=option3,
            answer=answer,
        ))
        db.session.commit()
        return redirect(url_for('dashboard'))

    categories = query_simulator_names()
    return render_template('add_question.html', categories=categories)


@app.route('/delete/<question_id>', methods=['POST'])
def delete_question(question_id):
    if 'username' not in session or not is_admin_session():
        return redirect(url_for('login'))

    validate_csrf_or_abort()

    question = db.session.get(Question, question_id)
    if question:
        db.session.delete(question)

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
    if ext not in {'csv', 'xlsx'}:
        flash('❌ Tipo de archivo no soportado (usa CSV o XLSX).', 'danger')
        return redirect(url_for('dashboard'))

    required_cols = ['category', 'question', 'option1', 'option2', 'option3', 'answer']

    try:
        if ext == 'csv':
            content = file.stream.read().decode('utf-8-sig')
            reader = csv.DictReader(io.StringIO(content))
            rows = [{str(k).strip().lower(): v for k, v in row.items()} for row in reader]
            fieldnames = [str(name).strip().lower() for name in (reader.fieldnames or [])]
        else:
            matrix = parse_xlsx(file)
            header = [str(c).strip() for c in (matrix[0] if matrix else [])]
            fieldnames = [h.lower() for h in header]
            rows = []
            for row_values in matrix[1:]:
                row_dict = {}
                for idx, key in enumerate(header):
                    key_norm = str(key).strip().lower()
                    if not key_norm:
                        continue
                    row_dict[key_norm] = '' if idx >= len(row_values) or row_values[idx] is None else str(row_values[idx])
                if any(str(v).strip() for v in row_dict.values()):
                    rows.append(row_dict)

    except Exception as e:
        flash(f'❌ Error al leer archivo: {e}', 'danger')
        return redirect(url_for('dashboard'))

    if not rows or any(col not in fieldnames for col in required_cols):
        missing = [col for col in required_cols if col not in fieldnames]
        flash(f"❌ Faltan columnas obligatorias: {', '.join(missing)}", 'danger')
        return redirect(url_for('dashboard'))

    inserted = 0
    for row in rows:
        category = str(row['category']).strip()
        ensure_simulator_exists(category)
        db.session.add(Question(
            id=os.urandom(4).hex(),
            category=category,
            question=str(row['question']).strip(),
            option1=str(row['option1']).strip(),
            option2=str(row['option2']).strip(),
            option3=str(row['option3']).strip(),
            answer=str(row['answer']).strip(),
        ))
        inserted += 1

    db.session.commit()

    flash('Preguntas importadas correctamente', 'success')
    return redirect(url_for('dashboard'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    message = ''

    if request.method == 'POST':
        identifier = normalize_username(request.form['username'])
        password = request.form['password']

        users = load_users()
        email_identifier = normalize_email(identifier)

        user = next(
            (
                u for u in users
                if normalize_username(u.get('username')).casefold() == identifier.casefold()
                or normalize_email(u.get('email')) == email_identifier
            ),
            None,
        )

        is_valid_password = False
        is_legacy_password = False
        if user:
            is_valid_password, is_legacy_password = verify_password(user.get('password'), password)

        if not user or not is_valid_password:
            message = 'Credenciales incorrectas.'
        elif not user.get('active'):
            message = 'Tu cuenta aún no ha sido activada por el administrador.'
        else:
            if is_legacy_password:
                user['password'] = generate_password_hash(password)
                save_users(users)

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

    all_questions = query_questions()
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
        username = normalize_username(request.form['username'])
        email = normalize_email(request.form['email'])
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


@app.route('/simulators/create', methods=['POST'])
def create_simulator():
    if 'username' not in session or not is_admin_session():
        return redirect(url_for('login'))

    csrf_error = validate_csrf_or_redirect('dashboard')
    if csrf_error:
        return csrf_error

    name = normalize_username(request.form.get('name'))
    if not name:
        flash('❌ El nombre del simulador es obligatorio.', 'danger')
        return redirect(url_for('dashboard'))

    existing = Simulator.query.filter(db.func.lower(Simulator.name) == name.lower()).first()
    if existing:
        flash('⚠️ Ese simulador ya existe.', 'warning')
        return redirect(url_for('dashboard'))

    db.session.add(Simulator(name=name))
    db.session.commit()
    flash('✅ Simulador creado correctamente.', 'success')
    return redirect(url_for('dashboard'))


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

    questions = query_questions()
    ids_categoria = [q['id'] for q in questions if q['category'] == category]

    user['progress']['by_category'][category] = []
    user['progress']['completed_questions'] = [qid for qid in user['progress']['completed_questions'] if qid not in ids_categoria]

    save_users(users)
    return redirect(url_for('home'))


@app.route('/landing')
def landing():
    categories = query_simulator_names()
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
    ensure_simulators_for_questions()

    try:
        admin = User.query.filter_by(username="Apolo96").first()
        if admin:
            admin.password = generate_password_hash("MiataMx5")
            admin.role = "admin"
            admin.active = True
            if not admin.email:
                admin.email = "apolo96@admin.local"
            db.session.commit()
            print("✅ Admin actualizado automáticamente: Apolo96")
        else:
            db.session.add(User(
                username="Apolo96",
                email="apolo96@admin.local",
                password=generate_password_hash("MiataMx5"),
                active=True,
                role="admin",
                progress={"completed_questions": [], "by_category": {}},
                avatar_url=None,
            ))
            db.session.commit()
            print("✅ Admin creado automáticamente: Apolo96")
    except Exception as e:
        db.session.rollback()
        print(f"⚠️ No se pudo crear/actualizar admin automático: {e}")

if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "false").lower() == "true")
