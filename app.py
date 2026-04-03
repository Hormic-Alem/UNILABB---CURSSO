from datetime import datetime
import base64
import csv
import io
import os
import secrets
import zipfile
import xml.etree.ElementTree as ET

from dotenv import load_dotenv
from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from flask import Flask, abort, flash, jsonify, redirect, render_template, request, session, url_for, send_from_directory

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



class Question(db.Model):
    id = db.Column(db.String(8), primary_key=True)
    category = db.Column(db.String(255), nullable=False, index=True)
    question = db.Column(db.Text, nullable=False)
    option1 = db.Column(db.Text, nullable=False)
    option2 = db.Column(db.Text, nullable=False)
    option3 = db.Column(db.Text, nullable=False)
    answer = db.Column(db.Text, nullable=False)


class Simulator(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False, index=True)
    segment = db.Column(db.String(20), nullable=False, default='ingreso', index=True)


class Program(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False, index=True)
    segment = db.Column(db.String(20), nullable=False, default='ingreso', index=True)


class ProgramArea(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    program_id = db.Column(db.Integer, db.ForeignKey('program.id'), nullable=False, index=True)
    name = db.Column(db.String(255), nullable=False, index=True)
    simulator_id = db.Column(db.Integer, db.ForeignKey('simulator.id'), nullable=True, index=True)


class SimulatorImage(db.Model):
    simulator_key = db.Column(db.String(255), primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    image_b64 = db.Column(db.Text, nullable=False)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


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
    referral_code = db.Column(db.String(50), nullable=True)
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


def normalize_username(value):
    return (value or '').strip()


def normalize_email(value):
    return (value or '').strip().lower()


def normalize_simulator_name(value):
    cleaned = ' '.join((value or '').split()).strip()
    return cleaned.title()


def normalize_segment(value):
    segment = (value or '').strip().lower()
    if not segment:
        return 'ingreso'
    if segment not in {'ingreso', 'egreso'}:
        return None
    return segment


def is_segmented_catalog_enabled():
    raw = os.getenv('ENABLE_SEGMENTED_LANDING', 'auto').strip().lower()
    if raw in {'1', 'true', 'yes', 'on'}:
        return True
    if raw in {'0', 'false', 'no', 'off'}:
        return False

    # Modo automático: activar si hay al menos un registro de egreso.
    try:
        has_egreso_simulator = db.session.query(Simulator.id).filter(func.lower(Simulator.segment) == 'egreso').first()
        if has_egreso_simulator:
            return True
        has_egreso_program = db.session.query(Program.id).filter(func.lower(Program.segment) == 'egreso').first()
        return bool(has_egreso_program)
    except Exception:
        return False

def simulator_image_filename(simulator_name):
    normalized = normalize_simulator_name(simulator_name)
    safe = normalized.replace('/', ' ').replace('\\', ' ').strip().lower()
    return f"{safe}.jpg" if safe else ''


def simulator_image_key(simulator_name):
    return normalize_simulator_name(simulator_name).casefold()


def persist_simulator_image(simulator_name, filename, image_bytes):
    key = simulator_image_key(simulator_name)
    if not key or not image_bytes:
        return

    payload = base64.b64encode(image_bytes).decode('ascii')
    row = db.session.get(SimulatorImage, key)
    if row is None:
        row = SimulatorImage(simulator_key=key, filename=filename, image_b64=payload, updated_at=datetime.utcnow())
        db.session.add(row)
    else:
        row.filename = filename
        row.image_b64 = payload
        row.updated_at = datetime.utcnow()
    db.session.commit()


def restore_simulator_images_from_db():
    target_dir = os.path.join(app.root_path, 'static', 'img', 'cursos')
    os.makedirs(target_dir, exist_ok=True)

    for row in SimulatorImage.query.all():
        target_path = os.path.join(target_dir, row.filename)
        if os.path.exists(target_path):
            continue
        try:
            image_bytes = base64.b64decode(row.image_b64.encode('ascii'))
            with open(target_path, 'wb') as fp:
                fp.write(image_bytes)
        except Exception:
            continue


def save_simulator_image(simulator_name, file_storage):
    if not file_storage or not file_storage.filename:
        return False, 'No se envió imagen.'

    filename = secure_filename(file_storage.filename)
    extension = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    if extension not in {'jpg', 'jpeg'}:
        return False, 'La imagen debe estar en formato JPG o JPEG.'

    target_name = simulator_image_filename(simulator_name)
    if not target_name:
        return False, 'Nombre de simulador inválido para guardar imagen.'

    target_dir = os.path.join(app.root_path, 'static', 'img', 'cursos')
    os.makedirs(target_dir, exist_ok=True)
    target_path = os.path.join(target_dir, target_name)
    file_storage.stream.seek(0)
    image_bytes = file_storage.stream.read()
    with open(target_path, 'wb') as fp:
        fp.write(image_bytes)

    persist_simulator_image(simulator_name, target_name, image_bytes)
    return True, target_name


def rename_simulator_image(old_name, new_name):
    old_filename = simulator_image_filename(old_name)
    new_filename = simulator_image_filename(new_name)
    if not old_filename or not new_filename or old_filename == new_filename:
        return

    target_dir = os.path.join(app.root_path, 'static', 'img', 'cursos')
    old_path = os.path.join(target_dir, old_filename)
    new_path = os.path.join(target_dir, new_filename)
    if not os.path.exists(old_path):
        return

    os.makedirs(target_dir, exist_ok=True)
    if os.path.exists(new_path):
        os.remove(new_path)
    os.replace(old_path, new_path)

    old_key = simulator_image_key(old_name)
    new_key = simulator_image_key(new_name)
    row = db.session.get(SimulatorImage, old_key)
    if row:
        row.simulator_key = new_key
        row.filename = new_filename
        row.updated_at = datetime.utcnow()
        db.session.commit()


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
        'referral_code': ticket.referral_code,
        'created_at': ticket.created_at.strftime('%Y-%m-%d %H:%M:%S'),
    }
    if ticket.paid_at:
        payload['paid_at'] = ticket.paid_at.strftime('%Y-%m-%d %H:%M:%S')
    return payload


def load_questions():
    return [question_to_dict(q) for q in Question.query.order_by(Question.category, Question.id).all()]


def list_questions():
    return [question_to_dict(q) for q in Question.query.order_by(Question.category, Question.id).all()]


def create_question(category, question, option1, option2, option3, answer):
    normalized_category = normalize_simulator_name(category)
    if not normalized_category:
        raise ValueError('El simulador es obligatorio.')

    exists = db.session.query(Simulator.id).filter(func.lower(Simulator.name) == normalized_category.lower()).first()
    if not exists:
        db.session.add(Simulator(name=normalized_category))

    new_question = Question(
        id=os.urandom(4).hex(),
        category=normalized_category,
        question=question,
        option1=option1,
        option2=option2,
        option3=option3,
        answer=answer,
    )
    db.session.add(new_question)
    db.session.commit()
    return question_to_dict(new_question)


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


def list_simulators():
    return Simulator.query.order_by(Simulator.name).all()


def parse_xlsx(file_storage):
    ns = {'x': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
    required_cols = ['category', 'question', 'option1', 'option2', 'option3', 'answer']

    file_storage.stream.seek(0)
    xlsx_bytes = file_storage.stream.read()
    with zipfile.ZipFile(io.BytesIO(xlsx_bytes)) as zf:
        shared_strings = []
        if 'xl/sharedStrings.xml' in zf.namelist():
            shared_root = ET.fromstring(zf.read('xl/sharedStrings.xml'))
            for si in shared_root.findall('x:si', ns):
                raw_text = ''.join(node.text or '' for node in si.findall('.//x:t', ns))
                # Normalizar UTF-8 para evitar caracteres rotos
                text = raw_text.encode("utf-8", "ignore").decode("utf-8")
                shared_strings.append(text)

        sheet_root = ET.fromstring(zf.read('xl/worksheets/sheet1.xml'))
        rows = []
        for row in sheet_root.findall('.//x:sheetData/x:row', ns):
            values = {}
            for cell in row.findall('x:c', ns):
                ref = cell.get('r', '')
                col_letters = ''.join(ch for ch in ref if ch.isalpha()).upper()
                col_index = 0
                for ch in col_letters:
                    col_index = (col_index * 26) + (ord(ch) - ord('A') + 1)
                col_index = max(col_index - 1, 0)

                cell_type = cell.get('t')
                value_node = cell.find('x:v', ns)
                if value_node is None:
                    cell_value = ''
                elif cell_type == 's':
                    shared_idx = int(value_node.text or '0')
                    cell_value = shared_strings[shared_idx] if 0 <= shared_idx < len(shared_strings) else ''
                else:
                    cell_value = value_node.text or ''

                values[col_index] = cell_value.strip()
            rows.append(values)

    if not rows:
        return []

    header_row = rows[0]
    max_col = max(header_row.keys(), default=-1)
    headers = [header_row.get(i, '').strip().lower() for i in range(max_col + 1)]
    index_by_name = {name: idx for idx, name in enumerate(headers) if name}

    if any(col not in index_by_name for col in required_cols):
        missing = [col for col in required_cols if col not in index_by_name]
        raise ValueError(f"Faltan columnas obligatorias: {', '.join(missing)}")

    parsed_rows = []
    for raw_row in rows[1:]:
        payload = {col: str(raw_row.get(index_by_name[col], '')).strip() for col in required_cols}
        if any(payload.values()):
            parsed_rows.append(payload)

    return parsed_rows


def parse_csv(file_storage):
    required_cols = ['category', 'question', 'option1', 'option2', 'option3', 'answer']

    # Leer muestra SOLO para detectar delimitador (sin reemplazar caracteres)
    file_storage.stream.seek(0)
    sample = file_storage.stream.read(1024).decode('utf-8-sig', errors='ignore')
    file_storage.stream.seek(0)

    delimiters = [';', ',']
    try:
        sniffed = csv.Sniffer().sniff(sample, delimiters=';,')
        if sniffed.delimiter in (';', ',') and sniffed.delimiter not in delimiters:
            delimiters.append(sniffed.delimiter)
    except csv.Error:
        pass

    for delimiter in delimiters:
        file_storage.stream.seek(0)

        # DECODIFICACIÓN CORRECTA
        content = file_storage.stream.read().decode('utf-8-sig', errors='ignore')

        reader = csv.DictReader(io.StringIO(content), delimiter=delimiter)
        fieldnames = [(name or '').strip().lower() for name in (reader.fieldnames or [])]

        rows = []
        for row in reader:
            rows.append({
                col: str(row.get(col, '')).strip()
                for col in required_cols
            })

        if all(col in fieldnames for col in required_cols):
            return rows, fieldnames

    # fallback
    return rows, fieldnames


def list_simulators():
    names_by_key = {}

    for sim in Simulator.query.order_by(Simulator.name).all():
        normalized = normalize_simulator_name(sim.name)
        if normalized:
            names_by_key[normalized.casefold()] = normalized

    for category in load_categories():
        normalized = normalize_simulator_name(category)
        if normalized and normalized.casefold() not in names_by_key:
            names_by_key[normalized.casefold()] = normalized

    return [
        {'name': name}
        for name in sorted(names_by_key.values(), key=lambda value: value.casefold())
    ]


def list_programs_catalog():
    programs = Program.query.order_by(Program.name).all()
    result = []
    for program in programs:
        areas = ProgramArea.query.filter_by(program_id=program.id).order_by(ProgramArea.name).all()
        result.append({
            'id': program.id,
            'name': program.name,
            'segment': program.segment,
            'areas': [area.name for area in areas],
            'area_items': [{'name': area.name, 'simulator_id': area.simulator_id} for area in areas],
        })
    return result


def get_or_create_program(program_name, default_segment='ingreso'):
    normalized = normalize_simulator_name(program_name)
    if not normalized:
        return None

    program = Program.query.filter(func.lower(Program.name) == normalized.lower()).first()
    if program:
        if not program.segment:
            program.segment = normalize_segment(default_segment) or 'ingreso'
        return program

    program = Program(name=normalized, segment=normalize_segment(default_segment) or 'ingreso')
    db.session.add(program)
    db.session.flush()
    return program


def upsert_program_area_for_simulator(simulator, program_name=None):
    if not simulator:
        return

    target_program = get_or_create_program(program_name or simulator.name, simulator.segment)
    if not target_program:
        return

    area = ProgramArea.query.filter_by(simulator_id=simulator.id).first()
    if area is None:
        area = ProgramArea(program_id=target_program.id, name=simulator.name, simulator_id=simulator.id)
        db.session.add(area)
        return

    area.program_id = target_program.id
    area.name = simulator.name


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


@app.route('/robots.txt')
def robots():
    return send_from_directory(app.root_path, 'robots.txt', mimetype='text/plain')


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
    stats_by_category = {cat: [] for cat in categories}

    for q in questions:
        qid = q['id']
        correct = stats.get(qid, {}).get('correct', 0)
        wrong = stats.get(qid, {}).get('wrong', 0)
        total = correct + wrong
        error_percent = int((wrong / total) * 100) if total > 0 else 0
        stats_by_category.setdefault(q['category'], []).append({
            'question': q['question'],
            'correct': correct,
            'wrong': wrong,
            'error_percent': error_percent,
        })

    selected_stats_category = request.args.get('stats_category', '')
    if selected_stats_category not in stats_by_category:
        selected_stats_category = categories[0] if categories else ''

    visible_stats = stats_by_category.get(selected_stats_category, [])

    course_cards = []
    use_segmented_catalog = is_segmented_catalog_enabled()
    if use_segmented_catalog:
        try:
            programs = list_programs_catalog()
            child_area_names = {
                item['name'].casefold()
                for program in programs
                for item in program.get('area_items', [])
                if item['name'].casefold() != program['name'].casefold()
            }
            for program in programs:
                # Mostrar solo programas padre o programas independientes.
                if program['name'].casefold() in child_area_names:
                    continue
                areas = program.get('areas') or [program['name']]
                completed = sum(progress_by_category.get(area, {}).get('completed', 0) for area in areas)
                total = sum(progress_by_category.get(area, {}).get('total', 0) for area in areas)
                percent = int((completed / total) * 100) if total > 0 else 0
                primary_area = next((area for area in areas if progress_by_category.get(area, {}).get('total', 0) > 0), areas[0])
                is_parent = any(area.casefold() != program['name'].casefold() for area in areas)
                course_cards.append({
                    'program_id': program.get('id'),
                    'name': program['name'],
                    'segment': program.get('segment', 'ingreso'),
                    'areas': areas,
                    'area_count': len(areas),
                    'is_parent': is_parent,
                    'completed': completed,
                    'total': total,
                    'percent': percent,
                    'primary_area': primary_area,
                })
        except Exception:
            course_cards = []

    if not course_cards:
        for category in categories:
            cat_progress = progress_by_category.get(category, {'completed': 0, 'total': 0, 'percent': 0})
            course_cards.append({
                'program_id': None,
                'name': category,
                'segment': 'ingreso',
                'areas': [category],
                'area_count': 1,
                'is_parent': False,
                'completed': cat_progress.get('completed', 0),
                'total': cat_progress.get('total', 0),
                'percent': cat_progress.get('percent', 0),
                'primary_area': category,
            })

    course_cards.sort(
        key=lambda card: (
            card.get('segment', 'ingreso'),
            0 if card.get('is_parent') else 1,
            card.get('name', '').casefold(),
        )
    )

    return render_template(
        'home.html',
        categories=categories,
        course_cards=course_cards,
        use_segmented_catalog=use_segmented_catalog,
        progress_by_category=progress_by_category,
        total_percent=total_percent,
        avatar_url=avatar_url,
        chart_labels=chart_labels,
        chart_values=chart_values,
        stats_by_category=stats_by_category,
        selected_stats_category=selected_stats_category,
        visible_stats=visible_stats,
    )


@app.route('/program/<int:program_id>')
def program_areas(program_id):
    program = db.session.get(Program, program_id)
    if not program:
        flash('Programa no encontrado.', 'warning')
        return redirect(url_for('landing'))

    areas = ProgramArea.query.filter_by(program_id=program_id).order_by(ProgramArea.name).all()
    if not areas:
        fallback_simulators = Simulator.query.filter(
            func.lower(Simulator.segment) == (program.segment or 'ingreso').lower(),
            func.lower(Simulator.name) != program.name.lower()
        ).order_by(Simulator.name).all()
        fallback_names = []
        for sim in fallback_simulators:
            questions_total = Question.query.filter(func.lower(Question.category) == sim.name.lower()).count()
            if questions_total > 0:
                fallback_names.append(sim.name)
        areas = [type('AreaFallback', (), {'name': name}) for name in fallback_names]
        if not areas:
            flash('Este programa aún no tiene áreas disponibles.', 'warning')
            return redirect(url_for('landing'))

    user = None
    if 'username' in session:
        users = load_users()
        user = next((u for u in users if u['username'] == session['username']), None)
        if user:
            normalize_user_progress(user)

    area_items = []
    for area in areas:
        total = Question.query.filter(func.lower(Question.category) == area.name.lower()).count()
        if user:
            completed = len(user.get('progress', {}).get('by_category', {}).get(area.name, []))
            completed = min(completed, total)
            percent = int((completed / total) * 100) if total > 0 else 0
        else:
            completed, percent = 0, 0
        area_items.append({
            'name': area.name,
            'completed': completed,
            'total': total,
            'percent': percent,
        })

    return render_template('program_areas.html', program=program, areas=area_items, can_start=bool(user))


@app.route('/dashboard')
def dashboard():
    if 'username' not in session or not is_admin_session():
        return redirect(url_for('login'))
    simulators = Simulator.query.order_by(Simulator.name).all()
    questions = Question.query.order_by(Question.category).all()
    programs = Program.query.order_by(Program.name).all()
    area_by_sim_id = {
        area.simulator_id: area.program_id
        for area in ProgramArea.query.filter(ProgramArea.simulator_id.isnot(None)).all()
    }
    area_program_name_by_sim_id = {}
    if area_by_sim_id:
        names_by_id = {program.id: program.name for program in programs}
        for sim_id, program_id in area_by_sim_id.items():
            area_program_name_by_sim_id[sim_id] = names_by_id.get(program_id, '')
    program_meta = {}
    for program in programs:
        areas = ProgramArea.query.filter_by(program_id=program.id).all()
        child_count = sum(1 for area in areas if area.name.casefold() != program.name.casefold())
        program_meta[program.id] = {
            'areas_count': len(areas),
            'child_count': child_count,
            'is_parent': child_count > 0,
        }
    return render_template(
        'dashboard.html',
        simulators=simulators,
        questions=questions,
        programs=programs,
        area_by_sim_id=area_by_sim_id,
        area_program_name_by_sim_id=area_program_name_by_sim_id,
        program_meta=program_meta,
    )


@app.route('/admin/programs_catalog')
def admin_programs_catalog():
    if 'username' not in session or not is_admin_session():
        return redirect(url_for('login'))
    return jsonify(list_programs_catalog())


@app.route('/programs/image/<int:program_id>', methods=['POST'])
def upload_program_image(program_id):
    if 'username' not in session or not is_admin_session():
        return redirect(url_for('login'))

    validate_csrf_or_abort()

    program = db.session.get(Program, program_id)
    if not program:
        flash('Programa no encontrado.', 'warning')
        return redirect(url_for('dashboard'))

    image_file = request.files.get('program_image')
    ok, message = save_simulator_image(program.name, image_file)
    if ok:
        flash('Imagen del programa actualizada.', 'success')
    else:
        flash(message, 'warning')
    return redirect(url_for('dashboard'))


@app.route('/simulators/create', methods=['POST'])
def create_simulator():
    if 'username' not in session or not is_admin_session():
        return redirect(url_for('login'))

    validate_csrf_or_abort()

    simulator_name = normalize_simulator_name(request.form.get('name'))
    simulator_segment = normalize_segment(request.form.get('segment'))
    parent_program_name = request.form.get('program_name')
    if not simulator_name:
        flash('❌ Debes ingresar un nombre válido para el simulador.', 'danger')
        return redirect(url_for('dashboard'))
    if simulator_segment is None:
        flash('❌ Segmento inválido. Usa ingreso o egreso.', 'danger')
        return redirect(url_for('dashboard'))

    exists = db.session.query(Simulator.id).filter(func.lower(Simulator.name) == simulator_name.lower()).first()
    if exists:
        flash('ℹ️ El simulador ya existe.', 'info')
        return redirect(url_for('dashboard'))

    new_simulator = Simulator(name=simulator_name, segment=simulator_segment)
    db.session.add(new_simulator)
    db.session.flush()
    upsert_program_area_for_simulator(new_simulator, parent_program_name)
    db.session.commit()

    image_file = request.files.get('simulator_image')
    if image_file and image_file.filename:
        ok, message = save_simulator_image(simulator_name, image_file)
        if ok:
            flash('✅ Simulador creado con imagen.', 'success')
        else:
            flash(f'✅ Simulador creado. Imagen no guardada: {message}', 'warning')
        return redirect(url_for('dashboard'))

    flash('✅ Simulador creado', 'success')
    return redirect(url_for('dashboard'))


@app.route('/simulators/edit/<int:sim_id>', methods=['POST'])
def edit_simulator(sim_id):
    if 'username' not in session or not is_admin_session():
        return redirect(url_for('login'))

    validate_csrf_or_abort()

    simulator = db.session.get(Simulator, sim_id)
    if not simulator:
        flash('❌ Simulador no encontrado.', 'danger')
        return redirect(url_for('dashboard'))

    old_name = simulator.name
    new_name = normalize_simulator_name(request.form.get('name'))
    segment_input = request.form.get('segment')
    parent_program_name = request.form.get('program_name')
    simulator_segment = normalize_segment(segment_input) if segment_input not in (None, '') else simulator.segment
    if not new_name:
        flash('❌ Debes ingresar un nombre válido.', 'danger')
        return redirect(url_for('dashboard'))
    if simulator_segment is None:
        flash('❌ Segmento inválido. Usa ingreso o egreso.', 'danger')
        return redirect(url_for('dashboard'))

    exists = db.session.query(Simulator.id).filter(
        func.lower(Simulator.name) == new_name.lower(),
        Simulator.id != sim_id
    ).first()
    if exists:
        flash('❌ Ya existe otro simulador con ese nombre.', 'danger')
        return redirect(url_for('dashboard'))

    simulator.name = new_name
    simulator.segment = simulator_segment
    upsert_program_area_for_simulator(simulator, parent_program_name)
    Question.query.filter(func.lower(Question.category) == old_name.lower()).update(
        {Question.category: new_name},
        synchronize_session=False,
    )

    users = User.query.all()
    for user in users:
        payload = user_to_dict(user)
        by_category = payload['progress'].get('by_category', {})
        if old_name in by_category:
            if new_name in by_category:
                merged = by_category[new_name] + [qid for qid in by_category[old_name] if qid not in by_category[new_name]]
                by_category[new_name] = merged
            else:
                by_category[new_name] = by_category[old_name]
            by_category.pop(old_name, None)
            user.progress = payload['progress']

    db.session.commit()
    rename_simulator_image(old_name, new_name)
    flash('✅ Nombre del simulador actualizado correctamente.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/simulators/image/<int:sim_id>', methods=['POST'])
def upload_simulator_image(sim_id):
    if 'username' not in session or not is_admin_session():
        return redirect(url_for('login'))

    validate_csrf_or_abort()

    simulator = db.session.get(Simulator, sim_id)
    if not simulator:
        flash('Simulador no encontrado.', 'warning')
        return redirect(url_for('dashboard'))

    image_file = request.files.get('simulator_image')
    ok, message = save_simulator_image(simulator.name, image_file)
    if ok:
        flash('Imagen del simulador actualizada.', 'success')
    else:
        flash(message, 'warning')

    return redirect(url_for('dashboard'))


@app.route('/simulators/delete/<int:sim_id>', methods=['POST'])
def delete_simulator(sim_id):
    if 'username' not in session or not is_admin_session():
        return redirect(url_for('login'))

    validate_csrf_or_abort()

    simulator = db.session.get(Simulator, sim_id)
    if simulator:
        image_key = simulator_image_key(simulator.name)
        row = db.session.get(SimulatorImage, image_key)
        if row:
            db.session.delete(row)

        image_filename = simulator_image_filename(simulator.name)
        if image_filename:
            image_path = os.path.join(app.root_path, 'static', 'img', 'cursos', image_filename)
            if os.path.exists(image_path):
                try:
                    os.remove(image_path)
                except OSError:
                    pass

        ProgramArea.query.filter_by(simulator_id=simulator.id).delete(synchronize_session=False)
        linked_questions = Question.query.filter_by(category=simulator.name).all()
        linked_ids = [q.id for q in linked_questions]

        if linked_ids:
            QuestionStat.query.filter(QuestionStat.question_id.in_(linked_ids)).delete(synchronize_session=False)
            Question.query.filter(Question.id.in_(linked_ids)).delete(synchronize_session=False)

            users = User.query.all()
            for user in users:
                payload = user_to_dict(user)
                progress = payload['progress']
                progress['completed_questions'] = [qid for qid in progress.get('completed_questions', []) if qid not in linked_ids]
                progress.get('by_category', {}).pop(simulator.name, None)
                user.progress = progress

            flash(f'Simulador eliminado junto con {len(linked_ids)} preguntas asociadas.', 'success')
        else:
            flash('Simulador eliminado.', 'success')

        db.session.delete(simulator)
        empty_program_ids = [
            row[0]
            for row in db.session.query(Program.id)
            .outerjoin(ProgramArea, Program.id == ProgramArea.program_id)
            .group_by(Program.id)
            .having(func.count(ProgramArea.id) == 0)
            .all()
        ]
        if empty_program_ids:
            Program.query.filter(Program.id.in_(empty_program_ids)).delete(synchronize_session=False)
        db.session.commit()

    return redirect(url_for('dashboard'))


@app.route('/add', methods=['GET', 'POST'])
def add_question():
    if 'username' not in session or not is_admin_session():
        return redirect(url_for('login'))

    if request.method == 'POST':
        category = request.form.get('category', '').strip()
        question = request.form.get('question', '').strip()
        option1 = request.form.get('option1', '').strip()
        option2 = request.form.get('option2', '').strip()
        option3 = request.form.get('option3', '').strip()
        answer = request.form.get('answer', '').strip()

        create_question(category, question, option1, option2, option3, answer)
        flash('Pregunta añadida correctamente.', 'success')
        return redirect(url_for('dashboard'))

    simulators = Simulator.query.order_by(Simulator.name).all()
    return render_template('add_question.html', simulators=simulators)


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

    if ext not in ('csv', 'xlsx'):
        flash('❌ Tipo de archivo no soportado (usa CSV o XLSX).', 'danger')
        return redirect(url_for('dashboard'))

    try:
        if ext == 'csv':
            normalized_rows, fieldnames = parse_csv(file)
        else:
            normalized_rows = parse_xlsx(file)
            fieldnames = ['category', 'question', 'option1', 'option2', 'option3', 'answer']
    except Exception as e:
        flash(f'❌ Error al leer archivo: {e}', 'danger')
        return redirect(url_for('dashboard'))

    required_cols = ['category', 'question', 'option1', 'option2', 'option3', 'answer']
    if any(col not in fieldnames for col in required_cols):
        missing = [col for col in required_cols if col not in fieldnames]
        flash(f"❌ Faltan columnas obligatorias: {', '.join(missing)}", 'danger')
        return redirect(url_for('dashboard'))

    created = 0
    for row in normalized_rows:
        if not all(row.get(col, '').strip() for col in required_cols):
            continue
        create_question(
            row['category'],
            row['question'],
            row['option1'],
            row['option2'],
            row['option3'],
            row['answer'],
        )
        created += 1

    flash(f'Preguntas importadas correctamente ({created} creadas)', 'success')
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

    all_questions = load_questions()
    questions = [q for q in all_questions if q['category'] == category]
    total_questions = len(questions)

    users = load_users()
    user = next(u for u in users if u['username'] == session['username'])
    normalize_user_progress(user)

    session.setdefault('page', 0)
    session.setdefault('score', 0)
    session.setdefault('quiz_answers', {})

    page = session['page']
    if request.method == 'GET' and page == 0:
        session['quiz_answers'] = {}
    start_idx = page * QUESTIONS_PER_PAGE
    end_idx = start_idx + QUESTIONS_PER_PAGE
    questions_page = questions[start_idx:end_idx]

    if request.method == 'POST':
        answers = session.get('quiz_answers', {})
        for i, q in enumerate(questions_page):
            key = f'question_{start_idx + i}'
            selected = request.form.get(key)
            is_correct = selected == q['answer']
            register_answer(q['id'], is_correct)
            answers[q['id']] = {
                'selected': selected or 'Sin respuesta',
                'correct': q['answer'],
                'is_correct': is_correct,
            }
            if is_correct:
                session['score'] += 1
            mark_question_completed(user, q['id'], category)

        session['quiz_answers'] = answers
        save_users(users)
        session['page'] += 1

        if end_idx >= total_questions:
            score = session.pop('score', 0)
            session.pop('page', None)
            answers = session.pop('quiz_answers', {})
            review = []
            for q in questions:
                answer_info = answers.get(q['id'])
                if not answer_info:
                    continue
                review.append({
                    'question': q['question'],
                    'selected': answer_info['selected'],
                    'correct': answer_info['correct'],
                    'is_correct': answer_info['is_correct'],
                })
            completed, total, percentage = calculate_progress_data(user, category)
            return render_template(
                'quiz_result.html',
                score=score,
                total=total,
                progress=percentage,
                category=category,
                review=review,
            )

        return redirect(url_for('quiz_by_category', category=category))

    completed, total, percentage = calculate_progress_data(user, category)
    return render_template('quiz_multiple.html', questions=questions_page, page=page + 1, total_pages=(total_questions + QUESTIONS_PER_PAGE - 1) // QUESTIONS_PER_PAGE, progress=percentage, category=category)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = normalize_username(request.form['username'])
        email = normalize_email(request.form['email'])
        password = request.form['password']
        referral_code = sanitize_referral_code(request.form.get('referral_code'))

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
            'referral_code': referral_code,
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
    categories = [row[0] for row in db.session.query(Question.category).distinct().order_by(Question.category).all() if row[0]]
    course_cards = []
    use_segmented_catalog = is_segmented_catalog_enabled()
    if use_segmented_catalog:
        try:
            programs = list_programs_catalog()
            child_area_names = {
                item['name'].casefold()
                for program in programs
                for item in program.get('area_items', [])
                if item['name'].casefold() != program['name'].casefold()
            }
            course_cards = [
                {
                    'name': p['name'],
                    'segment': p.get('segment', 'ingreso'),
                    'program_id': p.get('id'),
                    'is_parent': any(area.casefold() != p['name'].casefold() for area in (p.get('areas') or [])),
                }
                for p in programs
                if p['name'].casefold() not in child_area_names
            ]
        except Exception:
            course_cards = []
    if not course_cards:
        course_cards = [{'name': category, 'segment': 'ingreso', 'program_id': None, 'is_parent': False} for category in categories]
    if not categories:
        categories = ['Inglés a2', 'Pensamiento científico', 'Pensamiento matemático', 'Redacción indirecta']
        if not course_cards:
            course_cards = [{'name': category, 'segment': 'ingreso', 'program_id': None, 'is_parent': False} for category in categories]
    course_cards.sort(
        key=lambda card: (
            card.get('segment', 'ingreso'),
            0 if card.get('is_parent') else 1,
            card.get('name', '').casefold(),
        )
    )
    return render_template('landing.html', categories=categories, course_cards=course_cards, use_segmented_catalog=use_segmented_catalog)


def load_tickets():
    return [ticket_to_dict(t) for t in Ticket.query.order_by(Ticket.created_at.desc()).all()]


def sanitize_referral_code(value):
    raw = (value or '').strip()
    if not raw:
        return None

    safe_text = raw.replace('<', '').replace('>', '').strip()
    if not safe_text:
        return None

    return safe_text[:50]


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
            referral_code=t.get('referral_code'),
            created_at=datetime.strptime(created_at, '%Y-%m-%d %H:%M:%S') if isinstance(created_at, str) else (created_at or datetime.utcnow()),
            paid_at=datetime.strptime(paid_at, '%Y-%m-%d %H:%M:%S') if isinstance(paid_at, str) else paid_at,
        ))
    db.session.commit()


@app.route('/create_ticket', methods=['POST'])
def create_ticket():
    email = request.form.get('email')
    referral_code = sanitize_referral_code(request.form.get('referral_code'))

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
        'referral_code': referral_code,
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

    referral_code_filter = sanitize_referral_code(request.args.get('referral_code'))
    tickets = load_tickets()
    if referral_code_filter:
        tickets = [t for t in tickets if (t.get('referral_code') or '').lower() == referral_code_filter.lower()]
    return render_template('admin_payments.html', tickets=tickets, referral_code_filter=referral_code_filter or '')


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


def backfill_program_catalog():
    programs_by_key = {}

    for program in Program.query.all():
        programs_by_key[program.name.casefold()] = program

    simulators = Simulator.query.order_by(Simulator.name).all()
    for simulator in simulators:
        key = simulator.name.casefold()
        if key not in programs_by_key:
            program = Program(name=simulator.name, segment=normalize_segment(simulator.segment) or 'ingreso')
            db.session.add(program)
            db.session.flush()
            programs_by_key[key] = program
        else:
            program = programs_by_key[key]
            if not program.segment:
                program.segment = normalize_segment(simulator.segment) or 'ingreso'

        area = ProgramArea.query.filter_by(simulator_id=simulator.id).first()
        if area is None:
            area = ProgramArea.query.filter(
                ProgramArea.program_id == program.id,
                func.lower(ProgramArea.name) == simulator.name.lower()
            ).first()
        if area is None:
            db.session.add(ProgramArea(program_id=program.id, name=simulator.name, simulator_id=simulator.id))
        else:
            area.program_id = program.id
            area.name = simulator.name
            if area.simulator_id is None:
                area.simulator_id = simulator.id

    categories = [row[0] for row in db.session.query(Question.category).distinct().all() if row[0]]
    for category in categories:
        normalized = normalize_simulator_name(category)
        if not normalized:
            continue
        key = normalized.casefold()
        if key not in programs_by_key:
            program = Program(name=normalized, segment='ingreso')
            db.session.add(program)
            db.session.flush()
            programs_by_key[key] = program
        else:
            program = programs_by_key[key]

        area_exists = db.session.query(ProgramArea.id).filter(
            ProgramArea.program_id == program.id,
            func.lower(ProgramArea.name) == normalized.lower()
        ).first()
        if not area_exists:
            db.session.add(ProgramArea(program_id=program.id, name=normalized))

    db.session.commit()


with app.app_context():
    db.create_all()

    try:
        ticket_columns = {col['name'] for col in inspect(db.engine).get_columns('ticket')}
        if 'referral_code' not in ticket_columns:
            db.session.execute(text('ALTER TABLE ticket ADD COLUMN referral_code VARCHAR(50)'))
            db.session.commit()
            print('✅ Columna referral_code agregada en ticket')
    except Exception as e:
        db.session.rollback()
        print(f'⚠️ No se pudo validar/agregar columna referral_code: {e}')

    try:
        simulator_columns = {col['name'] for col in inspect(db.engine).get_columns('simulator')}
        if 'segment' not in simulator_columns:
            db.session.execute(text("ALTER TABLE simulator ADD COLUMN segment VARCHAR(20) DEFAULT 'ingreso'"))
            db.session.execute(text("UPDATE simulator SET segment='ingreso' WHERE segment IS NULL OR segment = ''"))
            db.session.commit()
            print('✅ Columna segment agregada en simulator con valor por defecto ingreso')
    except Exception as e:
        db.session.rollback()
        print(f'⚠️ No se pudo validar/agregar columna segment en simulator: {e}')

    try:
        program_area_columns = {col['name'] for col in inspect(db.engine).get_columns('program_area')}
        if 'simulator_id' not in program_area_columns:
            db.session.execute(text('ALTER TABLE program_area ADD COLUMN simulator_id INTEGER'))
            db.session.commit()
            print('✅ Columna simulator_id agregada en program_area')
    except Exception as e:
        db.session.rollback()
        print(f'⚠️ No se pudo validar/agregar columna simulator_id en program_area: {e}')

    try:
        backfill_program_catalog()
        print('✅ Catálogo Program/ProgramArea sincronizado desde simuladores/categorías existentes')
    except Exception as e:
        db.session.rollback()
        print(f'⚠️ No se pudo sincronizar catálogo Program/ProgramArea: {e}')

    try:
        restore_simulator_images_from_db()
        print('✅ Imágenes de simuladores restauradas desde base de datos')
    except Exception as e:
        print(f'⚠️ No se pudo restaurar imágenes de simuladores: {e}')

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
