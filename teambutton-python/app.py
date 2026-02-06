"""
THE TEAM COMPANY - 팀빌딩 플랫폼
Python Flask + Socket.IO + SQLite
모든 기능 포함: 회원가입/로그인, 이벤트관리, 게임7종, 실시간채팅, 타이머, 점수관리
"""
import os, json, time, random, string, hashlib, secrets, threading, math
from datetime import datetime, timedelta
from functools import wraps
import sqlite3

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, g, send_from_directory
from flask_socketio import SocketIO, emit, join_room, leave_room, rooms

# ============================================
# App Setup
# ============================================
app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', ping_timeout=120, ping_interval=25, max_http_buffer_size=1024*1024, logger=False, engineio_logger=False)

# Throttle mechanism for high-frequency events
_last_emit = {}
def throttled_emit(key, event, data, room, interval=0.5):
    """Throttle emits to max once per interval seconds per key"""
    now = time.time()
    if key in _last_emit and (now - _last_emit[key]) < interval:
        return
    _last_emit[key] = now
    socketio.emit(event, data, room=room)

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'teambutton.db')
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ============================================
# Database
# ============================================
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db: db.close()

def db_exec(sql, params=(), fetch=False, fetchone=False):
    db = get_db()
    cur = db.execute(sql, params)
    db.commit()
    if fetchone: return cur.fetchone()
    if fetch: return cur.fetchall()
    return cur.lastrowid

def init_db():
    db = sqlite3.connect(DATABASE)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        phone TEXT DEFAULT '',
        salt TEXT NOT NULL,
        hash TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        profile TEXT DEFAULT '',
        code TEXT UNIQUE,
        active INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_connect TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_id INTEGER NOT NULL,
        code TEXT UNIQUE NOT NULL,
        title TEXT DEFAULT '',
        company_name TEXT DEFAULT '',
        location TEXT DEFAULT '',
        description TEXT DEFAULT '',
        image TEXT DEFAULT '',
        status TEXT DEFAULT '대기',
        max_participants INTEGER DEFAULT 100,
        has_teams INTEGER DEFAULT 0,
        team_score_type TEXT DEFAULT '합계',
        display_mode TEXT DEFAULT '대기',
        like_active INTEGER DEFAULT 0,
        like_count INTEGER DEFAULT 0,
        chat_active INTEGER DEFAULT 0,
        chat_anonymous INTEGER DEFAULT 0,
        game_anonymous INTEGER DEFAULT 0,
        current_game_id INTEGER,
        timer_id INTEGER,
        start_at TIMESTAMP,
        end_at TIMESTAMP,
        real_start_at TIMESTAMP,
        real_end_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(host_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS teams (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        image TEXT DEFAULT '',
        score INTEGER DEFAULT 0,
        description TEXT DEFAULT '',
        max_members INTEGER DEFAULT 10,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS participants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id INTEGER NOT NULL,
        team_id INTEGER,
        name TEXT NOT NULL,
        phone TEXT DEFAULT '',
        email TEXT DEFAULT '',
        password TEXT DEFAULT '',
        ip TEXT DEFAULT '',
        code INTEGER DEFAULT 0,
        role TEXT DEFAULT '참가자',
        status TEXT DEFAULT '참가',
        score INTEGER DEFAULT 0,
        memo TEXT DEFAULT '',
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE,
        FOREIGN KEY(team_id) REFERENCES teams(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS games (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id INTEGER NOT NULL,
        type TEXT NOT NULL,
        status TEXT DEFAULT '대기',
        settings TEXT DEFAULT '{}',
        responses TEXT DEFAULT '[]',
        anonymous INTEGER DEFAULT 0,
        started_at TIMESTAMP,
        ended_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id INTEGER NOT NULL,
        sender_id INTEGER,
        sender_name TEXT DEFAULT '',
        type TEXT DEFAULT 'all',
        author TEXT DEFAULT 'normal',
        team_id INTEGER,
        message TEXT NOT NULL,
        anonymous INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS like_participants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id INTEGER NOT NULL,
        participant_id INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(event_id, participant_id)
    );
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        actor_id INTEGER,
        data TEXT DEFAULT '{}',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    db.close()

# ============================================
# Helpers
# ============================================
def make_id(n=8):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=n))

def hash_pw(password, salt=None):
    if not salt: salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha512', password.encode(), salt.encode(), 10000)
    return salt, h.hex()

def verify_pw(password, salt, hashed):
    _, h = hash_pw(password, salt)
    return h == hashed

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

def get_current_user():
    if 'user_id' in session:
        return db_exec("SELECT * FROM users WHERE id=?", (session['user_id'],), fetchone=True)
    return None

def row_to_dict(row):
    if row is None: return None
    return dict(row)

def rows_to_list(rows):
    return [dict(r) for r in rows] if rows else []

# ============================================
# Timers (in-memory)
# ============================================
active_timers = {}  # event_id -> timer_data

# ============================================
# Auth Routes
# ============================================
@app.route('/')
def index():
    user = get_current_user()
    if user: return redirect(url_for('dashboard'))
    return redirect(url_for('landing_page'))

@app.route('/landing')
def landing_page():
    return render_template('landing.html')

@app.route('/auth/login', methods=['GET','POST'])
def login_page():
    if request.method == 'POST':
        email = request.form.get('email','')
        pw = request.form.get('password','')
        user = db_exec("SELECT * FROM users WHERE email=?", (email,), fetchone=True)
        if not user: return render_template('auth/login.html', error='계정을 찾을 수 없습니다.')
        if not verify_pw(pw, user['salt'], user['hash']):
            return render_template('auth/login.html', error='비밀번호가 일치하지 않습니다.')
        session['user_id'] = user['id']
        session['user_name'] = user['name']
        db_exec("UPDATE users SET last_connect=? WHERE id=?", (datetime.now(), user['id']))
        return redirect(url_for('dashboard'))
    return render_template('auth/login.html')

@app.route('/auth/register', methods=['GET','POST'])
def register_page():
    if request.method == 'POST':
        email = request.form.get('email','')
        name = request.form.get('name','')
        pw = request.form.get('password','')
        pw2 = request.form.get('password2','')
        if not email or not name or not pw:
            return render_template('auth/register.html', error='모든 항목을 입력하세요.')
        if pw != pw2:
            return render_template('auth/register.html', error='비밀번호가 일치하지 않습니다.')
        if len(pw) < 6:
            return render_template('auth/register.html', error='비밀번호는 6자 이상이어야 합니다.')
        existing = db_exec("SELECT id FROM users WHERE email=?", (email,), fetchone=True)
        if existing:
            return render_template('auth/register.html', error='이미 가입된 이메일입니다.')
        salt, hashed = hash_pw(pw)
        code = make_id(8)
        db_exec("INSERT INTO users(email,name,salt,hash,code) VALUES(?,?,?,?,?)",
                (email,name,salt,hashed,code))
        user = db_exec("SELECT * FROM users WHERE email=?", (email,), fetchone=True)
        session['user_id'] = user['id']
        session['user_name'] = user['name']
        return redirect(url_for('dashboard'))
    return render_template('auth/register.html')

@app.route('/auth/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

# ============================================
# Dashboard Routes
# ============================================
@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()
    events = rows_to_list(db_exec(
        "SELECT * FROM events WHERE host_id=? ORDER BY created_at DESC", (user['id'],), fetch=True))
    return render_template('dashboard/index.html', user=user, events=events)

@app.route('/dashboard/mypage', methods=['GET','POST'])
@login_required
def mypage():
    user = get_current_user()
    if request.method == 'POST':
        name = request.form.get('name', user['name'])
        phone = request.form.get('phone', user['phone'] or '')
        db_exec("UPDATE users SET name=?, phone=? WHERE id=?", (name, phone, user['id']))
        session['user_name'] = name
        return redirect(url_for('mypage'))
    return render_template('dashboard/mypage.html', user=user)

# ============================================
# Event CRUD Routes
# ============================================
@app.route('/dashboard/event/create', methods=['GET','POST'])
@login_required
def event_create():
    user = get_current_user()
    if request.method == 'POST':
        title = request.form.get('title','')
        company = request.form.get('company_name','')
        location = request.form.get('location','')
        desc = request.form.get('description','')
        max_p = int(request.form.get('max_participants', 100))
        has_teams = 1 if request.form.get('has_teams') else 0
        code = make_id(8)
        eid = db_exec("INSERT INTO events(host_id,code,title,company_name,location,description,max_participants,has_teams) VALUES(?,?,?,?,?,?,?,?)",
                      (user['id'], code, title, company, location, desc, max_p, has_teams))
        return redirect(url_for('event_manage', id=eid))
    return render_template('dashboard/event_form.html', user=user, event=None)

@app.route('/dashboard/event/<int:id>/edit', methods=['GET','POST'])
@login_required
def event_edit(id):
    user = get_current_user()
    event = row_to_dict(db_exec("SELECT * FROM events WHERE id=? AND host_id=?", (id,user['id']), fetchone=True))
    if not event: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        title = request.form.get('title','')
        company = request.form.get('company_name','')
        location = request.form.get('location','')
        desc = request.form.get('description','')
        max_p = int(request.form.get('max_participants', 100))
        has_teams = 1 if request.form.get('has_teams') else 0
        db_exec("UPDATE events SET title=?,company_name=?,location=?,description=?,max_participants=?,has_teams=? WHERE id=?",
                (title,company,location,desc,max_p,has_teams,id))
        return redirect(url_for('event_manage', id=id))
    return render_template('dashboard/event_form.html', user=user, event=event)

@app.route('/dashboard/event/<int:id>/delete', methods=['POST'])
@login_required
def event_delete(id):
    user = get_current_user()
    db_exec("DELETE FROM events WHERE id=? AND host_id=?", (id,user['id']))
    return redirect(url_for('dashboard'))

@app.route('/dashboard/event/<int:id>/manage')
@login_required
def event_manage(id):
    user = get_current_user()
    event = row_to_dict(db_exec("SELECT * FROM events WHERE id=? AND host_id=?", (id,user['id']), fetchone=True))
    if not event: return redirect(url_for('dashboard'))
    teams = rows_to_list(db_exec("SELECT * FROM teams WHERE event_id=? ORDER BY created_at", (id,), fetch=True))
    participants = rows_to_list(db_exec("SELECT p.*, t.name as team_name FROM participants p LEFT JOIN teams t ON p.team_id=t.id WHERE p.event_id=? ORDER BY p.code", (id,), fetch=True))
    games = rows_to_list(db_exec("SELECT * FROM games WHERE event_id=? ORDER BY created_at DESC", (id,), fetch=True))
    return render_template('dashboard/event_manage.html', user=user, event=event, teams=teams, participants=participants, games=games)

@app.route('/dashboard/event/<int:id>/result')
@login_required
def event_result(id):
    user = get_current_user()
    event = row_to_dict(db_exec("SELECT * FROM events WHERE id=? AND host_id=?", (id,user['id']), fetchone=True))
    if not event: return redirect(url_for('dashboard'))
    teams = rows_to_list(db_exec("SELECT * FROM teams WHERE event_id=? ORDER BY score DESC", (id,), fetch=True))
    participants = rows_to_list(db_exec("SELECT p.*, t.name as team_name FROM participants p LEFT JOIN teams t ON p.team_id=t.id WHERE p.event_id=? ORDER BY p.score DESC", (id,), fetch=True))
    games = rows_to_list(db_exec("SELECT * FROM games WHERE event_id=? ORDER BY created_at", (id,), fetch=True))
    for g_item in games:
        g_item['settings'] = json.loads(g_item['settings'] or '{}')
        g_item['responses'] = json.loads(g_item['responses'] or '[]')
    return render_template('dashboard/event_result.html', user=user, event=event, teams=teams, participants=participants, games=games)

# ============================================
# Team API
# ============================================
@app.route('/api/event/<int:event_id>/team', methods=['POST'])
@login_required
def api_team_create(event_id):
    data = request.get_json() or request.form
    name = data.get('name', '새 팀')
    tid = db_exec("INSERT INTO teams(event_id,name) VALUES(?,?)", (event_id,name))
    return jsonify(success=True, team_id=tid)

@app.route('/api/event/<int:event_id>/team/<int:team_id>', methods=['PUT','DELETE'])
@login_required
def api_team_edit(event_id, team_id):
    if request.method == 'DELETE':
        db_exec("UPDATE participants SET team_id=NULL WHERE team_id=?", (team_id,))
        db_exec("DELETE FROM teams WHERE id=? AND event_id=?", (team_id, event_id))
        return jsonify(success=True)
    data = request.get_json()
    if data.get('name'):
        db_exec("UPDATE teams SET name=? WHERE id=?", (data['name'], team_id))
    if 'score' in data:
        db_exec("UPDATE teams SET score=? WHERE id=?", (data['score'], team_id))
    return jsonify(success=True)

# ============================================
# Participant API
# ============================================
@app.route('/api/event/<int:event_id>/participant/<int:pid>', methods=['PUT','DELETE'])
@login_required
def api_participant_edit(event_id, pid):
    if request.method == 'DELETE':
        db_exec("DELETE FROM participants WHERE id=? AND event_id=?", (pid, event_id))
        return jsonify(success=True)
    data = request.get_json()
    if data.get('team_id') is not None:
        db_exec("UPDATE participants SET team_id=? WHERE id=?", (data['team_id'] or None, pid))
    if 'score' in data:
        db_exec("UPDATE participants SET score=? WHERE id=?", (data['score'], pid))
    if 'name' in data:
        db_exec("UPDATE participants SET name=? WHERE id=?", (data['name'], pid))
    return jsonify(success=True)

# ============================================
# Host Event Screen
# ============================================
@app.route('/event/host/<int:id>')
@login_required
def host_event(id):
    user = get_current_user()
    event = row_to_dict(db_exec("SELECT * FROM events WHERE id=? AND host_id=?", (id,user['id']), fetchone=True))
    if not event: return redirect(url_for('dashboard'))
    teams = rows_to_list(db_exec("SELECT * FROM teams WHERE event_id=?", (id,), fetch=True))
    participants = rows_to_list(db_exec("SELECT p.*, t.name as team_name FROM participants p LEFT JOIN teams t ON p.team_id=t.id WHERE p.event_id=? ORDER BY p.code", (id,), fetch=True))
    return render_template('event/host.html', user=user, event=event, teams=teams, participants=participants)

# ============================================
# Participant Join
# ============================================
@app.route('/join/<code>', methods=['GET','POST'])
def join_event(code):
    event = row_to_dict(db_exec("SELECT * FROM events WHERE code=?", (code,), fetchone=True))
    if not event: return render_template('join.html', error='이벤트를 찾을 수 없습니다.', event=None, teams=[])
    teams = rows_to_list(db_exec("SELECT * FROM teams WHERE event_id=?", (event['id'],), fetch=True))
    if request.method == 'POST':
        name = request.form.get('name','').strip()
        team_id = request.form.get('team_id') or None
        pw = request.form.get('password','')
        if not name: return render_template('join.html', error='이름을 입력하세요.', event=event, teams=teams)
        # Check existing
        existing = db_exec("SELECT * FROM participants WHERE event_id=? AND name=?", (event['id'],name), fetchone=True)
        if existing:
            session['participant_id'] = existing['id']
            session['participant_event_id'] = event['id']
            session['participant_name'] = existing['name']
            return redirect(url_for('participant_event', code=code))
        # Get next code
        last = db_exec("SELECT MAX(code) as m FROM participants WHERE event_id=?", (event['id'],), fetchone=True)
        next_code = (last['m'] or 0) + 1
        pid = db_exec("INSERT INTO participants(event_id,team_id,name,password,code,ip) VALUES(?,?,?,?,?,?)",
                      (event['id'], int(team_id) if team_id else None, name, pw, next_code, request.remote_addr))
        if team_id:
            pass  # team member count tracked via query
        session['participant_id'] = pid
        session['participant_event_id'] = event['id']
        session['participant_name'] = name
        return redirect(url_for('participant_event', code=code))
    return render_template('join.html', event=event, teams=teams, error=None)

@app.route('/event/participant/<code>')
def participant_event(code):
    event = row_to_dict(db_exec("SELECT * FROM events WHERE code=?", (code,), fetchone=True))
    if not event: return redirect(url_for('landing_page'))
    pid = session.get('participant_id')
    if not pid: return redirect(url_for('join_event', code=code))
    participant = row_to_dict(db_exec("SELECT p.*, t.name as team_name FROM participants p LEFT JOIN teams t ON p.team_id=t.id WHERE p.id=?", (pid,), fetchone=True))
    if not participant: return redirect(url_for('join_event', code=code))
    teams = rows_to_list(db_exec("SELECT * FROM teams WHERE event_id=?", (event['id'],), fetch=True))
    participants = rows_to_list(db_exec("SELECT p.*, t.name as team_name FROM participants p LEFT JOIN teams t ON p.team_id=t.id WHERE p.event_id=?", (event['id'],), fetch=True))
    return render_template('event/participant.html', event=event, participant=participant, teams=teams, participants=participants)

# ============================================
# Monitor Screen
# ============================================
@app.route('/event/monitor/<int:id>')
def monitor_event(id):
    event = row_to_dict(db_exec("SELECT * FROM events WHERE id=?", (id,), fetchone=True))
    if not event: return redirect(url_for('landing_page'))
    teams = rows_to_list(db_exec("SELECT * FROM teams WHERE event_id=?", (id,), fetch=True))
    participants = rows_to_list(db_exec("SELECT p.*, t.name as team_name FROM participants p LEFT JOIN teams t ON p.team_id=t.id WHERE p.event_id=? ORDER BY p.score DESC", (id,), fetch=True))
    return render_template('event/monitor.html', event=event, teams=teams, participants=participants)

# ============================================
# File Upload
# ============================================
@app.route('/api/upload', methods=['POST'])
@login_required
def api_upload():
    f = request.files.get('file')
    if not f: return jsonify(success=False, error='파일이 없습니다.')
    ext = f.filename.rsplit('.',1)[-1].lower() if '.' in f.filename else 'png'
    fname = f"{make_id(16)}.{ext}"
    f.save(os.path.join(UPLOAD_FOLDER, fname))
    return jsonify(success=True, url=f'/static/uploads/{fname}')

# ============================================
# Game API (REST)
# ============================================
@app.route('/api/event/<int:event_id>/game', methods=['POST'])
@login_required
def api_game_create(event_id):
    data = request.get_json()
    game_type = data.get('type','퀴즈')
    settings = json.dumps(data.get('settings',{}), ensure_ascii=False)
    gid = db_exec("INSERT INTO games(event_id,type,settings) VALUES(?,?,?)", (event_id, game_type, settings))
    db_exec("UPDATE events SET current_game_id=? WHERE id=?", (gid, event_id))
    return jsonify(success=True, game_id=gid)

# ============================================
# Socket.IO Event Handlers
# ============================================

# --- Connection ---
@socketio.on('connect')
def on_connect():
    pass

@socketio.on('disconnect')
def on_disconnect():
    pass

# --- Host Events ---
@socketio.on('host:join')
def on_host_join(data):
    event_id = data.get('eventId')
    if event_id:
        join_room(f'event:{event_id}')
        join_room(f'event:{event_id}:host')
        emit('connected', {'role':'host','eventId':event_id})

@socketio.on('host:start_event')
def on_host_start_event(data):
    eid = data.get('eventId')
    db_exec("UPDATE events SET status='진행중', real_start_at=? WHERE id=?", (datetime.now(), eid))
    socketio.emit('event:started', {'eventId':eid}, room=f'event:{eid}')
    socketio.emit('event:updated', _get_event_data(eid), room=f'event:{eid}')

@socketio.on('host:end_event')
def on_host_end_event(data):
    eid = data.get('eventId')
    db_exec("UPDATE events SET status='종료', real_end_at=? WHERE id=?", (datetime.now(), eid))
    socketio.emit('event:ended', {'eventId':eid}, room=f'event:{eid}')
    socketio.emit('event:updated', _get_event_data(eid), room=f'event:{eid}')

@socketio.on('host:update_event')
def on_host_update_event(data):
    eid = data.get('eventId')
    update = data.get('update', {})
    fields = []
    vals = []
    allowed = ['title','display_mode','like_active','chat_active','chat_anonymous','game_anonymous','team_score_type']
    for k,v in update.items():
        key = k.replace('displayMode','display_mode').replace('likeActive','like_active').replace('chatActive','chat_active').replace('chatAnonymous','chat_anonymous').replace('gameAnonymous','game_anonymous').replace('teamScoreType','team_score_type')
        if key in allowed:
            fields.append(f"{key}=?")
            vals.append(v)
    if fields:
        vals.append(eid)
        db_exec(f"UPDATE events SET {','.join(fields)} WHERE id=?", vals)
    if update.get('likeActive') == False or update.get('like_active') == 0:
        db_exec("UPDATE events SET like_count=0 WHERE id=?", (eid,))
        db_exec("DELETE FROM like_participants WHERE event_id=?", (eid,))
    socketio.emit('event:updated', _get_event_data(eid), room=f'event:{eid}')

@socketio.on('host:display_mode')
def on_host_display_mode(data):
    eid = data.get('eventId')
    mode = data.get('displayMode','대기')
    db_exec("UPDATE events SET display_mode=? WHERE id=?", (mode, eid))
    socketio.emit('event:updated', _get_event_data(eid), room=f'event:{eid}')

# --- Host: Team & Participant Management ---
@socketio.on('host:manage_team')
def on_host_manage_team(data):
    eid = data.get('eventId')
    action = data.get('action')
    if action == 'create':
        name = data.get('name', '새 팀')
        db_exec("INSERT INTO teams(event_id,name) VALUES(?,?)", (eid, name))
    elif action == 'update':
        tid = data.get('teamId')
        update = data.get('update',{})
        if 'name' in update: db_exec("UPDATE teams SET name=? WHERE id=?", (update['name'], tid))
        if 'score' in update: db_exec("UPDATE teams SET score=? WHERE id=?", (update['score'], tid))
    elif action == 'delete':
        tid = data.get('teamId')
        db_exec("UPDATE participants SET team_id=NULL WHERE team_id=?", (tid,))
        db_exec("DELETE FROM teams WHERE id=?", (tid,))
    _emit_teams_update(eid)
    _emit_participants_update(eid)

@socketio.on('host:manage_participant')
def on_host_manage_participant(data):
    eid = data.get('eventId')
    action = data.get('action')
    pid = data.get('participantId')
    if action == 'update':
        update = data.get('update',{})
        if 'teamId' in update or 'team_id' in update:
            tid = update.get('teamId') or update.get('team_id')
            db_exec("UPDATE participants SET team_id=? WHERE id=?", (tid, pid))
        if 'score' in update:
            db_exec("UPDATE participants SET score=? WHERE id=?", (update['score'], pid))
        if 'name' in update:
            db_exec("UPDATE participants SET name=? WHERE id=?", (update['name'], pid))
    elif action == 'remove':
        db_exec("DELETE FROM participants WHERE id=?", (pid,))
        socketio.emit('event:kick', {'participantId':pid}, room=f'event:{eid}')
    _emit_participants_update(eid)
    _emit_teams_update(eid)

@socketio.on('host:update_team_score')
def on_host_update_team_score(data):
    eid = data.get('eventId')
    tid = data.get('teamId')
    score = data.get('score', 0)
    db_exec("UPDATE teams SET score=score+? WHERE id=?", (score, tid))
    _emit_teams_update(eid)

@socketio.on('host:update_participant_score')
def on_host_update_participant_score(data):
    eid = data.get('eventId')
    pid = data.get('participantId')
    score = data.get('score', 0)
    db_exec("UPDATE participants SET score=score+? WHERE id=?", (score, pid))
    _emit_participants_update(eid)

# --- Participant Events ---
@socketio.on('participant:join')
def on_participant_join(data):
    eid = data.get('eventId')
    pid = data.get('participantId')
    if eid:
        join_room(f'event:{eid}')
        join_room(f'event:{eid}:participant')
        if pid:
            join_room(f'participant:{pid}')
    _emit_participants_update(eid)

@socketio.on('event:like')
def on_event_like(data):
    eid = data.get('eventId')
    pid = data.get('participantId')
    try:
        db_exec("INSERT INTO like_participants(event_id,participant_id) VALUES(?,?)", (eid, pid))
        db_exec("UPDATE events SET like_count=like_count+1 WHERE id=?", (eid,))
    except:
        pass  # Already liked
    event = row_to_dict(db_exec("SELECT like_count FROM events WHERE id=?", (eid,), fetchone=True))
    socketio.emit('event:like_updated', {'eventId':eid, 'likeCount':event['like_count']}, room=f'event:{eid}')

# --- Chat ---
@socketio.on('chat:send')
def on_chat_send(data):
    eid = data.get('eventId')
    msg = data.get('message','')
    sender_id = data.get('senderId')
    sender_name = data.get('senderName','')
    msg_type = data.get('type','all')
    author = data.get('author','normal')
    team_id = data.get('teamId')
    anonymous = data.get('anonymous', False)
    mid = db_exec("INSERT INTO messages(event_id,sender_id,sender_name,type,author,team_id,message,anonymous) VALUES(?,?,?,?,?,?,?,?)",
                  (eid, sender_id, sender_name, msg_type, author, team_id, msg, 1 if anonymous else 0))
    msg_data = {
        'id': mid, 'eventId': eid, 'senderId': sender_id,
        'senderName': '익명' if anonymous else sender_name,
        'type': msg_type, 'author': author, 'message': msg,
        'teamId': team_id, 'anonymous': anonymous,
        'createdAt': datetime.now().isoformat()
    }
    if msg_type == 'team' and team_id:
        socketio.emit('chat:message', msg_data, room=f'team:{team_id}')
    else:
        socketio.emit('chat:message', msg_data, room=f'event:{eid}')

@socketio.on('chat:get_messages')
def on_chat_get_messages(data):
    eid = data.get('eventId')
    msg_type = data.get('type','all')
    page = data.get('page',1)
    per_page = data.get('perPage',50)
    offset = (page-1)*per_page
    if msg_type == 'all':
        msgs = rows_to_list(db_exec("SELECT * FROM messages WHERE event_id=? AND type='all' ORDER BY created_at DESC LIMIT ? OFFSET ?", (eid,per_page,offset), fetch=True))
    else:
        team_id = data.get('teamId')
        msgs = rows_to_list(db_exec("SELECT * FROM messages WHERE event_id=? AND type='team' AND team_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?", (eid,team_id,per_page,offset), fetch=True))
    emit('chat:messages', {'messages': list(reversed(msgs)), 'page':page})

# --- Games ---
@socketio.on('host:prepare_game')
def on_host_prepare_game(data):
    eid = data.get('eventId')
    game_type = data.get('type','퀴즈')
    settings = data.get('settings',{})
    # End current game if exists
    cur = db_exec("SELECT current_game_id FROM events WHERE id=?", (eid,), fetchone=True)
    if cur and cur['current_game_id']:
        db_exec("UPDATE games SET status='종료', ended_at=? WHERE id=? AND status='진행중'", (datetime.now(), cur['current_game_id']))
    gid = db_exec("INSERT INTO games(event_id,type,settings,status) VALUES(?,?,?,?)",
                  (eid, game_type, json.dumps(settings, ensure_ascii=False), '대기'))
    db_exec("UPDATE events SET current_game_id=?, display_mode=? WHERE id=?", (gid, game_type, eid))
    # Initialize responses for all participants
    participants = rows_to_list(db_exec("SELECT id FROM participants WHERE event_id=? AND status='참가'", (eid,), fetch=True))
    responses = []
    for p in participants:
        resp = {'participantId': p['id'], 'timestamp': datetime.now().isoformat()}
        if game_type == '빙고':
            size = settings.get('bingo',{}).get('size',5)
            resp['bingo'] = [[''] * size for _ in range(size)]
        elif game_type == '부저카운트':
            resp['buzzerCount'] = {'clicks': 0}
        elif game_type == '코드넘버':
            board_size = settings.get('codeNumber',{}).get('boardSize',9)
            resp['codeNumber'] = {'board': [None]*board_size, 'placedNumbers':[], 'score':0, 'longestSequence':0}
        responses.append(resp)
    db_exec("UPDATE games SET responses=? WHERE id=?", (json.dumps(responses, ensure_ascii=False), gid))
    socketio.emit('game:prepared', {'eventId':eid, 'gameId':gid, 'type':game_type, 'settings':settings}, room=f'event:{eid}')
    socketio.emit('event:updated', _get_event_data(eid), room=f'event:{eid}')

@socketio.on('host:start_game')
def on_host_start_game(data):
    eid = data.get('eventId')
    gid = data.get('gameId')
    settings = data.get('settings')
    if settings:
        db_exec("UPDATE games SET settings=? WHERE id=?", (json.dumps(settings, ensure_ascii=False), gid))
    db_exec("UPDATE games SET status='진행중', started_at=? WHERE id=?", (datetime.now(), gid))
    game = row_to_dict(db_exec("SELECT * FROM games WHERE id=?", (gid,), fetchone=True))
    game_settings = json.loads(game['settings'] or '{}')
    # Start timer if timeLimit
    time_limit = game_settings.get('timeLimit')
    if time_limit and time_limit > 0:
        _start_game_timer(eid, gid, time_limit)
    socketio.emit('game:started', {
        'eventId':eid, 'gameId':gid, 'type':game['type'],
        'settings':game_settings, 'status':'진행중'
    }, room=f'event:{eid}')

@socketio.on('host:end_game')
def on_host_end_game(data):
    eid = data.get('eventId')
    gid = data.get('gameId')
    _end_game(eid, gid)

@socketio.on('host:update_game')
def on_host_update_game(data):
    eid = data.get('eventId')
    gid = data.get('gameId')
    settings = data.get('settings',{})
    game = row_to_dict(db_exec("SELECT settings FROM games WHERE id=?", (gid,), fetchone=True))
    cur_settings = json.loads(game['settings'] or '{}')
    cur_settings.update(settings)
    db_exec("UPDATE games SET settings=? WHERE id=?", (json.dumps(cur_settings, ensure_ascii=False), gid))
    socketio.emit('game:updated', {'eventId':eid,'gameId':gid,'settings':cur_settings}, room=f'event:{eid}')

# --- Game: Submit Answer (Quiz/Buzzer/Subjective/Order) ---
@socketio.on('game:submit_answer')
def on_game_submit_answer(data):
    gid = data.get('gameId')
    pid = data.get('participantId')
    answer = data.get('answer')
    game = row_to_dict(db_exec("SELECT * FROM games WHERE id=?", (gid,), fetchone=True))
    if not game or game['status'] != '진행중': return
    responses = json.loads(game['responses'] or '[]')
    found = False
    for r in responses:
        if r['participantId'] == pid:
            r['answer'] = answer
            r['timestamp'] = datetime.now().isoformat()
            found = True
            break
    if not found:
        responses.append({'participantId':pid, 'answer':answer, 'timestamp':datetime.now().isoformat()})
    db_exec("UPDATE games SET responses=? WHERE id=?", (json.dumps(responses, ensure_ascii=False), gid))
    eid = game['event_id']
    # Notify host
    p = row_to_dict(db_exec("SELECT name FROM participants WHERE id=?", (pid,), fetchone=True))
    socketio.emit('game:response', {
        'eventId':eid, 'gameId':gid, 'participantId':pid,
        'participantName': p['name'] if p else '', 'answer':answer
    }, room=f'event:{eid}')

# --- Game: Buzzer Count Click ---
@socketio.on('game:buzzer_count_click')
def on_buzzer_count_click(data):
    gid = data.get('gameId')
    pid = data.get('participantId')
    eid = data.get('eventId')
    game = row_to_dict(db_exec("SELECT * FROM games WHERE id=?", (gid,), fetchone=True))
    if not game or game['status'] != '진행중': return
    settings = json.loads(game['settings'] or '{}')
    responses = json.loads(game['responses'] or '[]')
    target = settings.get('buzzerCount',{}).get('targetClicks')
    for r in responses:
        if r['participantId'] == pid:
            bc = r.get('buzzerCount',{'clicks':0})
            bc['clicks'] = bc.get('clicks',0) + 1
            r['buzzerCount'] = bc
            # Check winner
            if target and bc['clicks'] >= target:
                p = row_to_dict(db_exec("SELECT name, team_id FROM participants WHERE id=?", (pid,), fetchone=True))
                winner = {'type':'individual','id':pid,'name':p['name'] if p else '','clicks':bc['clicks']}
                settings['buzzerCount'] = settings.get('buzzerCount',{})
                settings['buzzerCount']['winner'] = winner
                db_exec("UPDATE games SET settings=?, responses=?, status='종료', ended_at=? WHERE id=?",
                        (json.dumps(settings,ensure_ascii=False), json.dumps(responses,ensure_ascii=False), datetime.now(), gid))
                socketio.emit('game:buzzer_count_winner', {'eventId':eid,'gameId':gid,'winner':winner}, room=f'event:{eid}')
                return
            socketio.emit('game:buzzer_count_click', {
                'eventId':eid,'gameId':gid,'participantId':pid,'clicks':bc['clicks']
            }, room=f'participant:{pid}')
            # Throttled emit to host only
            throttled_emit(f'bc:{eid}:{pid}', 'game:buzzer_count_click', {
                'eventId':eid,'gameId':gid,'participantId':pid,'clicks':bc['clicks']
            }, room=f'event:{eid}', interval=0.3)
            break
    db_exec("UPDATE games SET responses=? WHERE id=?", (json.dumps(responses, ensure_ascii=False), gid))

# --- Game: Bingo ---
@socketio.on('game:bingo_set')
def on_bingo_set(data):
    gid = data.get('gameId')
    pid = data.get('participantId')
    bingo = data.get('bingo')
    game = row_to_dict(db_exec("SELECT * FROM games WHERE id=?", (gid,), fetchone=True))
    if not game: return
    responses = json.loads(game['responses'] or '[]')
    settings = json.loads(game['settings'] or '{}')
    for r in responses:
        if r['participantId'] == pid:
            r['bingo'] = bingo
            break
    # Collect all words
    all_items = set(settings.get('bingo',{}).get('items',[]))
    for row in bingo:
        for word in row:
            if word.strip(): all_items.add(word)
    settings.setdefault('bingo',{})['items'] = list(all_items)
    db_exec("UPDATE games SET responses=?, settings=? WHERE id=?",
            (json.dumps(responses,ensure_ascii=False), json.dumps(settings,ensure_ascii=False), gid))
    socketio.emit('game:bingo_updated', {'gameId':gid,'participantId':pid}, room=f'event:{game["event_id"]}')

@socketio.on('game:bingo_turn')
def on_bingo_turn(data):
    gid = data.get('gameId')
    pid = data.get('participantId')
    answer = data.get('answer','')
    game = row_to_dict(db_exec("SELECT * FROM games WHERE id=?", (gid,), fetchone=True))
    if not game: return
    settings = json.loads(game['settings'] or '{}')
    responses = json.loads(game['responses'] or '[]')
    bingo_settings = settings.get('bingo',{})
    # Mark correct in all boards
    bingo_settings.setdefault('correctItems',[])
    if answer not in bingo_settings['correctItems']:
        bingo_settings['correctItems'].append(answer)
    # Next player turn
    curr_idx = 0
    for i, r in enumerate(responses):
        if r['participantId'] == pid:
            curr_idx = i
            break
    next_idx = (curr_idx + 1) % len(responses) if responses else 0
    if responses:
        bingo_settings['playerTurn'] = responses[next_idx]['participantId']
        bingo_settings['canTurn'] = True
    settings['bingo'] = bingo_settings
    db_exec("UPDATE games SET settings=?, responses=? WHERE id=?",
            (json.dumps(settings,ensure_ascii=False), json.dumps(responses,ensure_ascii=False), gid))
    socketio.emit('game:bingo_turn_update', {
        'eventId':game['event_id'],'gameId':gid,'answer':answer,
        'correctItems':bingo_settings['correctItems'],
        'playerTurn':bingo_settings.get('playerTurn'),
        'settings': bingo_settings
    }, room=f'event:{game["event_id"]}')

# --- Game: Code Number ---
@socketio.on('game:code_number_place')
def on_code_number_place(data):
    gid = data.get('gameId')
    pid = data.get('participantId')
    position = data.get('position')
    game = row_to_dict(db_exec("SELECT * FROM games WHERE id=?", (gid,), fetchone=True))
    if not game or game['status'] != '진행중': return
    settings = json.loads(game['settings'] or '{}')
    responses = json.loads(game['responses'] or '[]')
    cn = settings.get('codeNumber',{})
    current_number = cn.get('currentNumber')
    if current_number is None: return
    for r in responses:
        if r['participantId'] == pid:
            cd = r.get('codeNumber',{'board':[None]*cn.get('boardSize',9),'placedNumbers':[],'score':0})
            board = cd['board']
            if board[position] is not None and current_number == cd.get('lastPlacedNumber'):
                # Re-place: move last number
                old_pos = cd.get('lastPlacedPosition')
                if old_pos is not None: board[old_pos] = None
            board[position] = current_number
            cd['board'] = board
            if current_number not in cd.get('placedNumbers',[]):
                cd.setdefault('placedNumbers',[]).append(current_number)
            cd['lastPlacedPosition'] = position
            cd['lastPlacedNumber'] = current_number
            # Calculate score
            score = 0
            longest = 0
            cur_seq = 0
            for i, v in enumerate(board):
                if v is not None:
                    if i == 0 or board[i-1] is None or v > board[i-1]:
                        cur_seq += 1
                    else:
                        cur_seq = 1
                    longest = max(longest, cur_seq)
                else:
                    cur_seq = 0
            cd['score'] = longest
            cd['longestSequence'] = longest
            r['codeNumber'] = cd
            break
    db_exec("UPDATE games SET responses=? WHERE id=?", (json.dumps(responses,ensure_ascii=False), gid))
    socketio.emit('game:code_number_place', {
        'eventId':game['event_id'],'gameId':gid,'participantId':pid,
        'position':position,'number':current_number
    }, room=f'event:{game["event_id"]}')

@socketio.on('host:code_number_next')
def on_code_number_next(data):
    gid = data.get('gameId')
    eid = data.get('eventId')
    game = row_to_dict(db_exec("SELECT * FROM games WHERE id=?", (gid,), fetchone=True))
    if not game: return
    settings = json.loads(game['settings'] or '{}')
    cn = settings.get('codeNumber',{})
    max_num = cn.get('maxNumber',30)
    new_num = random.randint(1, max_num)
    cn['currentNumber'] = new_num
    settings['codeNumber'] = cn
    db_exec("UPDATE games SET settings=? WHERE id=?", (json.dumps(settings,ensure_ascii=False), gid))
    socketio.emit('game:code_number_next', {
        'eventId':eid,'gameId':gid,'number':new_num,'settings':cn
    }, room=f'event:{eid}')

# Auto mode for code number
code_number_timers = {}

@socketio.on('host:code_number_start_auto')
def on_code_number_start_auto(data):
    gid = data.get('gameId')
    eid = data.get('eventId')
    game = row_to_dict(db_exec("SELECT * FROM games WHERE id=?", (gid,), fetchone=True))
    if not game: return
    settings = json.loads(game['settings'] or '{}')
    cn = settings.get('codeNumber',{})
    speed = cn.get('gameSpeed', 3)
    def auto_loop():
        while gid in code_number_timers:
            g_check = None
            with app.app_context():
                db2 = sqlite3.connect(DATABASE)
                db2.row_factory = sqlite3.Row
                g_check = dict(db2.execute("SELECT status, settings FROM games WHERE id=?", (gid,)).fetchone() or {})
                db2.close()
            if not g_check or g_check.get('status') != '진행중':
                break
            s = json.loads(g_check.get('settings','{}'))
            cn2 = s.get('codeNumber',{})
            max_num = cn2.get('maxNumber',30)
            new_num = random.randint(1, max_num)
            cn2['currentNumber'] = new_num
            s['codeNumber'] = cn2
            with app.app_context():
                db3 = sqlite3.connect(DATABASE)
                db3.execute("UPDATE games SET settings=? WHERE id=?", (json.dumps(s,ensure_ascii=False), gid))
                db3.commit()
                db3.close()
            socketio.emit('game:code_number_next', {'eventId':eid,'gameId':gid,'number':new_num,'settings':cn2}, room=f'event:{eid}')
            time.sleep(speed)
        code_number_timers.pop(gid, None)
    code_number_timers[gid] = True
    t = threading.Thread(target=auto_loop, daemon=True)
    t.start()
    emit('code_number_auto_started', {'gameId':gid})

@socketio.on('host:code_number_stop_auto')
def on_code_number_stop_auto(data):
    gid = data.get('gameId')
    code_number_timers.pop(gid, None)
    emit('code_number_auto_stopped', {'gameId':gid})

# --- Host: Grade & Award Points ---
@socketio.on('host:grade_answers')
def on_host_grade_answers(data):
    gid = data.get('gameId')
    grades = data.get('grades',[])  # [{participantId, isCorrect, earnedPoints}]
    game = row_to_dict(db_exec("SELECT * FROM games WHERE id=?", (gid,), fetchone=True))
    if not game: return
    responses = json.loads(game['responses'] or '[]')
    for grade in grades:
        for r in responses:
            if r['participantId'] == grade['participantId']:
                r['isCorrect'] = grade.get('isCorrect', False)
                r['earnedPoints'] = grade.get('earnedPoints', 0)
                break
    db_exec("UPDATE games SET responses=? WHERE id=?", (json.dumps(responses,ensure_ascii=False), gid))
    socketio.emit('game:graded', {'eventId':game['event_id'],'gameId':gid,'grades':grades}, room=f'event:{game["event_id"]}')

@socketio.on('host:award_points')
def on_host_award_points(data):
    gid = data.get('gameId')
    eid = data.get('eventId')
    game = row_to_dict(db_exec("SELECT * FROM games WHERE id=?", (gid,), fetchone=True))
    if not game: return
    responses = json.loads(game['responses'] or '[]')
    earned_list = []
    for r in responses:
        points = r.get('earnedPoints', 0)
        if points > 0:
            db_exec("UPDATE participants SET score=score+? WHERE id=?", (points, r['participantId']))
            earned_list.append({'participantId':r['participantId'], 'earnedPoints':points})
            # Update team score too
            p = row_to_dict(db_exec("SELECT team_id FROM participants WHERE id=?", (r['participantId'],), fetchone=True))
            if p and p.get('team_id'):
                event = row_to_dict(db_exec("SELECT team_score_type FROM events WHERE id=?", (eid,), fetchone=True))
                db_exec("UPDATE teams SET score=score+? WHERE id=?", (points, p['team_id']))
    socketio.emit('game:points_awarded', {'eventId':eid,'gameId':gid,'earned':earned_list}, room=f'event:{eid}')
    _emit_participants_update(eid)
    _emit_teams_update(eid)

@socketio.on('host:correct_answers')
def on_host_correct_answers(data):
    gid = data.get('gameId')
    correct = data.get('correctAnswers',[])
    game = row_to_dict(db_exec("SELECT * FROM games WHERE id=?", (gid,), fetchone=True))
    if not game: return
    settings = json.loads(game['settings'] or '{}')
    settings['correctAnswers'] = correct
    responses = json.loads(game['responses'] or '[]')
    points = settings.get('points', 10)
    # Auto-grade
    for r in responses:
        ans = r.get('answer')
        if ans is not None:
            if game['type'] in ('객관식퀴즈','퀴즈'):
                r['isCorrect'] = str(ans) in [str(c) for c in correct]
            elif game['type'] == '주관식퀴즈':
                r['isCorrect'] = str(ans).strip().lower() in [str(c).strip().lower() for c in correct]
            else:
                r['isCorrect'] = str(ans) in [str(c) for c in correct]
            r['earnedPoints'] = points if r['isCorrect'] else 0
    db_exec("UPDATE games SET settings=?, responses=? WHERE id=?",
            (json.dumps(settings,ensure_ascii=False), json.dumps(responses,ensure_ascii=False), gid))
    socketio.emit('game:answers_revealed', {
        'eventId':game['event_id'],'gameId':gid,'correctAnswers':correct,'responses':responses
    }, room=f'event:{game["event_id"]}')

# --- Host: Lottery ---
@socketio.on('host:lottery_add')
def on_host_lottery_add(data):
    gid = data.get('gameId')
    eid = data.get('eventId')
    game = row_to_dict(db_exec("SELECT * FROM games WHERE id=?", (gid,), fetchone=True))
    if not game: return
    settings = json.loads(game['settings'] or '{}')
    lottery = settings.get('lottery',{})
    winner_count = lottery.get('winnerCount',1)
    participants = rows_to_list(db_exec("SELECT id, name FROM participants WHERE event_id=? AND status='참가'", (eid,), fetch=True))
    existing_winners = lottery.get('participants',[])
    available = [p for p in participants if str(p['id']) not in existing_winners and p['name'] not in existing_winners]
    if available:
        winners = random.sample(available, min(winner_count, len(available)))
        for w in winners:
            existing_winners.append(w['name'])
        lottery['participants'] = existing_winners
        settings['lottery'] = lottery
        db_exec("UPDATE games SET settings=? WHERE id=?", (json.dumps(settings,ensure_ascii=False), gid))
        socketio.emit('game:lottery_result', {
            'eventId':eid,'gameId':gid,'winners':[w['name'] for w in winners],'allWinners':existing_winners
        }, room=f'event:{eid}')

# --- Timer ---
@socketio.on('host:prepare_timer')
def on_host_prepare_timer(data):
    eid = data.get('eventId')
    settings = data.get('settings',{})
    gid = db_exec("INSERT INTO games(event_id,type,settings,status) VALUES(?,?,?,?)",
                  (eid, '타이머', json.dumps(settings,ensure_ascii=False), '대기'))
    db_exec("UPDATE events SET timer_id=? WHERE id=?", (gid, eid))
    socketio.emit('timer:prepared', {'eventId':eid,'timerId':gid,'settings':settings}, room=f'event:{eid}')

@socketio.on('host:start_timer')
def on_host_start_timer(data):
    eid = data.get('eventId')
    tid = data.get('timerId')
    game = row_to_dict(db_exec("SELECT * FROM games WHERE id=?", (tid,), fetchone=True))
    if not game: return
    settings = json.loads(game['settings'] or '{}')
    time_limit = settings.get('timeLimit', 60)
    db_exec("UPDATE games SET status='진행중', started_at=? WHERE id=?", (datetime.now(), tid))
    active_timers[eid] = {
        'timerId': tid, 'timeLimit': time_limit,
        'startedAt': time.time(), 'remaining': time_limit
    }
    socketio.emit('timer:started', {
        'eventId':eid,'timerId':tid,'timeLimit':time_limit,
        'startedAt':datetime.now().isoformat()
    }, room=f'event:{eid}')
    # Background timer
    def timer_tick():
        while eid in active_timers and active_timers[eid]['remaining'] > 0:
            time.sleep(1)
            if eid not in active_timers: break
            active_timers[eid]['remaining'] -= 1
            socketio.emit('timer:tick', {
                'eventId':eid, 'remaining': active_timers[eid]['remaining']
            }, room=f'event:{eid}')
        if eid in active_timers:
            del active_timers[eid]
            with app.app_context():
                db2 = sqlite3.connect(DATABASE)
                db2.execute("UPDATE games SET status='종료', ended_at=? WHERE id=?", (datetime.now(), tid))
                db2.commit()
                db2.close()
            socketio.emit('timer:ended', {'eventId':eid,'timerId':tid}, room=f'event:{eid}')
    threading.Thread(target=timer_tick, daemon=True).start()

@socketio.on('host:end_timer')
def on_host_end_timer(data):
    eid = data.get('eventId')
    tid = data.get('timerId')
    active_timers.pop(eid, None)
    db_exec("UPDATE games SET status='종료', ended_at=? WHERE id=?", (datetime.now(), tid))
    socketio.emit('timer:ended', {'eventId':eid,'timerId':tid}, room=f'event:{eid}')

@socketio.on('timer:give_time')
def on_timer_give_time(data):
    eid = data.get('eventId')
    add_time = data.get('time', 0)
    if eid in active_timers:
        active_timers[eid]['remaining'] += add_time

# --- Dashboard Socket ---
@socketio.on('dashboard:join')
def on_dashboard_join(data):
    eid = data.get('eventId')
    if eid:
        join_room(f'dashboard:event:{eid}')

# --- Game Data Fetch ---
@socketio.on('game:get_current')
def on_game_get_current(data):
    eid = data.get('eventId')
    event = row_to_dict(db_exec("SELECT current_game_id FROM events WHERE id=?", (eid,), fetchone=True))
    if event and event['current_game_id']:
        game = row_to_dict(db_exec("SELECT * FROM games WHERE id=?", (event['current_game_id'],), fetchone=True))
        if game:
            emit('game:current', {
                'gameId':game['id'], 'type':game['type'], 'status':game['status'],
                'settings':json.loads(game['settings'] or '{}'),
                'responses':json.loads(game['responses'] or '[]')
            })

@socketio.on('game:get_current_response')
def on_game_get_current_response(data):
    gid = data.get('gameId')
    pid = data.get('participantId')
    game = row_to_dict(db_exec("SELECT responses FROM games WHERE id=?", (gid,), fetchone=True))
    if game:
        responses = json.loads(game['responses'] or '[]')
        for r in responses:
            if r['participantId'] == pid:
                emit('game:my_response', r)
                return
    emit('game:my_response', None)

# ============================================
# Helper functions for socket emissions
# ============================================
def _get_event_data(eid):
    event = row_to_dict(db_exec("SELECT * FROM events WHERE id=?", (eid,), fetchone=True))
    return event or {}

def _emit_teams_update(eid):
    teams = rows_to_list(db_exec("SELECT * FROM teams WHERE event_id=? ORDER BY created_at", (eid,), fetch=True))
    socketio.emit('teams:updated', {'eventId':eid, 'teams':teams}, room=f'event:{eid}')

def _emit_participants_update(eid):
    participants = rows_to_list(db_exec("SELECT p.*, t.name as team_name FROM participants p LEFT JOIN teams t ON p.team_id=t.id WHERE p.event_id=? ORDER BY p.code", (eid,), fetch=True))
    socketio.emit('participants:updated', {'eventId':eid, 'participants':participants}, room=f'event:{eid}')

def _start_game_timer(eid, gid, time_limit):
    def timer_end():
        time.sleep(time_limit)
        with app.app_context():
            _end_game(eid, gid)
    threading.Thread(target=timer_end, daemon=True).start()

def _end_game(eid, gid):
    db_exec("UPDATE games SET status='종료', ended_at=? WHERE id=?", (datetime.now(), gid))
    game = row_to_dict(db_exec("SELECT * FROM games WHERE id=?", (gid,), fetchone=True))
    if game:
        socketio.emit('game:ended', {
            'eventId':eid, 'gameId':gid, 'type':game['type'],
            'settings':json.loads(game['settings'] or '{}'),
            'responses':json.loads(game['responses'] or '[]')
        }, room=f'event:{eid}')

# ============================================
# Static files
# ============================================
@app.route('/static/sounds/<path:filename>')
def serve_sound(filename):
    return send_from_directory(os.path.join(app.static_folder, 'sounds'), filename)

# ============================================
# Main
# ============================================
if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 8080))
    print("=" * 50)
    print("🔥 THE TEAM COMPANY 팀빌딩 플랫폼")
    print(f"🌐 http://0.0.0.0:{port}")
    print(f"📁 Database: {DATABASE}")
    print(f"⚡ v2.0.0 · threading mode")
    print("=" * 50)
    socketio.run(app, host='0.0.0.0', port=port, debug=False, allow_unsafe_werkzeug=True)
