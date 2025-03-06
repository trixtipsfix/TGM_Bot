from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
import asyncio
from telethon import TelegramClient, events
from telethon.sessions import StringSession
from bot_server import validate_and_associate_key, PATTERN_44
from key_manager import load_keys, save_keys
import os
import json
import random
import string
from datetime import datetime, timedelta
import threading
from functools import wraps

app = Flask(__name__)
app.secret_key = 'verysecseckey'  # Required for flash messages and session

# Admin credentials (hardcoded for simplicity; use a database in production)
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "securepassword123"  # Change this in production

# Configuration
BASE_CONFIG_DIR = "./configs"

# Delay times for key categories (editable by admin)
DELAY_TIMES = {
    'normal': 1.2,
    'premium': 0.7,
    'titanium': 0.0
}

# Helper functions
def ensure_config_dir():
    os.makedirs(BASE_CONFIG_DIR, exist_ok=True)

def get_user_config_path(key):
    return os.path.join(BASE_CONFIG_DIR, key, "config.json")

def load_user_config(key):
    config_path = get_user_config_path(key)
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return json.load(f)
        return None
    except json.JSONDecodeError:
        return None

def save_user_config(key, config_data):
    user_folder = os.path.join(BASE_CONFIG_DIR, key)
    os.makedirs(user_folder, exist_ok=True)
    config_path = get_user_config_path(key)
    with open(config_path, 'w') as f:
        json.dump(config_data, f, indent=4)

def get_key_validity_days(key):
    keys_data = load_keys()
    key_data = keys_data.get(key)
    if key_data and key_data.get("expiration"):
        expiration_date = datetime.strptime(key_data["expiration"], "%Y-%m-%d")
        current_date = datetime.now()
        days_left = (expiration_date - current_date).days
        return max(0, days_left)
    return None

async def check_session_validity(session_string, api_id, api_hash):
    client = TelegramClient(StringSession(session_string), api_id, api_hash)
    try:
        await client.connect()
        authorized = await client.is_user_authorized()
        await client.disconnect()
        return authorized
    except Exception as e:
        print(f"ERROR: Thunderbot session check failed: {str(e)}")
        await client.disconnect()
        return False

async def revoke_session(session_string, api_id, api_hash):
    client = TelegramClient(StringSession(session_string), api_id, api_hash)
    try:
        await client.connect()
        if await client.is_user_authorized():
            await client.log_out()
            print(f"INFO: Previous session revoked for key")
        await client.disconnect()
    except Exception as e:
        print(f"ERROR: Failed to revoke previous session: {str(e)}")
        await client.disconnect()

def is_session_valid(session_string, api_id, api_hash):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    result = loop.run_until_complete(check_session_validity(session_string, api_id, api_hash))
    loop.close()
    return result

async def get_chats(session_string, api_id, api_hash):
    client = TelegramClient(StringSession(session_string), api_id, api_hash)
    try:
        await client.connect()
        if not await client.is_user_authorized():
            await client.disconnect()
            return None
        dialogs = await client.get_dialogs()
        chats = [{'id': dialog.id, 'name': dialog.name or 'Sin Nombre'} for dialog in dialogs]
        await client.disconnect()
        return chats
    except Exception as e:
        print(f"ERROR: Failed to fetch chats for editing: {str(e)}")
        await client.disconnect()
        return None

def fetch_chats_sync(session_string, api_id, api_hash):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    chats = loop.run_until_complete(get_chats(session_string, api_id, api_hash))
    loop.close()
    return chats

# Decorators
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            flash("Please log in as admin to access this page.", "error")
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'key' not in session:
            flash("Please log in to access this page.", "error")
            return redirect(url_for('login'))
        validity_days = get_key_validity_days(session['key'])
        if validity_days is None or validity_days <= 0:
            flash("Your key has expired. Please renew it or use a valid key.", "error")
            session.pop('key', None)
            session.pop('telegram_session', None)
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    validity_days = get_key_validity_days(session.get('key')) if 'key' in session else None
    return render_template('home.html', validity_days=validity_days)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        key = request.form['key']
        if validate_and_associate_key(key):
            validity_days = get_key_validity_days(key)
            if validity_days is None or validity_days <= 0:
                flash("This key has expired. Please renew it or use a valid key.", "error")
                return render_template('login.html', validity_days=None)
            
            # Revoke any existing session
            if 'telegram_session' in session:
                config = load_user_config(key)
                if config and all(k in config for k in ['api_id', 'api_hash']):
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    loop.run_until_complete(revoke_session(session['telegram_session'], config['api_id'], config['api_hash']))
                    loop.close()
                    print(f"INFO: Revoked previous session for key {key}")
            
            session['key'] = key
            ensure_config_dir()
            config = load_user_config(key)
            if not config or not all(k in config for k in ['api_id', 'api_hash', 'phone']):
                flash("Configuration incomplete. Please set up your Thunderbot.", "warning")
                return redirect(url_for('setup'))
            
            if 'telegram_session' not in session:
                flash("New device detected. Please set up Thunderbot.", "warning")
                return redirect(url_for('setup'))
            
            if not is_session_valid(session['telegram_session'], config['api_id'], config['api_hash']):
                flash("Session invalid. Please re-authenticate.", "warning")
                return redirect(url_for('setup'))
            
            flash("Logged in successfully!", "success")
            return redirect(url_for('dashboard'))
        flash("Invalid or expired key. Please try again.", "error")
        return render_template('login.html', validity_days=None)
    
    validity_days = get_key_validity_days(session.get('key')) if 'key' in session else None
    return render_template('login.html', validity_days=validity_days)

@app.route('/logout')
@key_required
def logout():
    if 'key' in session:
        key = session['key']
        if key in active_clients:
            del active_clients[key]  # Thread will handle cleanup
        session.pop('key', None)
        session.pop('telegram_session', None)  # Clear client-side session
        flash("Logged out successfully.", "success")
    return redirect(url_for('index'))

@app.route('/setup', methods=['GET', 'POST'])
@key_required
def setup():
    if request.method == 'POST':
        data = request.json
        config = {
            "api_id": data['api_id'],
            "api_hash": data['api_hash'],
            "phone": data['phone'],
            "chats_origen": [],
            "chat_destino": None
        }
        save_user_config(session['key'], config)
        flash("Setup saved successfully. Please authenticate with Telegram.", "success")
        return jsonify({'success': True})
    validity_days = get_key_validity_days(session['key'])
    return render_template('setup.html', validity_days=validity_days)

@app.route('/telegram_auth', methods=['POST'])
@key_required
async def telegram_auth():
    data = request.json
    config = load_user_config(session['key'])
    if not config:
        return jsonify({'error': 'Configuration not found'}), 500
    
    session_string = session.get('telegram_session_temp', '')
    client = TelegramClient(StringSession(session_string), config['api_id'], config['api_hash'])
    print("INFO: Thunderbot Client Created")
    
    try:
        await client.connect()
        print("INFO: Thunderbot Client Connected")
        
        if not await client.is_user_authorized():
            if 'code' not in data:
                try:
                    sent_code = await client.send_code_request(config['phone'])
                    session['telegram_session_temp'] = client.session.save()
                    print(f"INFO: Code Required, phone_code_hash: {sent_code.phone_code_hash}, session: {session['telegram_session_temp']}")
                    await client.disconnect()
                    return jsonify({
                        'status': 'code_required',
                        'phone_code_hash': sent_code.phone_code_hash
                    })
                except Exception as e:
                    await client.disconnect()
                    print(f"ERROR: Failed to send code request: {str(e)}")
                    return jsonify({'error': f'Failed to send code request: {str(e)}'}), 400
            
            else:
                if 'phone_code_hash' not in data:
                    await client.disconnect()
                    print("ERROR: phone_code_hash missing")
                    return jsonify({'error': 'phone_code_hash is required'}), 400
                try:
                    print(f"DEBUG: Attempting sign-in with code: {data['code']}, hash: {data['phone_code_hash']}, session: {session['telegram_session_temp']}")
                    await client.sign_in(
                        phone=config['phone'],
                        code=data['code'],
                        phone_code_hash=data['phone_code_hash']
                    )
                    print("INFO: Thunderbot Signed In")
                    session['telegram_session'] = client.session.save()
                    session.pop('telegram_session_temp', None)
                    dialogs = await client.get_dialogs()
                    if not isinstance(dialogs, (list, tuple)):
                        raise ValueError(f"Expected list of dialogs, got {type(dialogs)}: {dialogs}")
                    chats = [{'id': dialog.id, 'name': dialog.name or 'Sin Nombre'} for dialog in dialogs]
                    await client.disconnect()
                    print("INFO: Thunderbot Successfully retrieved chats")
                    return jsonify({'status': 'success', 'chats': chats})
                except Exception as e:
                    await client.disconnect()
                    print(f"ERROR: Thunderbot Sign-in failed: {str(e)}")
                    if "The confirmation code has expired" in str(e):
                        flash("The confirmation code has expired. Please request a new one.", "error")
                        return jsonify({'error': 'Code expired, please request a new one'}), 400
                    return jsonify({'error': f'Sign-in failed: {str(e)}'}), 400
        
        dialogs = await client.get_dialogs()
        if not isinstance(dialogs, (list, tuple)):
            raise ValueError(f"Expected list of dialogs, got {type(dialogs)}: {dialogs}")
        chats = [{'id': dialog.id, 'name': dialog.name or 'Sin Nombre'} for dialog in dialogs]
        await client.disconnect()
        print("INFO: Thunderbot Successfully retrieved chats for authorized user")
        return jsonify({'chats': chats})
    
    except Exception as e:
        if client.is_connected():
            await client.disconnect()
        print(f"ERROR: Thunderbot Connection failed: {str(e)}")
        return jsonify({'error': f'Failed to connect to Telegram: {str(e)}'}), 500

@app.route('/edit_chats', methods=['GET', 'POST'])
@key_required
def edit_chats():
    config = load_user_config(session['key'])
    if not config:
        flash("Configuration not found. Please set up Thunderbot.", "error")
        return redirect(url_for('setup'))
    
    if 'telegram_session' not in session:
        flash("Session not found. Please re-authenticate.", "warning")
        return redirect(url_for('setup'))
    
    if request.method == 'POST':
        data = request.json
        config['chats_origen'] = data['source_chats']
        config['chat_destino'] = data['dest_chat']
        save_user_config(session['key'], config)
        flash("Chats updated successfully!", "success")
        return jsonify({'success': True})
    
    chats = fetch_chats_sync(session['telegram_session'], config['api_id'], config['api_hash'])
    if chats is None:
        flash("Session invalid. Please re-authenticate.", "warning")
        return redirect(url_for('setup'))
    
    validity_days = get_key_validity_days(session['key'])
    return render_template('edit_chats.html', chats=chats, config=config, validity_days=validity_days)

@app.route('/save_chats', methods=['POST'])
@key_required
def save_chats():
    if 'telegram_session' not in session:
        return jsonify({'error': 'Session not found'}), 401
    
    data = request.json
    config = load_user_config(session['key'])
    if not config:
        return jsonify({'error': 'Configuration not found'}), 500
    
    config['chats_origen'] = data['source_chats']
    config['chat_destino'] = data['dest_chat']
    save_user_config(session['key'], config)
    flash("Chats saved successfully!", "success")
    return jsonify({'success': True})

# Store active clients
active_clients = {}

def run_bot_in_thread(key, session_string, config):
    async def bot_loop():
        client = TelegramClient(StringSession(session_string), config['api_id'], config['api_hash'])
        try:
            await client.connect()
            if not await client.is_user_authorized():
                print(f"ERROR: Thunderbot not authorized for key {key}")
                return

            @client.on(events.NewMessage(chats=config['chats_origen']))
            async def forward_message(event):
                try:
                    message_text = event.message.message or ""
                    chat_id = event.chat_id
                    print(f"DEBUG: Thunderbot received message in chat {chat_id}: {message_text}")
                    if PATTERN_44.search(message_text):
                        keys_data = load_keys()
                        key_data = keys_data.get(key, {})
                        delay = DELAY_TIMES.get(key_data.get('type', 'normal'), 1.2)
                        print(f"DEBUG: Thunderbot message matches pattern, forwarding with delay {delay}s")
                        await asyncio.sleep(delay)
                        await client.send_message(config['chat_destino'], message_text)
                        print(f"DEBUG: Thunderbot message forwarded to {config['chat_destino']}")
                    else:
                        print("DEBUG: Thunderbot message ignored (no 44-char pattern match)")
                except Exception as e:
                    print(f"ERROR: Thunderbot forwarding failed: {str(e)}")

            print(f"INFO: Thunderbot loop started for key {key} with source chats {config['chats_origen']}")
            await client.run_until_disconnected()
            print(f"INFO: Thunderbot loop stopped for key {key}")
        except Exception as e:
            print(f"ERROR: Thunderbot loop failed for key {key}: {str(e)}")
        finally:
            if client.is_connected():
                await client.disconnect()
            if key in active_clients:
                del active_clients[key]

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(bot_loop())

@app.route('/start_bot', methods=['POST'])
@key_required
async def start_bot():
    if 'telegram_session' not in session:
        flash("Session not found. Please authenticate.", "warning")
        return jsonify({'error': 'Session not found'}), 401
    
    key = session['key']
    config = load_user_config(key)
    if not config or not all(k in config for k in ['api_id', 'api_hash', 'phone', 'chats_origen', 'chat_destino']):
        flash("Configuration incomplete. Please set up Thunderbot fully.", "error")
        return jsonify({'error': 'Configuration incomplete'}), 400
    
    if key in active_clients:
        flash("Thunderbot is already running.", "info")
        return jsonify({'status': 'already_running'})

    thread = threading.Thread(target=run_bot_in_thread, args=(key, session['telegram_session'], config), daemon=True)
    active_clients[key] = None
    thread.start()

    await asyncio.sleep(1)
    print(f"INFO: Thunderbot successfully started for key {key}")
    flash("Thunderbot started successfully!", "success")
    return jsonify({'status': 'started'})

@app.route('/stop_bot', methods=['POST'])
@key_required
async def stop_bot():
    key = session['key']
    if key in active_clients:
        del active_clients[key]
        print(f"INFO: Thunderbot stopped for key {key}")
        flash("Thunderbot stopped successfully.", "success")
        return jsonify({'status': 'stopped'})
    flash("Thunderbot is not running.", "info")
    return jsonify({'status': 'not_running'})

@app.route('/dashboard')
@key_required
def dashboard():
    config = load_user_config(session['key'])
    if not config:
        flash("Configuration not found. Please set up Thunderbot.", "error")
        return redirect(url_for('setup'))
    
    if 'telegram_session' not in session:
        flash("Session not found. Please authenticate.", "warning")
        return redirect(url_for('setup'))
    
    bot_status = 'running' if session['key'] in active_clients else 'stopped'
    validity_days = get_key_validity_days(session['key'])
    return render_template('dashboard.html', config=config, bot_status=bot_status, validity_days=validity_days)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            flash("Admin logged in successfully!", "success")
            return redirect(url_for('admin_dashboard'))
        flash("Invalid admin credentials.", "error")
        return render_template('admin/admin_login.html', validity_days=None)
    validity_days = get_key_validity_days(session.get('key')) if 'key' in session else None
    return render_template('admin/admin_login.html', validity_days=validity_days)

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    flash("Admin logged out successfully.", "success")
    return redirect(url_for('admin_login'))

@app.route('/admin')
@admin_required
def admin_dashboard():
    keys = load_keys()
    validity_days = get_key_validity_days(session.get('key')) if 'key' in session else None
    return render_template('admin/admin_dashboard.html', keys=keys, delay_times=DELAY_TIMES, validity_days=validity_days)

@app.route('/admin/update_delays', methods=['POST'])
@admin_required
def update_delays():
    global DELAY_TIMES
    try:
        DELAY_TIMES['normal'] = float(request.form['normal_delay'])
        DELAY_TIMES['premium'] = float(request.form['premium_delay'])
        DELAY_TIMES['titanium'] = float(request.form['titanium_delay'])
        print(f"INFO: Thunderbot updated delay times - Normal: {DELAY_TIMES['normal']}, Premium: {DELAY_TIMES['premium']}, Titanium: {DELAY_TIMES['titanium']}")
        flash("Delay times updated successfully!", "success")
    except ValueError:
        flash("Invalid delay values. Please enter numeric values.", "error")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/generate_key', methods=['GET', 'POST'])
@admin_required
def admin_generate_key():
    if request.method == 'POST':
        try:
            days = int(request.form['days'])
            key_type = request.form['type']
            
            keys_data = load_keys()
            new_key = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
            expiration_date = datetime.now() + timedelta(days=days)
            
            keys_data[new_key] = {
                "status": "active",
                "expiration": expiration_date.strftime("%Y-%m-%d"),
                "user": request.form.get('user_name', 'Nuevo Usuario'),
                "hwid": None,
                "type": key_type
            }
            ensure_config_dir()
            save_user_config(new_key, {
                "api_id": "",
                "api_hash": "",
                "phone": "",
                "chats_origen": [],
                "chat_destino": None
            })
            save_keys(keys_data)
            flash(f"Key {new_key} generated successfully!", "success")
        except ValueError:
            flash("Invalid number of days. Please enter a valid integer.", "error")
        return redirect(url_for('admin_dashboard'))
    
    validity_days = get_key_validity_days(session.get('key')) if 'key' in session else None
    return render_template('admin/generate_key.html', validity_days=validity_days)

@app.route('/admin/renew_key/<key>', methods=['POST'])
@admin_required
def admin_renew_key(key):
    days = int(request.form['days'])
    keys_data = load_keys()
    if key in keys_data:
        current_expiration = datetime.strptime(keys_data[key]["expiration"], "%Y-%m-%d")
        new_expiration = current_expiration + timedelta(days=days)
        keys_data[key]["expiration"] = new_expiration.strftime("%Y-%m-%d")
        keys_data[key]["status"] = "active"
        save_keys(keys_data)
        flash(f"Key {key} renewed successfully!", "success")
    else:
        flash(f"Key {key} not found.", "error")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_key/<key>')
@admin_required
def admin_delete_key(key):
    keys_data = load_keys()
    if key in keys_data:
        if key in active_clients:
            del active_clients[key]
        del keys_data[key]
        save_keys(keys_data)
        user_folder = os.path.join(BASE_CONFIG_DIR, key)
        if os.path.exists(user_folder):
            import shutil
            shutil.rmtree(user_folder)
        flash(f"Key {key} deleted successfully!", "success")
    else:
        flash(f"Key {key} not found.", "error")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reset_hwid/<key>')
@admin_required
def admin_reset_hwid(key):
    keys_data = load_keys()
    if key in keys_data:
        keys_data[key]["hwid"] = None
        save_keys(keys_data)
        flash(f"HWID for key {key} reset successfully!", "success")
    else:
        flash(f"Key {key} not found.", "error")
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    app.run(debug=False, host="0.0.0.0", port=80)