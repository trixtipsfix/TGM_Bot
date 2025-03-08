from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
import asyncio
from telethon import TelegramClient, events
from telethon.sessions import StringSession
import os
import json
import random
import string
from datetime import datetime, timedelta
import threading
from functools import wraps
import uuid
import re

app = Flask(__name__)
app.secret_key = 'verysecseckey'  # Required for secure sessions; change in production

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

# Updated pattern for 44-character IDs (with optional "pump" or "moon")
PATTERN_44 = re.compile(r"[a-zA-Z0-9]{44}(?:pump|moon)?")

# Simulated key storage (replace with a real database in production)
KEYS_FILE = "keys.json"

def load_keys():
    """Load keys from a JSON file."""
    if os.path.exists(KEYS_FILE):
        with open(KEYS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_keys(keys_data):
    """Save keys to a JSON file."""
    with open(KEYS_FILE, 'w') as f:
        json.dump(keys_data, f, indent=4)

def validate_and_associate_key(key):
    """Validate a key exists and is active."""
    keys_data = load_keys()
    return key in keys_data and keys_data[key].get("status") == "active"

# Helper Functions
def ensure_config_dir():
    """Ensure the config directory exists."""
    os.makedirs(BASE_CONFIG_DIR, exist_ok=True)

def get_user_config_path(key):
    """Get the path to a user's config file."""
    return os.path.join(BASE_CONFIG_DIR, key, "config.json")

def load_user_config(key):
    """Load a user's configuration."""
    config_path = get_user_config_path(key)
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return json.load(f)
        return None
    except json.JSONDecodeError:
        return None

def save_user_config(key, config_data):
    """Save a user's configuration."""
    user_folder = os.path.join(BASE_CONFIG_DIR, key)
    os.makedirs(user_folder, exist_ok=True)
    config_path = get_user_config_path(key)
    with open(config_path, 'w') as f:
        json.dump(config_data, f, indent=4)

def get_key_validity_days(key):
    """Calculate remaining validity days for a key."""
    keys_data = load_keys()
    key_data = keys_data.get(key)
    if key_data and key_data.get("expiration"):
        expiration_date = datetime.strptime(key_data["expiration"], "%Y-%m-%d")
        current_date = datetime.now()
        days_left = (expiration_date - current_date).days
        return max(0, days_left)
    return None

def is_key_deleted(key):
    """Check if a key has been deleted."""
    keys_data = load_keys()
    return key not in keys_data

def get_device_hwid():
    """Get a unique hardware ID based on MAC address."""
    return str(uuid.getnode())

async def check_session_validity(session_string, api_id, api_hash):
    """Check if a Telegram session is valid."""
    client = TelegramClient(StringSession(session_string), api_id, api_hash)
    try:
        await client.connect()
        authorized = await client.is_user_authorized()
        await client.disconnect()
        return authorized
    except Exception as e:
        print(f"ERROR: Session check failed: {str(e)}")
        await client.disconnect()
        return False

async def revoke_session(session_string, api_id, api_hash):
    """Revoke a Telegram session."""
    client = TelegramClient(StringSession(session_string), api_id, api_hash)
    try:
        await client.connect()
        if await client.is_user_authorized():
            await client.log_out()
            print(f"INFO: Previous session revoked")
        await client.disconnect()
    except Exception as e:
        print(f"ERROR: Failed to revoke session: {str(e)}")
        await client.disconnect()

def is_session_valid(session_string, api_id, api_hash):
    """Synchronously check session validity."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    result = loop.run_until_complete(check_session_validity(session_string, api_id, api_hash))
    loop.close()
    return result

async def get_chats(session_string, api_id, api_hash):
    """Fetch available Telegram chats."""
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
        print(f"ERROR: Failed to fetch chats: {str(e)}")
        await client.disconnect()
        return None

def fetch_chats_sync(session_string, api_id, api_hash):
    """Synchronously fetch Telegram chats."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    chats = loop.run_until_complete(get_chats(session_string, api_id, api_hash))
    loop.close()
    return chats

# Decorators
def admin_required(f):
    """Ensure the user is an admin."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            flash("Please log in as admin to access this page.", "error")
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def key_required(f):
    """Ensure the user has a valid key."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'key' not in session:
            flash("Please log in to access this page.", "error")
            return redirect(url_for('login'))
        if is_key_deleted(session['key']):
            revoke_existing_session(session['key'])
            session.pop('key', None)
            flash("Your key has been deleted by an admin.", "error")
            return redirect(url_for('login'))
        validity_days = get_key_validity_days(session['key'])
        if validity_days is None or validity_days <= 0:
            revoke_existing_session(session['key'])
            session.pop('key', None)
            flash("Your key has expired.", "error")
            return redirect(url_for('logout'))
        keys_data = load_keys()
        key_data = keys_data.get(session['key'])
        current_hwid = get_device_hwid()
        if key_data['hwid'] and key_data['hwid'] != current_hwid:
            flash("This key is bound to another device. Contact admin to reset HWID.", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def revoke_existing_session(key):
    """Revoke the existing Telegram session for a given key."""
    config = load_user_config(key)
    if config and 'session_string' in config and all(k in config for k in ['api_id', 'api_hash']):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        client = TelegramClient(StringSession(config['session_string']), config['api_id'], config['api_hash'], loop=loop)
        loop.run_until_complete(client.connect())
        loop.run_until_complete(client.log_out())
        client.disconnect()  # Synchronous disconnect
        loop.close()
        config['session_string'] = None  # Clear the session string
        save_user_config(key, config)
        print(f"INFO: Revoked session for key {key}")

# Routes
@app.route('/')
def index():
    """Home page."""
    validity_days = get_key_validity_days(session.get('key')) if 'key' in session else None
    return render_template('home.html', validity_days=validity_days)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login route."""
    if request.method == 'POST':
        key = request.form['key']
        if validate_and_associate_key(key):
            validity_days = get_key_validity_days(key)
            if validity_days is None or validity_days <= 0:
                flash("This key has expired.", "error")
                return redirect(url_for('logout'))
            if is_key_deleted(key):
                flash("This key has been deleted.", "error")
                return redirect(url_for('logout'))
            
            keys_data = load_keys()
            key_data = keys_data.get(key)
            current_hwid = get_device_hwid()
            
            # Associate HWID if not set
            if key_data.get('hwid') is None:
                key_data['hwid'] = current_hwid
                save_keys(keys_data)
            # Deny if HWID mismatch
            elif key_data['hwid'] != current_hwid:
                flash("This key is bound to another device. Contact admin to reset HWID.", "error")
                return redirect(url_for('login'))
            
            # Check if key is locked (only during login)
            if key_data.get('lock', False):
                print("This key is currently in use. Please log out first.")
                flash("This key is currently in use. Please log out first.", "error")
                return redirect(url_for('login'))
                
            # Set the key in session and lock it
            session['key'] = key
            key_data['lock'] = True
            save_keys(keys_data)
            config = load_user_config(key)
            if not config or not all(k in config for k in ['api_id', 'api_hash', 'phone']):
                flash("Configuration incomplete. Please set up your Thunderbot.", "warning")
                return redirect(url_for('setup'))
            
            # Check if session_string exists and is valid
            if not config.get('session_string') or not is_session_valid(config['session_string'], config['api_id'], config['api_hash']):
                flash("Please authenticate Telegram.", "warning")
                return redirect(url_for('setup'))
            
            flash("Logged in successfully!", "success")
            return redirect(url_for('dashboard'))
        flash("Invalid key.", "error")
        return redirect(url_for('login'))
    
    validity_days = get_key_validity_days(session.get('key')) if 'key' in session else None
    return render_template('login.html', validity_days=validity_days)

@app.route('/logout')
@key_required
def logout():
    """User logout route."""
    if 'key' in session:
        key = session['key']
        keys_data = load_keys()
        if key in keys_data:
            keys_data[key]['lock'] = False  # Unlock the key
            save_keys(keys_data)
        if key in active_clients:
            del active_clients[key]
        session.pop('key', None)
        flash("Logged out successfully.", "success")
    return redirect(url_for('index'))

@app.route('/setup', methods=['GET', 'POST'])
@key_required
def setup():
    """Setup Thunderbot configuration."""
    if request.method == 'POST':
        data = request.json
        config = {
            "api_id": data['api_id'],
            "api_hash": data['api_hash'],
            "phone": data['phone'],
            "chats_origen": [],
            "chat_destino": None,
            "session_string": None  # Initialize session_string
        }
        save_user_config(session['key'], config)
        flash("Setup saved successfully. Please authenticate with Telegram.", "success")
        return jsonify({'success': True})
    validity_days = get_key_validity_days(session['key'])
    return render_template('setup.html', validity_days=validity_days)

@app.route('/telegram_auth', methods=['POST'])
@key_required
def telegram_auth():
    """Authenticate with Telegram."""
    data = request.json
    config = load_user_config(session['key'])
    if not config:
        print("ERROR: Configuration not found for key {}".format(session['key']))
        return jsonify({'error': 'Configuration not found'}), 500

    session_string = session.get('telegram_session_temp', config.get('session_string', ''))
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    client = TelegramClient(StringSession(session_string), config['api_id'], config['api_hash'], loop=loop)
    print("INFO: Thunderbot Client Created with api_id: {}, phone: {}".format(config['api_id'], config['phone']))
    
    try:
        loop.run_until_complete(client.connect())
        print("INFO: Thunderbot Client Connected")
        
        authorized = loop.run_until_complete(client.is_user_authorized())
        if not authorized:
            if 'code' not in data:
                if 'phone_code_hash' in session:
                    print("INFO: Code already requested, reusing phone_code_hash: {}".format(session['phone_code_hash']))
                    client.disconnect()
                    return jsonify({
                        'status': 'code_required',
                        'phone_code_hash': session['phone_code_hash']
                    })
                print("DEBUG: Sending code request for phone: {}".format(config['phone']))
                try:
                    sent_code = loop.run_until_complete(client.send_code_request(config['phone']))
                    session['telegram_session_temp'] = client.session.save()
                    session['phone_code_hash'] = sent_code.phone_code_hash
                    print("INFO: Code requested successfully, phone_code_hash: {}".format(sent_code.phone_code_hash))
                    client.disconnect()
                    return jsonify({
                        'status': 'code_required',
                        'phone_code_hash': sent_code.phone_code_hash
                    })
                except Exception as e:
                    client.disconnect()
                    print("ERROR: Failed to send code request: {}".format(str(e)))
                    return jsonify({'error': f'Failed to send code: {str(e)}'}), 400
            else:
                if 'phone_code_hash' not in data:
                    print("ERROR: phone_code_hash missing in request")
                    client.disconnect()
                    return jsonify({'error': 'phone_code_hash is required'}), 400
                print(f"DEBUG: Signing in with code: {data['code']}, phone_code_hash: {data['phone_code_hash']}")
                try:
                    loop.run_until_complete(client.sign_in(
                        phone=config['phone'],
                        code=data['code'],
                        phone_code_hash=data['phone_code_hash']
                    ))
                    config['session_string'] = client.session.save()
                    session.pop('telegram_session_temp', None)
                    session.pop('phone_code_hash', None)
                    save_user_config(session['key'], config)
                    dialogs = loop.run_until_complete(client.get_dialogs())
                    chats = [{'id': dialog.id, 'name': dialog.name or 'Sin Nombre'} for dialog in dialogs]
                    client.disconnect()
                    print("INFO: Thunderbot Successfully retrieved chats")
                    return jsonify({'status': 'success', 'chats': chats})
                except Exception as e:
                    client.disconnect()
                    print(f"ERROR: Sign-in failed: {str(e)}")
                    return jsonify({'error': f'Sign-in failed: {str(e)}'}), 400
        
        dialogs = loop.run_until_complete(client.get_dialogs())
        chats = [{'id': dialog.id, 'name': dialog.name or 'Sin Nombre'} for dialog in dialogs]
        client.disconnect()
        print("INFO: Thunderbot Successfully retrieved chats for authorized user")
        return jsonify({'chats': chats})
    
    except Exception as e:
        print(f"ERROR: Connection failed: {str(e)}")
        return jsonify({'error': f'Failed to connect to Telegram: {str(e)}'}), 500
    finally:
        client.disconnect()
        loop.close()

@app.route('/edit_chats', methods=['GET', 'POST'])
@key_required
def edit_chats():
    """Edit source and destination chats."""
    config = load_user_config(session['key'])
    if not config:
        flash("Configuration not found. Please set up Thunderbot.", "error")
        return redirect(url_for('setup'))
    
    if not config.get('session_string'):
        flash("Session not found. Please re-authenticate.", "warning")
        return redirect(url_for('setup'))
    
    if request.method == 'POST':
        data = request.json
        config['chats_origen'] = data['source_chats']
        config['chat_destino'] = data['dest_chat']
        save_user_config(session['key'], config)
        flash("Chats updated successfully!", "success")
        return jsonify({'success': True})
    
    chats = fetch_chats_sync(config['session_string'], config['api_id'], config['api_hash'])
    if chats is None:
        flash("Session invalid. Please re-authenticate.", "warning")
        return redirect(url_for('setup'))
    
    validity_days = get_key_validity_days(session['key'])
    return render_template('edit_chats.html', chats=chats, config=config, validity_days=validity_days)

@app.route('/save_chats', methods=['POST'])
@key_required
def save_chats():
    """Save selected chats."""
    config = load_user_config(session['key'])
    if not config or not config.get('session_string'):
        return jsonify({'error': 'Session not found'}), 401
    
    data = request.json
    if not config:
        return jsonify({'error': 'Configuration not found'}), 500
    
    config['chats_origen'] = data['source_chats']
    config['chat_destino'] = data['dest_chat']
    save_user_config(session['key'], config)
    flash("Chats saved successfully!", "success")
    return jsonify({'success': True})

# Store active bot clients
active_clients = {}

def run_bot_in_thread(key, session_string, config):
    """Run the Telegram bot in a separate thread."""
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
                    match = PATTERN_44.search(message_text)
                    if match:
                        id_to_forward = match.group(0)
                        keys_data = load_keys()
                        key_data = keys_data.get(key, {})
                        delay = DELAY_TIMES.get(key_data.get('type', 'normal'), 1.2)
                        print(f"DEBUG: Thunderbot matched ID: {id_to_forward}, forwarding with delay {delay}s")
                        await asyncio.sleep(delay)
                        await client.send_message(config['chat_destino'], id_to_forward)
                        print(f"DEBUG: Thunderbot forwarded ID {id_to_forward} to {config['chat_destino']}")
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
def start_bot():
    """Start the Telegram bot."""
    config = load_user_config(session['key'])
    if not config or not config.get('session_string'):
        flash("Session not found. Please authenticate.", "warning")
        return jsonify({'error': 'Session not found'}), 401
    
    key = session['key']
    if not config or not all(k in config for k in ['api_id', 'api_hash', 'phone', 'chats_origen', 'chat_destino']):
        flash("Configuration incomplete. Please set up Thunderbot fully.", "error")
        return jsonify({'error': 'Configuration incomplete'}), 400
    
    if key in active_clients:
        flash("Thunderbot is already running.", "info")
        return jsonify({'status': 'already_running'})

    thread = threading.Thread(target=run_bot_in_thread, args=(key, config['session_string'], config), daemon=True)
    active_clients[key] = None
    thread.start()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(asyncio.sleep(1))
    loop.close()
    print(f"INFO: Thunderbot successfully started for key {key}")
    flash("Thunderbot started successfully!", "success")
    return jsonify({'status': 'started'})

@app.route('/stop_bot', methods=['POST'])
@key_required
def stop_bot():
    """Stop the Telegram bot."""
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
    """User dashboard."""
    config = load_user_config(session['key'])
    if not config:
        flash("Configuration not found. Please set up Thunderbot.", "error")
        return redirect(url_for('setup'))
    
    if not config.get('session_string'):
        flash("Session not found. Please authenticate.", "warning")
        return redirect(url_for('setup'))
    
    bot_status = 'running' if session['key'] in active_clients else 'stopped'
    validity_days = get_key_validity_days(session['key'])
    return render_template('dashboard.html', config=config, bot_status=bot_status, validity_days=validity_days)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login route."""
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
    """Admin logout route."""
    session.pop('admin_logged_in', None)
    flash("Admin logged out successfully.", "success")
    return redirect(url_for('admin_login'))

@app.route('/admin')
@admin_required
def admin_dashboard():
    """Admin dashboard."""
    keys = load_keys()
    validity_days = get_key_validity_days(session.get('key')) if 'key' in session else None
    return render_template('admin/admin_dashboard.html', keys=keys, delay_times=DELAY_TIMES, validity_days=validity_days)

@app.route('/admin/update_delays', methods=['POST'])
@admin_required
def update_delays():
    """Update delay times for key types."""
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
    """Generate a new key."""
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
                "type": key_type,
                "lock": False  # Initialize lock as False
            }
            ensure_config_dir()
            save_user_config(new_key, {
                "api_id": "",
                "api_hash": "",
                "phone": "",
                "chats_origen": [],
                "chat_destino": None,
                "session_string": None
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
    """Renew an existing key."""
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
    """Delete a key."""
    keys_data = load_keys()
    if key in keys_data:
        if key in active_clients:
            del active_clients[key]
        config = load_user_config(key)
        if config and config.get('session_string'):
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(revoke_session(config['session_string'], config['api_id'], config['api_hash']))
            loop.close()
            print(f"INFO: Revoked session for deleted key {key}")
        del keys_data[key]
        save_keys(keys_data)
        user_folder = os.path.join(BASE_CONFIG_DIR, key)
        if os.path.exists(user_folder):
            import shutil
            shutil.rmtree(user_folder)
        if 'key' in session and session['key'] == key:
            session.pop('key', None)
        flash(f"Key {key} deleted successfully!", "success")
    else:
        flash(f"Key {key} not found.", "error")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reset_hwid/<key>')
@admin_required
def admin_reset_hwid(key):
    """Reset the HWID for a key and unlock it."""
    keys_data = load_keys()
    if key in keys_data:
        keys_data[key]["hwid"] = None
        keys_data[key]["lock"] = False  # Unlock the key when resetting HWID
        save_keys(keys_data)
        flash(f"HWID for key {key} reset successfully!", "success")
    else:
        flash(f"Key {key} not found.", "error")
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=80)