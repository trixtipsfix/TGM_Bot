from flask import Flask, render_template, request, jsonify, session, redirect, url_for
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

app = Flask(__name__)
app.secret_key = 'verysecseckey'  # Change this to a secure key in production

# Configuration
BASE_CONFIG_DIR = "./configs"

# Helper functions for config management
def ensure_config_dir():
    """Ensure the base config directory exists."""
    os.makedirs(BASE_CONFIG_DIR, exist_ok=True)

def get_user_config_path(key):
    """Get the config path for a specific user."""
    return os.path.join(BASE_CONFIG_DIR, key, "config.json")

def load_user_config(key):
    """Load user configuration from file."""
    config_path = get_user_config_path(key)
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return json.load(f)
        return None
    except json.JSONDecodeError:
        return None

def save_user_config(key, config_data):
    """Save user configuration to file."""
    user_folder = os.path.join(BASE_CONFIG_DIR, key)
    os.makedirs(user_folder, exist_ok=True)
    config_path = get_user_config_path(key)
    with open(config_path, 'w') as f:
        json.dump(config_data, f, indent=4)

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        key = request.form['key']
        if validate_and_associate_key(key):
            session['key'] = key
            ensure_config_dir()
            config = load_user_config(key)
            if not config or not all(k in config for k in ['api_id', 'api_hash', 'phone']):
                return redirect(url_for('setup'))
            return redirect(url_for('dashboard'))
        return jsonify({'error': 'Invalid or expired key'}), 401
    return render_template('login.html')

@app.route('/setup', methods=['GET', 'POST'])
def setup():
    if 'key' not in session:
        return redirect(url_for('login'))
    
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
        return jsonify({'success': True})
    return render_template('setup.html')

@app.route('/telegram_auth', methods=['POST'])
async def telegram_auth():
    if 'key' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    config = load_user_config(session['key'])
    if not config:
        return jsonify({'error': 'Configuration not found'}), 500
    
    client = TelegramClient(
        os.path.join(BASE_CONFIG_DIR, session['key'], "session_name"),
        config['api_id'],
        config['api_hash']
    )
    print("INFO: Client Created")
    
    try:
        await client.connect()
        print("INFO: Client Connected")
        
        if not await client.is_user_authorized():
            if 'code' not in data:
                try:
                    sent_code = await client.send_code_request(config['phone'])
                    print(f"INFO: Code Required, phone_code_hash: {sent_code.phone_code_hash}")
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
                    return jsonify({'error': 'phone_code_hash is required'}), 400
                try:
                    await client.sign_in(
                        phone=config['phone'],
                        code=data['code'],
                        phone_code_hash=data['phone_code_hash']
                    )
                    print("INFO: Got the Code. Signing in....")
                    dialogs = await client.get_dialogs()
                    if not isinstance(dialogs, (list, tuple)):
                        raise ValueError(f"Expected list of dialogs, got {type(dialogs)}: {dialogs}")
                    chats = [{'id': dialog.id, 'name': dialog.name or 'Sin Nombre'} for dialog in dialogs]
                    await client.disconnect()
                    print("INFO: Successfully retrieved chats")
                    return jsonify({'status': 'success', 'chats': chats})
                except Exception as e:
                    await client.disconnect()
                    print(f"ERROR: Sign-in failed: {str(e)}")
                    return jsonify({'error': f'Sign-in failed: {str(e)}'}), 400
        
        dialogs = await client.get_dialogs()
        if not isinstance(dialogs, (list, tuple)):
            raise ValueError(f"Expected list of dialogs, got {type(dialogs)}: {dialogs}")
        chats = [{'id': dialog.id, 'name': dialog.name or 'Sin Nombre'} for dialog in dialogs]
        await client.disconnect()
        print("INFO: Successfully retrieved chats for authorized user")
        return jsonify({'chats': chats})
    
    except Exception as e:
        if client.is_connected():
            await client.disconnect()
        print(f"ERROR: Telegram connection failed: {str(e)}")
        return jsonify({'error': f'Failed to connect to Telegram: {str(e)}'}), 500
    
@app.route('/save_chats', methods=['POST'])
def save_chats():
    if 'key' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    config = load_user_config(session['key'])
    if not config:
        return jsonify({'error': 'Configuration not found'}), 500
    
    config['chats_origen'] = data['source_chats']
    config['chat_destino'] = data['dest_chat']
    save_user_config(session['key'], config)
    return jsonify({'success': True})
# Store active clients
active_clients = {}
def run_bot_in_thread(key, client, config):
    async def bot_loop():
        try:
            await client.connect()
            if not await client.is_user_authorized():
                print(f"ERROR: Client not authorized for key {key}")
                return

            @client.on(events.NewMessage(chats=config['chats_origen']))
            async def forward_message(event):
                try:
                    message_text = event.message.message or ""
                    chat_id = event.chat_id
                    print(f"DEBUG: New message received in chat {chat_id}: {message_text}")
                    if PATTERN_44.search(message_text):
                        keys_data = load_keys()
                        key_data = keys_data.get(key, {})
                        delay = {'normal': 1.2, 'premium': 0.7, 'titanium': 0}.get(key_data.get('type', 'normal'), 1.2)
                        print(f"DEBUG: Message matches pattern, forwarding with delay {delay}s")
                        await asyncio.sleep(delay)
                        await client.send_message(config['chat_destino'], message_text)
                        print(f"DEBUG: Message forwarded to {config['chat_destino']}")
                    else:
                        print("DEBUG: Message ignored (no 44-char pattern match)")
                except Exception as e:
                    print(f"ERROR: Forwarding message failed: {str(e)}")

            print(f"INFO: Bot loop started for key {key} with source chats {config['chats_origen']}")
            await client.run_until_disconnected()
            print(f"INFO: Bot loop stopped for key {key}")
        except Exception as e:
            print(f"ERROR: Bot loop failed for key {key}: {str(e)}")
        finally:
            if client.is_connected():
                await client.disconnect()
            if key in active_clients:
                del active_clients[key]

    # Run the async loop in a new event loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(bot_loop())

@app.route('/start_bot', methods=['POST'])
async def start_bot():
    if 'key' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    key = session['key']
    config = load_user_config(key)
    if not config or not all(k in config for k in ['api_id', 'api_hash', 'phone', 'chats_origen', 'chat_destino']):
        return jsonify({'error': 'Configuration incomplete'}), 400
    
    if key in active_clients:
        return jsonify({'status': 'already_running'})

    client = TelegramClient(
        os.path.join(BASE_CONFIG_DIR, key, "session_name"),
        config['api_id'],
        config['api_hash']
    )

    # Start the bot in a background thread
    thread = threading.Thread(target=run_bot_in_thread, args=(key, client, config), daemon=True)
    active_clients[key] = client
    thread.start()

    # Wait briefly to ensure it starts
    await asyncio.sleep(1)
    print(f"INFO: Bot successfully started for key {key}")
    return jsonify({'status': 'started'})

@app.route('/stop_bot', methods=['POST'])
async def stop_bot():
    if 'key' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    key = session['key']
    if key in active_clients:
        client = active_clients[key]
        try:
            if client.is_connected():
                await client.disconnect()
            del active_clients[key]
            print(f"INFO: Bot stopped for key {key}")
            return jsonify({'status': 'stopped'})
        except Exception as e:
            print(f"ERROR: Failed to stop bot: {str(e)}")
            return jsonify({'error': f'Failed to stop bot: {str(e)}'}), 500
    return jsonify({'status': 'not_running'})

@app.route('/dashboard')
def dashboard():
    if 'key' not in session:
        return redirect(url_for('login'))
    
    config = load_user_config(session['key'])
    if not config:
        return redirect(url_for('setup'))
    
    bot_status = 'running' if session['key'] in active_clients else 'stopped'
    return render_template('dashboard.html', config=config, bot_status=bot_status)

@app.route('/admin')
def admin_dashboard():
    keys = load_keys()
    return render_template('admin/admin_dashboard.html', keys=keys)

@app.route('/admin/generate_key', methods=['GET', 'POST'])
def admin_generate_key():
    if request.method == 'POST':
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
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin/generate_key.html')

@app.route('/admin/renew_key/<key>', methods=['POST'])
def admin_renew_key(key):
    days = int(request.form['days'])
    keys_data = load_keys()
    if key in keys_data:
        current_expiration = datetime.strptime(keys_data[key]["expiration"], "%Y-%m-%d")
        new_expiration = current_expiration + timedelta(days=days)
        keys_data[key]["expiration"] = new_expiration.strftime("%Y-%m-%d")
        keys_data[key]["status"] = "active"
        save_keys(keys_data)
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_key/<key>')
def admin_delete_key(key):
    keys_data = load_keys()
    if key in keys_data:
        if key in active_clients:
            active_clients[key].disconnect()
            del active_clients[key]
        del keys_data[key]
        save_keys(keys_data)
        user_folder = os.path.join(BASE_CONFIG_DIR, key)
        if os.path.exists(user_folder):
            import shutil
            shutil.rmtree(user_folder)
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reset_hwid/<key>')
def admin_reset_hwid(key):
    keys_data = load_keys()
    if key in keys_data:
        keys_data[key]["hwid"] = None
        save_keys(keys_data)
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    app.run(debug=True)