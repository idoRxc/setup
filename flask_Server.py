import json
import ssl
import socket
from flask import Flask, request, jsonify, session, g, has_app_context
from functools import wraps
from typing import Dict, Any, Optional
import logging
import os
from datetime import datetime, timedelta
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import redis
from redis.exceptions import ConnectionError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import threading
from Proxy import MiddleProxy  
from werkzeug.middleware.proxy_fix import ProxyFix
from flask import send_from_directory, abort
from marshmallow import Schema, fields, ValidationError
import ipaddress
from tenacity import retry, stop_after_attempt, wait_fixed
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import yaml

app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s - IP: %(ip)s - User: %(user)s',
    handlers=[
        logging.FileHandler('flask_server.log'),
        logging.StreamHandler()
    ]
)

class ContextFilter(logging.Filter):
    def filter(self, record):
        if has_app_context():
            record.ip = g.get('ip', request.remote_addr if request else 'N/A')
            record.user = g.get('user', 'anonymous')
        else:
            record.ip = 'N/A'
            record.user = 'anonymous'
        return True

logging.getLogger().addFilter(ContextFilter())

# Environment variable validation
SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SECRET_KEY'] = SECRET_KEY
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

REDIS_HOST = os.environ.get('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.environ.get('REDIS_PORT', 6379))
REDIS_DB = int(os.environ.get('REDIS_DB', 0))
REDIS_PASSWORD = os.environ.get('REDIS_PASSWORD', None)
REDIS_SSL = os.environ.get('REDIS_SSL', 'false').lower() == 'true'
REDIS_URL = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}"
if REDIS_PASSWORD:
    REDIS_URL = f"redis://:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}"
if REDIS_SSL:
    REDIS_URL = REDIS_URL.replace('redis://', 'rediss://')

PROXY_HOST = os.environ.get('PROXY_HOST', 'localhost')
PROXY_PORT = int(os.environ.get('PROXY_PORT', 8443))
OSINT_SERVER_HOST = os.environ.get('OSINT_SERVER_HOST', 'localhost')
OSINT_SERVER_PORT = int(os.environ.get('OSINT_SERVER_PORT', 8444))
CA_CERT_PATH = os.environ.get('CA_CERT_PATH', 'certs/ca.crt')
CERT_PATH = os.environ.get('CERT_PATH', 'certs/client.crt')
KEY_PATH = os.environ.get('KEY_PATH', 'certs/client.key')
TIMEOUT = 10  # Reduced from 30 to mitigate slowloris attacks

# Redis with retry and SSL
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def get_redis_client():
    return redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        db=REDIS_DB,
        password=REDIS_PASSWORD,
        ssl=REDIS_SSL,
        ssl_ca_certs=CA_CERT_PATH if REDIS_SSL else None,
        decode_responses=True
    )

redis_client = get_redis_client()

limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri=REDIS_URL,
    default_limits=["100 per day", "10 per minute"]
)

# Input validation schemas
class LoginSchema(Schema):
    username = fields.Str(required=True, validate=lambda x: x.isalnum())
    password = fields.Str(required=True)

class JobSchema(Schema):
    agent_id = fields.Str(required=True)
    tool = fields.Str(required=True)
    parameters = fields.Dict(required=True)

class IpSchema(Schema):
    ip = fields.Str(required=True, validate=lambda x: ipaddress.ip_address(x))

def init_redis():
    try:
        if os.environ.get('INITIALIZE_ADMIN') == 'true' and not redis_client.hexists('users', 'admin'):
            admin_data = {
                'password_hash': generate_password_hash('admin123'),
                'role': 'admin',
                'created_at': datetime.utcnow().isoformat()
            }
            redis_client.hset('users', 'admin', json.dumps(admin_data))
            logging.info("Initialized default admin user")
        if not redis_client.exists('blocked_ips'):
            redis_client.sadd('blocked_ips', '0.0.0.0')
    except ConnectionError as e:
        logging.error(f"Failed to connect to Redis: {str(e)}")
        raise

proxy = MiddleProxy(
    server_host=PROXY_HOST,
    server_port=PROXY_PORT,
    proxy_host=OSINT_SERVER_HOST,
    proxy_port=OSINT_SERVER_PORT
)
proxy_thread = threading.Thread(target=lambda: (proxy.start(), proxy.accept_connections()))
proxy_thread.daemon = True
proxy_thread.start()

class OSINTClientError(Exception):
    pass

class OSINTClient:
    def __init__(self):
        self.context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        self.context.load_verify_locations(cafile=CA_CERT_PATH)
        self.context.load_cert_chain(certfile=CERT_PATH, keyfile=KEY_PATH)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
        with open(CERT_PATH, 'r') as f: self.cert = f.read()
        with open(KEY_PATH, 'r') as f: self.key = f.read()
        with open(CA_CERT_PATH, 'r') as f: self.ca = f.read()

def send_command(self, command: str, args: Dict = None) -> Dict:
    try:
        with socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=TIMEOUT) as sock:
            with self.context.wrap_socket(sock, server_hostname=PROXY_HOST) as ssock:
                cert_data = {'cert': self.cert, 'key': self.key, 'ca': self.ca}
                ssock.send(json.dumps(cert_data).encode('utf-8'))
                salt = ssock.recv(4096)
                if not salt:
                    raise OSINTClientError("Failed to receive encryption salt from proxy")
                
                connection_id = hash(str(ssock.getpeercert()))
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(str(connection_id).encode()))
                cipher = Fernet(key)
                
                cmd = {"command": command}
                if args:
                    cmd["args"] = args
                ssock.send(json.dumps(cmd).encode('utf-8'))
                
                response_data = b""
                while True:
                    chunk = ssock.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk
                
                # Decrypt the response
                decrypted_data = cipher.decrypt(response_data)
                return json.loads(decrypted_data.decode('utf-8'))
    except (socket.error, ssl.SSLError, json.JSONDecodeError) as e:
        logging.error(f"Proxy error: {str(e)}", exc_info=True)
        raise OSINTClientError(f"Communication error: {str(e)}")

client = OSINTClient()

def generate_csrf_token():
    token = secrets.token_hex(16)
    try:
        redis_client.setex(f"csrf:{token}", 3600, "valid")
        return token
    except ConnectionError:
        raise Exception("Failed to generate CSRF token")

def verify_csrf_token(token: str) -> bool:
    try:
        return redis_client.get(f"csrf:{token}") == "valid"
    except ConnectionError:
        return False

def csrf_protect(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ['POST', 'PUT', 'DELETE']:
            csrf_token = request.headers.get('X-CSRF-Token')
            if not csrf_token or not verify_csrf_token(csrf_token):
                return jsonify({"status": "error", "message": "Invalid or missing CSRF token"}), 403
            redis_client.delete(f"csrf:{csrf_token}")
        return f(*args, **kwargs)
    return decorated_function




def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"status": "error", "message": "Token required"}), 401
        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            g.user = payload['user']
            g.ip = request.remote_addr
            if not redis_client.exists(f"session:{g.user}:{token}"):
                return jsonify({"status": "error", "message": "Invalid session"}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({"status": "error", "message": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"status": "error", "message": "Invalid token"}), 401
        except ConnectionError:
            return jsonify({"status": "error", "message": "Database error"}), 500
        return f(*args, **kwargs)
    return decorated_function

def role_required(role: str):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            try:
                user_data = json.loads(redis_client.hget('users', g.user) or '{}')
                if user_data.get('role') != role:
                    return jsonify({"status": "error", "message": "Insufficient permissions"}), 403
                return f(*args, **kwargs)
            except ConnectionError:
                return jsonify({"status": "error", "message": "Database error"}), 500
        return decorated_function
    return decorator

def check_ip_blocked(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr
        try:
            if redis_client.sismember('blocked_ips', ip):
                logging.warning(f"Blocked IP {ip} attempted to access {request.path}")
                return jsonify({"status": "error", "message": "IP address blocked"}), 403
            return f(*args, **kwargs)
        except ConnectionError:
            return jsonify({"status": "error", "message": "Database error"}), 500
    return decorated_function

@app.route('/csrf-token', methods=['GET'])
@login_required
def get_csrf_token():
    try:
        token = generate_csrf_token()
        return jsonify({"status": "success", "csrf_token": token}), 200
    except Exception as e:
        logging.error(f"CSRF token generation failed: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": "Internal server error"}), 500

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
@check_ip_blocked
def login():
    try:
        data = LoginSchema().load(request.get_json())
        username = data['username']
        password = data['password']
        ip = request.remote_addr

        user_data_str = redis_client.hget('users', username)
        if not user_data_str:
            logging.warning(f"Failed login attempt for non-existent user: {username} from IP {ip}")
            return jsonify({"status": "error", "message": "Invalid credentials"}), 401

        user_data = json.loads(user_data_str)
        if check_password_hash(user_data['password_hash'], password):
            token = jwt.encode({
                'user': username,
                'exp': datetime.utcnow() + timedelta(minutes=30)
            }, SECRET_KEY, algorithm="HS256")
            session_key = f"session:{username}:{token}"
            redis_client.setex(session_key, 1800, 'active')
            csrf_token = generate_csrf_token()
            activity = {
                'username': username,
                'action': 'login',
                'ip': ip,
                'timestamp': datetime.utcnow().isoformat()
            }
            redis_client.lpush('user_activity', json.dumps(activity))
            redis_client.ltrim('user_activity', 0, 999)
            logging.info(f"User {username} logged in from IP {ip}")
            return jsonify({
                "status": "success",
                "token": token,
                "csrf_token": csrf_token,
                "user": {"username": username, "role": user_data['role']}
            }), 200
        logging.warning(f"Failed login attempt for {username} from IP {ip}")
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401
    except ValidationError as e:
        return jsonify({"status": "error", "message": str(e.messages)}), 400
    except ConnectionError:
        return jsonify({"status": "error", "message": "Database error"}), 500

@app.route('/logout', methods=['POST'])
@login_required
@csrf_protect
def logout():
    try:
        token = request.headers.get('Authorization').split(" ")[1]
        session_key = f"session:{g.user}:{token}"
        redis_client.delete(session_key)
        activity = {
            'username': g.user,
            'action': 'logout',
            'ip': g.ip,
            'timestamp': datetime.utcnow().isoformat()
        }
        redis_client.lpush('user_activity', json.dumps(activity))
        redis_client.ltrim('user_activity', 0, 999)
        logging.info(f"User {g.user} logged out")
        return jsonify({"status": "success", "message": "Logged out successfully"}), 200
    except ConnectionError:
        return jsonify({"status": "error", "message": "Database error"}), 500

@app.route('/health', methods=['GET'])
def health_check():
    try:
        response = client.send_command("server_status")
        return jsonify({
            "status": "healthy",
            "flask_server": "running",
            "osint_server": response.get("data", {}),
            "redis": "connected" if redis_client.ping() else "disconnected",
            "proxy": "running" if proxy_thread.is_alive() and proxy.server_socket else "stopped"
        }), 200
    except OSINTClientError as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 503
    except ConnectionError:
        return jsonify({"status": "unhealthy", "error": "Redis connection failed"}), 503

@app.route('/api/agents', methods=['GET'])
@login_required
def list_agents():
    try:
        response = client.send_command("list_agents")
        if response["status"] == "success":
            return jsonify({"status": "success", "agents": response["data"]}), 200
        return jsonify(response), 400
    except OSINTClientError as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/agents/<agent_id>', methods=['GET'])
@login_required
def get_agent(agent_id: str):
    try:
        response = client.send_command("agent_info", {"agent_id": agent_id})
        if response["status"] == "success":
            return jsonify({"status": "success", "agent": response["data"]}), 200
        return jsonify(response), 404 if response["message"] == "Agent not found" else 400
    except OSINTClientError as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/')
def serve_frontend():
    return send_from_directory('static', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    if '..' in path or path.startswith('/'):
        abort(403)
    return send_from_directory('static', path)

@app.route('/user_data/<username>', methods=['GET'])
@login_required
@role_required('admin')
def get_user_data(username: str) -> Optional[Dict[str, Any]]:
    try:
        user_data_str = redis_client.hget('users', username)
        if user_data_str:
            return jsonify({"status": "success", "data": json.loads(user_data_str)}), 200
        return jsonify({"status": "error", "message": "User not found"}), 404
    except ConnectionError:
        return jsonify({"status": "error", "message": "Database error"}), 500

@app.route('/api/block_ip', methods=['POST'])
@login_required
@role_required('admin')
@csrf_protect
def block_ip():
    try:
        data = IpSchema().load(request.get_json())
        ip_to_block = data['ip']
        redis_client.sadd('blocked_ips', ip_to_block)
        activity = {
            'username': g.user,
            'action': 'block_ip',
            'ip': ip_to_block,
            'timestamp': datetime.utcnow().isoformat()
        }
        redis_client.lpush('user_activity', json.dumps(activity))
        redis_client.ltrim('user_activity', 0, 999)
        logging.info(f"IP {ip_to_block} blocked by admin {g.user}")
        return jsonify({"status": "success", "message": f"IP {ip_to_block} blocked"}), 200
    except ValidationError as e:
        return jsonify({"status": "error", "message": str(e.messages)}), 400
    except ConnectionError:
        return jsonify({"status": "error", "message": "Database error"}), 500

@app.route('/api/unblock_ip', methods=['POST'])
@login_required
@role_required('admin')
@csrf_protect
def unblock_ip():
    try:
        data = IpSchema().load(request.get_json())
        ip_to_unblock = data['ip']
        if redis_client.srem('blocked_ips', ip_to_unblock):
            activity = {
                'username': g.user,
                'action': 'unblock_ip',
                'ip': ip_to_unblock,
                'timestamp': datetime.utcnow().isoformat()
            }
            redis_client.lpush('user_activity', json.dumps(activity))
            redis_client.ltrim('user_activity', 0, 999)
            logging.info(f"IP {ip_to_unblock} unblocked by admin {g.user}")
            return jsonify({"status": "success", "message": f"IP {ip_to_unblock} unblocked"}), 200
        return jsonify({"status": "error", "message": "IP not blocked"}), 404
    except ValidationError as e:
        return jsonify({"status": "error", "message": str(e.messages)}), 400
    except ConnectionError:
        return jsonify({"status": "error", "message": "Database error"}), 500

@app.route('/api/share-csrf', methods=['POST'])
@login_required
@role_required('admin')  
@csrf_protect
def share_csrf():
    try:
        data = request.get_json()
        service_key = data.get('service_key')
        if service_key != os.environ.get('SERVICE_KEY', 'your_shared_secret'): 
            return jsonify({"status": "error", "message": "Invalid service key"}), 403
        token = generate_csrf_token()
        return jsonify({"status": "success", "csrf_token": token}), 200
    except Exception as e:
        logging.error(f"CSRF sharing failed: {str(e)}")
        return jsonify({"status": "error", "message": "Internal server error"}), 500

@app.route('/api/user_activity', methods=['GET'])
@login_required
@role_required('admin')
def get_user_activity():
    try:
        activities = redis_client.lrange('user_activity', 0, -1)
        activity_list = [json.loads(act) for act in activities]
        return jsonify({"status": "success", "activities": activity_list}), 200
    except ConnectionError:
        return jsonify({"status": "error", "message": "Database error"}), 500

@app.route('/api/jobs', methods=['POST'])
@login_required
@csrf_protect
@limiter.limit("10 per minute")
def create_job():
    try:
        data = JobSchema().load(request.get_json())
        response = client.send_command("run_tool", {
            "agent_id": data["agent_id"],
            "tool": data["tool"],
            "parameters": data["parameters"]
        })
        if response["status"] == "success":
            job_id = response["data"]["job_id"]
            redis_client.hset('jobs', job_id, json.dumps({
                "created_by": g.user,
                "created_at": datetime.utcnow().isoformat()
            }))
            activity = {
                'username': g.user,
                'action': 'create_job',
                'job_id': job_id,
                'ip': g.ip,
                'timestamp': datetime.utcnow().isoformat()
            }
            redis_client.lpush('user_activity', json.dumps(activity))
            redis_client.ltrim('user_activity', 0, 999)
            logging.info(f"Job {job_id} created by {g.user}")
            return jsonify({"status": "success", "job_id": job_id}), 201
        return jsonify(response), 400
    except ValidationError as e:
        return jsonify({"status": "error", "message": str(e.messages)}), 400
    except (OSINTClientError, ConnectionError) as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/jobs/<job_id>', methods=['GET'])
@login_required
def get_job_status(job_id: str):
    try:
        response = client.send_command("job_status", {"job_id": job_id})
        if response["status"] == "success":
            job_meta = json.loads(redis_client.hget('jobs', job_id) or '{}')
            response["data"]["metadata"] = job_meta
            if "results" not in response["data"] or not response["data"]["results"]:
                response["data"]["results"] = {"locations": [{"lat": 40.7128, "lon": -74.0060}]}  
            return jsonify({"status": "success", "job": response["data"]}), 200
        return jsonify(response), 404 if response["message"] == "Job not found" else 400
    except (OSINTClientError, ConnectionError) as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/jobs/<job_id>', methods=['DELETE'])
@login_required
@role_required('admin')
@csrf_protect
@limiter.limit("5 per minute")
def cancel_job(job_id: str):
    try:
        response = client.send_command("cancel_job", {"job_id": job_id})
        if response["status"] == "success":
            redis_client.hset('jobs', job_id, json.dumps({
                **json.loads(redis_client.hget('jobs', job_id) or '{}'),
                "cancelled_by": g.user,
                "cancelled_at": datetime.utcnow().isoformat()
            }))
            activity = {
                'username': g.user,
                'action': 'cancel_job',
                'job_id': job_id,
                'ip': g.ip,
                'timestamp': datetime.utcnow().isoformat()
            }
            redis_client.lpush('user_activity', json.dumps(activity))
            redis_client.ltrim('user_activity', 0, 999)
            logging.info(f"Job {job_id} cancelled by {g.user}")
            return jsonify({"status": "success", "message": "Job cancelled"}), 200
        return jsonify(response), 400
    except (OSINTClientError, ConnectionError) as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/jobs', methods=['GET'])
@login_required
def list_jobs():
    try:
        filters = request.args.get('filters')
        args = {"filters": json.loads(filters)} if filters else {}
        response = client.send_command("list_jobs", args)
        if response["status"] == "success":
            for job in response["data"]:
                job_id = job["id"]
                job["metadata"] = json.loads(redis_client.hget('jobs', job_id) or '{}')
            return jsonify({"status": "success", "jobs": response["data"]}), 200
        return jsonify(response), 400
    except (OSINTClientError, ConnectionError, json.JSONDecodeError) as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self';"
    return response

def load_env_vars_from_yaml(yaml_file: str):
    with open(yaml_file, 'r') as file:
        env_vars = yaml.safe_load(file)
        for key, value in env_vars.items():
            os.environ[key] = str(value)

# Load environment variables from a YAML file
load_env_vars_from_yaml('config.yaml')

if __name__ == '__main__':
    required_vars = ['SECRET_KEY', 'CA_CERT_PATH', 'CERT_PATH', 'KEY_PATH']
    for var in required_vars:
        if not os.environ.get(var):
            logging.error(f"Missing required env var: {var}")
            exit(1)
    
    init_redis()
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
    
    import atexit
    atexit.register(lambda: proxy.stop() if hasattr(proxy, 'stop') else None)
    
    port = int(os.environ.get("PORT", 8444))
    app.run(
        host='0.0.0.0',
        port=port,
        debug=False,
        ssl_context='adhoc' if os.environ.get('FLASK_ENV') == 'development' else None
    )