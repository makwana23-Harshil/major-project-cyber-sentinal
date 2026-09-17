from flask import Blueprint, request, jsonify, g
from database import db, serialize_doc
from auth.middleware import hash_password, check_password, generate_token
from datetime import datetime, timezone
from bson import ObjectId

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    name = (data.get('name') or '').strip()
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    role = data.get('role', 'user')

    if not name or not email or not password:
        return jsonify({'success': False, 'message': 'Name, email and password are required'}), 400
    if len(password) < 6:
        return jsonify({'success': False, 'message': 'Password must be at least 6 characters'}), 400
    
    # Check if user already exists
    if db.users.find_one({"email": email}):
        return jsonify({'success': False, 'message': 'Email already registered'}), 409

    now = datetime.now(timezone.utc)

    # Build the document
    new_user = {
        "name": name,
        "email": email,
        "password_hash": hash_password(password),
        "role": 'user',
        "is_active": True,
        "created_at": now,
        "last_login": now,  # <-- FIXED: Now sets login time on registration
        "total_scans": 0
    }
    
    # Insert into DB
    result = db.users.insert_one(new_user)
    new_user['_id'] = result.inserted_id
    
    token = generate_token(str(result.inserted_id), 'user')
    
    return jsonify({
        'success': True,
        'message': 'Registration successful',
        'token': token,
        'token_name': 'Utoken',
        'user': serialize_doc(new_user)
    }), 201


@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    login_as = data.get('role', 'user')

    if not email or not password:
        return jsonify({'success': False, 'message': 'Email and password are required'}), 400

    # Fetch user document
    user = db.users.find_one({"email": email})
    
    if not user or not check_password(password, user['password_hash']):
        return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
    
    if not user.get('is_active', True):
        return jsonify({'success': False, 'message': 'Account is deactivated'}), 403
        
    if login_as == 'admin' and user.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Access denied: Not an admin account'}), 403

    # Update last login
    now = datetime.now(timezone.utc)
    db.users.update_one(
        {"_id": user['_id']},
        {"$set": {"last_login": now}}
    )
    user['last_login'] = now

    token = generate_token(str(user['_id']), user['role'])
    token_name = 'Atoken' if user.get('role') == 'admin' else 'Utoken'

    return jsonify({
        'success': True,
        'message': 'Login successful',
        'token': token,
        'token_name': token_name,
        'user': serialize_doc(user)
    })


@auth_bp.route('/logout', methods=['POST'])
def logout():
    return jsonify({'success': True, 'message': 'Logged out successfully'})


@auth_bp.route('/me', methods=['GET'])
def me():
    from auth.middleware import token_required, decode_token
    auth_header = request.headers.get('Authorization', '')
    
    if not auth_header.startswith('Bearer '):
        return jsonify({'success': False, 'message': 'No token provided'}), 401
        
    try:
        data = decode_token(auth_header.split(' ')[1])
        # Find user by ObjectId
        user = db.users.find_one({"_id": ObjectId(data['user_id'])})
        
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
            
        return jsonify({'success': True, 'user': serialize_doc(user)})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 401