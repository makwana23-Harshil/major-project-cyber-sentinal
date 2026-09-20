import jwt
import bcrypt
from flask import request, jsonify, current_app, g
from database import db
from datetime import datetime, timezone
from bson import ObjectId
from functools import wraps

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def check_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))


def generate_token(user_id: str, role: str) -> str:
    from datetime import timedelta
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': datetime.now(timezone.utc) + timedelta(hours=current_app.config['JWT_EXPIRY_HOURS']),
        'iat': datetime.now(timezone.utc)
    }
    return jwt.encode(payload, current_app.config['SECRET_KEY'],
                      algorithm=current_app.config['JWT_ALGORITHM'])


def decode_token(token: str) -> dict:
    return jwt.decode(token, current_app.config['SECRET_KEY'],
                      algorithms=[current_app.config['JWT_ALGORITHM']])


def token_required(f):
    """Decorator: requires valid Utoken or Atoken"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        if not token:
            return jsonify({'success': False, 'message': 'Token is missing'}), 401
        try:
            data = decode_token(token)
            
            # Fetch user from MongoDB using ObjectId
            g.current_user = db.users.find_one({'_id': ObjectId(data['user_id'])})
            
            # Dictionary access instead of object attributes
            if not g.current_user or not g.current_user.get('is_active', True):
                return jsonify({'success': False, 'message': 'User not found or inactive'}), 401
            g.current_role = data.get('role', 'user')
            
        except jwt.ExpiredSignatureError:
            return jsonify({'success': False, 'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'success': False, 'message': 'Invalid token'}), 401
        except Exception as e:
            return jsonify({'success': False, 'message': 'Invalid token format'}), 401
            
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Decorator: requires admin role"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        if not token:
            return jsonify({'success': False, 'message': 'Token is missing'}), 401
        try:
            data = decode_token(token)
            if data.get('role') != 'admin':
                return jsonify({'success': False, 'message': 'Admin access required'}), 403
            
            # Fetch user from MongoDB using ObjectId
            g.current_user = db.users.find_one({'_id': ObjectId(data['user_id'])})
            
            # Dictionary access instead of object attributes
            if not g.current_user or not g.current_user.get('is_active', True):
                return jsonify({'success': False, 'message': 'Admin not found or inactive'}), 401
            g.current_role = 'admin'
            
        except jwt.ExpiredSignatureError:
            return jsonify({'success': False, 'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'success': False, 'message': 'Invalid token'}), 401
        except Exception as e:
            return jsonify({'success': False, 'message': 'Invalid token format'}), 401
            
        return f(*args, **kwargs)
    return decorated

def user_required(f):
    """Requires a valid JWT belonging to a normal user."""

    @wraps(f)
    def decorated(*args, **kwargs):

        # 1. Get Authorization header
        auth_header = request.headers.get('Authorization', '')

        if not auth_header.startswith('Bearer '):
            return jsonify({
                'success': False,
                'message': 'Authentication required'
            }), 401

        # 2. Extract JWT
        token = auth_header.split(' ', 1)[1].strip()

        if not token:
            return jsonify({
                'success': False,
                'message': 'Invalid token'
            }), 401

        # 3. Decode JWT
        try:
            token_data = decode_token(token)

        except jwt.ExpiredSignatureError:
            return jsonify({
                'success': False,
                'message': 'Token has expired'
            }), 401

        except jwt.InvalidTokenError:
            return jsonify({
                'success': False,
                'message': 'Invalid token'
            }), 401

        except Exception:
            return jsonify({
                'success': False,
                'message': 'Invalid token format'
            }), 401

        # 4. Token must belong to a normal user
        if token_data.get('role') != 'user':
            return jsonify({
                'success': False,
                'message': 'User authentication required'
            }), 403

        # 5. Get user ID FROM JWT
        user_id = token_data.get('user_id')

        if not user_id:
            return jsonify({
                'success': False,
                'message': 'Invalid token payload'
            }), 401

        # 6. Find user in MongoDB
        try:
            user = db.users.find_one({
                '_id': ObjectId(user_id)
            })

        except Exception:
            return jsonify({
                'success': False,
                'message': 'Invalid user ID'
            }), 401

        # 7. User must exist
        if not user:
            return jsonify({
                'success': False,
                'message': 'User account not found'
            }), 401

        # 8. User must be active
        if not user.get('is_active', True):
            return jsonify({
                'success': False,
                'message': 'Your account has been deactivated'
            }), 403

        # 9. Store authenticated information
        g.user_id = user_id
        g.current_user = user
        g.current_role = 'user'

        # 10. Continue to protected route
        return f(*args, **kwargs)

    return decorated