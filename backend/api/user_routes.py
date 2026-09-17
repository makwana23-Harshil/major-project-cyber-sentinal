"""User API Routes"""
from flask import Blueprint, jsonify, g
from database import db
from auth.middleware import token_required
from datetime import datetime, timedelta, timezone

user_bp = Blueprint('user', __name__, url_prefix='/api/user')

def serialize_scan(scan):
    """Helper to convert MongoDB _id to string for JSON"""
    if scan and '_id' in scan:
        scan['id'] = str(scan['_id'])
        del scan['_id']
    if scan and 'user_id' in scan and scan['user_id']:
        scan['user_id'] = str(scan['user_id'])
    return scan

def serialize_user(user):
    """Helper to safely format the user document for the frontend"""
    return {
        'id': str(user['_id']),
        'name': user.get('name'),
        'email': user.get('email'),
        'role': user.get('role'),
        'is_active': user.get('is_active'),
        'created_at': user.get('created_at').isoformat() if user.get('created_at') else None,
        'last_login': user.get('last_login').isoformat() if user.get('last_login') else None
    }

@user_bp.route('/history', methods=['GET'])
@token_required
def history():
    uid = g.current_user['_id']
    # Mongo: find by user_id, sort by created_at DESC (-1), limit 50
    scans_cursor = db.scans.find({"user_id": uid}).sort("created_at", -1).limit(50)
    scans = [serialize_scan(s) for s in scans_cursor]
    return jsonify({'success': True, 'scans': scans})


@user_bp.route('/stats', methods=['GET'])
@token_required
def stats():
    uid = g.current_user['_id']
    
    # Use count_documents instead of .count()
    total = db.scans.count_documents({"user_id": uid})
    sms_count = db.scans.count_documents({"user_id": uid, "scan_type": "sms"})
    email_addr_count = db.scans.count_documents({"user_id": uid, "scan_type": "email_address"})
    email_body_count = db.scans.count_documents({"user_id": uid, "scan_type": "email_body"})
    url_count = db.scans.count_documents({"user_id": uid, "scan_type": "url"})

    dangerous = db.scans.count_documents({"user_id": uid, "verdict": "DANGEROUS"})
    phishing = db.scans.count_documents({"user_id": uid, "verdict": "PHISHING"})
    spam = db.scans.count_documents({"user_id": uid, "verdict": "SPAM"})
    
    # $in operator replaces .in_()
    safe = db.scans.count_documents({
        "user_id": uid,
        "verdict": {"$in": ['SAFE', 'LEGITIMATE', 'HAM']}
    })

    # Last 30 days activity
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    
    # $gte operator replaces >=
    recent = db.scans.find({
        "user_id": uid,
        "created_at": {"$gte": thirty_days_ago}
    })

    # Group by day
    daily = {}
    for s in recent:
        if 'created_at' in s and s['created_at']:
            day = s['created_at'].strftime('%Y-%m-%d')
            daily[day] = daily.get(day, 0) + 1

    return jsonify({
        'success': True,
        'stats': {
            'total_scans': total,
            'by_type': {
                'sms': sms_count,
                'email_address': email_addr_count,
                'email_body': email_body_count,
                'url': url_count
            },
            'by_verdict': {
                'dangerous': dangerous,
                'phishing': phishing,
                'spam': spam,
                'safe': safe
            },
            'daily_activity': daily,
            'threats_blocked': dangerous + phishing + spam
        }
    })


@user_bp.route('/dashboard', methods=['GET'])
@token_required
def dashboard():
    uid = g.current_user['_id']
    
    recent_cursor = db.scans.find({"user_id": uid}).sort("created_at", -1).limit(5)
    recent_scans = [serialize_scan(s) for s in recent_cursor]
    
    total = db.scans.count_documents({"user_id": uid})
    threats = db.scans.count_documents({
        "user_id": uid,
        "verdict": {"$in": ['DANGEROUS', 'PHISHING', 'SPAM', 'SUSPICIOUS']}
    })

    safety_score = 100 if total == 0 else max(0, int(100 - (threats / total * 100)))

    return jsonify({
        'success': True,
        'dashboard': {
            'user': serialize_user(g.current_user),
            'total_scans': total,
            'threats_found': threats,
            'safety_score': safety_score,
            'recent_scans': recent_scans
        }
    })