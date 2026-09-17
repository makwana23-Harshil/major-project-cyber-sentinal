"""Admin API Routes"""
import math
from flask import Blueprint, request, jsonify, g
from database import db
from auth.middleware import admin_required
from datetime import datetime, timedelta, timezone
from bson.objectid import ObjectId

admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')

def serialize_user(user):
    if not user: return None
    user_dict = dict(user)
    user_dict['id'] = str(user_dict['_id'])
    del user_dict['_id']
    if user_dict.get('created_at'):
        user_dict['created_at'] = user_dict['created_at'].isoformat()
    if user_dict.get('last_login'):
        user_dict['last_login'] = user_dict['last_login'].isoformat()
    # Remove password hash before sending to frontend
    user_dict.pop('password_hash', None)
    return user_dict

def serialize_scan(scan):
    if not scan: return None
    scan_dict = dict(scan)
    scan_dict['id'] = str(scan_dict['_id'])
    del scan_dict['_id']
    if scan_dict.get('user_id'):
        scan_dict['user_id'] = str(scan_dict['user_id'])
    if scan_dict.get('created_at'):
        scan_dict['created_at'] = scan_dict['created_at'].isoformat()
    return scan_dict


@admin_bp.route('/users', methods=['GET'])
@admin_required
def get_users():
    users_cursor = db.users.find().sort("created_at", -1)
    return jsonify({'success': True, 'users': [serialize_user(u) for u in users_cursor]})


@admin_bp.route('/user/<uid>', methods=['GET'])
@admin_required
def get_user(uid):
    try:
        user = db.users.find_one({"_id": ObjectId(uid)})
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
            
        scans = db.scans.find({"user_id": uid}).sort("created_at", -1).limit(20)
        
        return jsonify({
            'success': True,
            'user': serialize_user(user),
            'scans': [serialize_scan(s) for s in scans]
        })
    except:
        return jsonify({'success': False, 'message': 'Invalid user ID'}), 400


@admin_bp.route('/user/<uid>/toggle', methods=['POST'])
@admin_required
def toggle_user(uid):
    try:
        user = db.users.find_one({"_id": ObjectId(uid)})
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
            
        if user.get('role') == 'admin':
            return jsonify({'success': False, 'message': 'Cannot deactivate admin'}), 403
            
        new_status = not user.get('is_active', True)
        db.users.update_one({"_id": ObjectId(uid)}, {"$set": {"is_active": new_status}})
        
        return jsonify({
            'success': True, 
            'message': f'User {"activated" if new_status else "deactivated"}', 
            'is_active': new_status
        })
    except:
        return jsonify({'success': False, 'message': 'Invalid ID'}), 400


@admin_bp.route('/user/<uid>', methods=['DELETE'])
@admin_required
def delete_user(uid):
    try:
        user = db.users.find_one({"_id": ObjectId(uid)})
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
            
        if user.get('role') == 'admin':
            return jsonify({'success': False, 'message': 'Cannot delete admin account'}), 403
            
        db.users.delete_one({"_id": ObjectId(uid)})
        return jsonify({'success': True, 'message': 'User deleted successfully'})
    except:
        return jsonify({'success': False, 'message': 'Invalid ID'}), 400


@admin_bp.route('/scans', methods=['GET'])
@admin_required
def get_scans():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    skip = (page - 1) * per_page
    
    total = db.scans.count_documents({})
    scans_cursor = db.scans.find().sort("created_at", -1).skip(skip).limit(per_page)
    pages = math.ceil(total / per_page)
    
    return jsonify({
        'success': True,
        'scans': [serialize_scan(s) for s in scans_cursor],
        'total': total,
        'pages': pages,
        'current_page': page
    })


@admin_bp.route('/stats', methods=['GET'])
@admin_required
def stats():
    total_users = db.users.count_documents({"role": "user"})
    total_scans = db.scans.count_documents({})

    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    
    scans_today = db.scans.count_documents({"created_at": {"$gte": today_start}})
    threats_today = db.scans.count_documents({
        "created_at": {"$gte": today_start},
        "verdict": {"$in": ['DANGEROUS', 'PHISHING', 'SPAM']}
    })

    # Aggregation Pipelines for Distributions
    verdict_counts = db.scans.aggregate([{"$group": {"_id": "$verdict", "count": {"$sum": 1}}}])
    verdict_dist = {v["_id"]: v["count"] for v in verdict_counts if v["_id"]}

    type_counts = db.scans.aggregate([{"$group": {"_id": "$scan_type", "count": {"$sum": 1}}}])
    type_dist = {t["_id"]: t["count"] for t in type_counts if t["_id"]}

    # Daily & Hourly Activity
    thirty_ago = now - timedelta(days=30)
    seven_ago = now - timedelta(days=7)
    
    recent_scans = db.scans.find({"created_at": {"$gte": thirty_ago}})
    daily = {}
    hourly = {}
    
    for s in recent_scans:
        if s.get('created_at'):
            day = s['created_at'].strftime('%Y-%m-%d')
            daily[day] = daily.get(day, 0) + 1
            if s['created_at'] >= seven_ago:
                h = s['created_at'].strftime('%H')
                hourly[h] = hourly.get(h, 0) + 1

    # Top flagged domains
    top_domains_agg = db.link_inspections.aggregate([
        {"$match": {"verdict": {"$in": ['DANGEROUS', 'SUSPICIOUS']}}},
        {"$group": {"_id": "$url", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10}
    ])
    top_domains = [{'url': d['_id'], 'count': d['count']} for d in top_domains_agg]

    # Most active users
    top_users_agg = db.scans.aggregate([
        {"$match": {"user_id": {"$ne": None}}},
        {"$group": {"_id": "$user_id", "scan_count": {"$sum": 1}}},
        {"$sort": {"scan_count": -1}},
        {"$limit": 5}
    ])
    
    top_users = []
    for tu in top_users_agg:
        try:
            u = db.users.find_one({"_id": ObjectId(tu['_id'])})
            if u:
                top_users.append({'name': u.get('name'), 'email': u.get('email'), 'scans': tu['scan_count']})
        except:
            continue

    return jsonify({
        'success': True,
        'stats': {
            'total_users': total_users,
            'total_scans': total_scans,
            'scans_today': scans_today,
            'threats_blocked_today': threats_today,
            'verdict_distribution': verdict_dist,
            'type_distribution': type_dist,
            'daily_activity': daily,
            'hourly_activity': hourly,
            'top_flagged_domains': top_domains,
            'top_users': top_users
        }
    })


@admin_bp.route('/dashboard', methods=['GET'])
@admin_required
def dashboard():
    total_users = db.users.count_documents({"role": "user"})
    total_scans = db.scans.count_documents({})
    
    recent_scans = db.scans.find().sort("created_at", -1).limit(10)

    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    
    threats_today = db.scans.count_documents({
        "created_at": {"$gte": today_start},
        "verdict": {"$in": ['DANGEROUS', 'PHISHING', 'SPAM']}
    })

    new_users_today = db.users.count_documents({"created_at": {"$gte": today_start}})

    return jsonify({
        'success': True,
        'dashboard': {
            'admin': serialize_user(g.current_user),
            'total_users': total_users,
            'total_scans': total_scans,
            'threats_today': threats_today,
            'new_users_today': new_users_today,
            'recent_scans': [serialize_scan(s) for s in recent_scans]
        }
    })