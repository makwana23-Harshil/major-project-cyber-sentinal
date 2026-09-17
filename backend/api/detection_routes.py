"""Detection API Routes"""
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, g
from database import db
from auth.middleware import token_required
from detection import sms_detector, email_detector, url_detector

detect_bp = Blueprint('detect', __name__, url_prefix='/api/scan')


def _save_scan(scan_type, input_text, result, user_id=None):
    """Persist scan result + link inspections to DB"""
    
    # MongoDB handles nested dictionaries natively, no need for json.dumps
    details = {k: v for k, v in result.items() 
               if k not in ('link_inspections', 'deep_inspection')}
    
    # 1. Create the Scan Document
    scan_doc = {
        "user_id": user_id,
        "scan_type": scan_type,
        "input_text": input_text[:2000],
        "verdict": result.get('verdict', 'UNKNOWN'),
        "confidence": result.get('confidence', 0),
        "risk_score": result.get('risk_score', 0),
        "details": details,
        "created_at": datetime.now(timezone.utc)
    }
    
    # Insert Scan into MongoDB
    scan_result = db.scans.insert_one(scan_doc)
    scan_id = scan_result.inserted_id

    # ---> NEW: Increment the user's total_scans counter <---
    if user_id:
        db.users.update_one({"_id": user_id}, {"$inc": {"total_scans": 1}})

    # 2. Prepare Link Inspections
    links = result.get('link_inspections') or []
    if result.get('deep_inspection'):
        links = [result['deep_inspection']]

    link_docs = []
    for li in links:
        link_docs.append({
            "scan_id": scan_id,  # Link it to the parent scan
            "url": li.get('url', ''),
            "is_reachable": li.get('is_reachable', False),
            "final_url": li.get('final_url'),
            "redirect_count": li.get('redirect_count', 0),
            "ssl_valid": li.get('ssl_valid', False),
            "page_title": li.get('page_title'),
            "virustotal_score": li.get('virustotal_score'),
            "safe_browsing_flag": li.get('safe_browsing_flag', False),
            "verdict": li.get('verdict', 'UNKNOWN'),
            "risk_evidence": li.get('risk_evidence', []), # MongoDB handles lists natively
            "risk_score": li.get('risk_score', 0),
            "created_at": datetime.now(timezone.utc)
        })
        
    # Insert all links at once (if there are any)
    if link_docs:
        db.link_inspections.insert_many(link_docs)

    return str(scan_id)


@detect_bp.route('/sms', methods=['POST'])
@token_required
def scan_sms():
    data = request.get_json()
    text = (data.get('text') or '').strip()
    if not text:
        return jsonify({'success': False, 'message': 'SMS text is required'}), 400
    inspect = data.get('inspect_links', True)
    try:
        result = sms_detector.analyze_sms(text, inspect_links=inspect)
        scan_id = _save_scan('sms', text, result, user_id=g.current_user['_id'])
        return jsonify({'success': True, 'scan_id': scan_id, 'result': result})
    except FileNotFoundError as e:
        return jsonify({'success': False, 'message': str(e)}), 503
    except Exception as e:
        return jsonify({'success': False, 'message': f'Analysis error: {str(e)}'}), 500


@detect_bp.route('/email-address', methods=['POST'])
@token_required
def scan_email_address():
    data = request.get_json()
    email = (data.get('email') or '').strip()
    if not email:
        return jsonify({'success': False, 'message': 'Email address is required'}), 400
    try:
        result = email_detector.analyze_email_address(email)
        scan_id = _save_scan('email_address', email, result, user_id=g.current_user['_id'])
        return jsonify({'success': True, 'scan_id': scan_id, 'result': result})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Analysis error: {str(e)}'}), 500


@detect_bp.route('/email-body', methods=['POST'])
@token_required
def scan_email_body():
    data = request.get_json()
    body = (data.get('body') or '').strip()
    if not body:
        return jsonify({'success': False, 'message': 'Email body is required'}), 400
    inspect = data.get('inspect_links', True)
    try:
        result = email_detector.analyze_email_body(body, inspect_links=inspect)
        scan_id = _save_scan('email_body', body, result, user_id=g.current_user['_id'])
        return jsonify({'success': True, 'scan_id': scan_id, 'result': result})
    except FileNotFoundError as e:
        return jsonify({'success': False, 'message': str(e)}), 503
    except Exception as e:
        return jsonify({'success': False, 'message': f'Analysis error: {str(e)}'}), 500


@detect_bp.route('/url', methods=['POST'])
@token_required
def scan_url():
    data = request.get_json()
    url = (data.get('url') or '').strip()
    if not url:
        return jsonify({'success': False, 'message': 'URL is required'}), 400
    inspect = data.get('deep_inspect', True)
    try:
        result = url_detector.analyze_url(url, do_inspect=inspect)
        scan_id = _save_scan('url', url, result, user_id=g.current_user['_id'])
        return jsonify({'success': True, 'scan_id': scan_id, 'result': result})
    except FileNotFoundError as e:
        return jsonify({'success': False, 'message': str(e)}), 503
    except Exception as e:
        return jsonify({'success': False, 'message': f'Analysis error: {str(e)}'}), 500


@detect_bp.route('/unified', methods=['POST'])
@token_required
def scan_unified():
    """Scan all types at once if fields provided"""
    data = request.get_json()
    results = {}

    if data.get('sms_text'):
        try:
            results['sms'] = sms_detector.analyze_sms(data['sms_text'])
            _save_scan('sms', data['sms_text'], results['sms'], g.current_user['_id'])
        except Exception as e:
            results['sms'] = {'error': str(e)}

    if data.get('email_address'):
        try:
            results['email_address'] = email_detector.analyze_email_address(data['email_address'])
            _save_scan('email_address', data['email_address'], results['email_address'], g.current_user['_id'])
        except Exception as e:
            results['email_address'] = {'error': str(e)}

    if data.get('email_body'):
        try:
            results['email_body'] = email_detector.analyze_email_body(data['email_body'])
            _save_scan('email_body', data['email_body'], results['email_body'], g.current_user['_id'])
        except Exception as e:
            results['email_body'] = {'error': str(e)}

    if data.get('url'):
        try:
            results['url'] = url_detector.analyze_url(data['url'])
            _save_scan('url', data['url'], results['url'], g.current_user['_id'])
        except Exception as e:
            results['url'] = {'error': str(e)}

    return jsonify({'success': True, 'results': results})