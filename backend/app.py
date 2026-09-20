import os
import sys
from datetime import datetime, timezone

# Ensure backend directory is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
from config import Config
from database import db
from auth.middleware import hash_password
from auth.routes import auth_bp
from api.detection_routes import detect_bp
from api.user_routes import user_bp
from api.admin_routes import admin_bp

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # CORS — allow frontend
    CORS(app, resources={r"/api/*": {"origins": Config.CORS_ORIGINS}},
         supports_credentials=True)

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(detect_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(admin_bp)

    # Health check
    @app.route('/api/health')
    def health():
        return jsonify({'status': 'ok', 'service': 'CyberSentinel Pro API'})

    # Serve frontend static files (optional)
    frontend_dir = os.path.join(os.path.dirname(__file__), '..', 'frontend')

    @app.route('/')
    def index():
        return send_from_directory(frontend_dir, 'index.html')

    @app.route('/<path:path>')
    def serve_static(path):
        try:
            return send_from_directory(frontend_dir, path)
        except Exception:
            return send_from_directory(frontend_dir, 'index.html')

    # Error handlers
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({'success': False, 'message': 'Endpoint not found'}), 404

    @app.errorhandler(500)
    def internal_error(e):
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

    with app.app_context():
        _seed_admin(app)

    return app

def _seed_admin(app):
    """Create default admin account if not exists using MongoDB"""
    existing = db.users.find_one({"email": app.config['ADMIN_EMAIL']})
    
    if not existing:
        admin_user = {
            "name": app.config['ADMIN_NAME'],
            "email": app.config['ADMIN_EMAIL'],
            "password_hash": hash_password(app.config['ADMIN_PASSWORD']),
            "role": 'admin',
            "is_active": True,
            "created_at": datetime.now(timezone.utc),
            "last_login": None,
            "total_scans": 0
        }
        db.users.insert_one(admin_user)
        print(f"[CyberSentinel] Admin seeded: {app.config['ADMIN_EMAIL']}")

if __name__ == '__main__':
    # Train models if not present
    models_dir = os.path.join(os.path.dirname(__file__), 'models')
    models_needed = ['sms_model.pkl', 'email_body_model.pkl', 'url_model.pkl']
    missing = [m for m in models_needed if not os.path.exists(os.path.join(models_dir, m))]
    
    if missing:
        print(f"[CyberSentinel] Training ML models: {missing}")
        import subprocess
        subprocess.check_call([sys.executable, os.path.join(models_dir, 'train_models.py')])
        print("[CyberSentinel] Models ready!")

    application = create_app()
    print("\n" + "="*55)
    print("  CyberSentinel Pro — Backend Running")
    print("  http://127.0.0.1:5000")
    print("  Admin: admin@cybersentinel.com / Admin@2024")
    print("="*55 + "\n")
    
    # Run the application with the reloader disabled to prevent socket crashes
    application.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)