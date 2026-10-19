import os
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import html

# JWT signing key comes from an environment variable. A hard-coded fallback keeps
# local development working, but production must always set JWT_SECRET_KEY.
app = Flask(__name__)
# RFC 7518 recommends >= 32 bytes for HMAC-SHA256. Fallback is long enough to
# avoid the weak-key warning; production must override via env var regardless.
app.config["JWT_SECRET_KEY"] = os.getenv(
    "JWT_SECRET_KEY",
    "dev-secret-not-for-production-please-override-xxxxxxxxxxxxxxxx",
)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL", 'sqlite:///app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

jwt = JWTManager(app)
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.LargeBinary, nullable=False)

with app.app_context():
    db.create_all()
    exist = User.query.filter_by(username="admin").first()
    if not exist:
        hash_pw = bcrypt.hashpw(b"pass1234", bcrypt.gensalt())
        new_user = User(username="admin", password_hash=hash_pw)
        db.session.add(new_user)
        db.session.commit()

@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)
    if not data:
        return jsonify(msg="Request body must be valid JSON"), 400
    username = data.get("username")
    password_raw = data.get("password")
    if not username or not isinstance(username, str) or not isinstance(password_raw, str):
        return jsonify(msg="username and password are required"), 400
    user = User.query.filter_by(username=username).first()
    # Use parameterized query (SQLAlchemy ORM) - immune to SQL injection.
    if user and bcrypt.checkpw(password_raw.encode("utf-8"), user.password_hash):
        token = create_access_token(identity=user.username)
        return jsonify(access_token=token), 200
    return jsonify(msg="Bad login or password"), 401

@app.route("/api/data", methods=["GET"])
@jwt_required()
def get_data():
    current_user = get_jwt_identity()
    resp_data = {
        "message": html.escape(f"Hello user {current_user}"),
        "users": [html.escape(u.username) for u in User.query.all()]
    }
    return jsonify(resp_data)

@app.route("/api/profile", methods=["GET"])
@jwt_required()
def profile():
    name = html.escape(get_jwt_identity())
    return jsonify(username=name, note="protected profile info")

if __name__ == "__main__":
    # Debug mode exposes the interactive debugger and the Werkzeug console which
    # can lead to remote code execution (see CVE-2018-1000656 in the report).
    # Kept behind an explicit FLASK_DEBUG=1 so it defaults to OFF in production.
    app.run(debug=os.getenv("FLASK_DEBUG") == "1")
