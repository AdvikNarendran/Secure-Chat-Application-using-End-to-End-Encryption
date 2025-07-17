from flask import Blueprint, jsonify, g
from keys import jwt_required  # reuse the same decorator

roster_bp = Blueprint("roster", __name__)

@roster_bp.route("/users", methods=["GET"])
@jwt_required
def list_users():
    """
    Return an array of all usernames except the current caller.
    Response: { "users": ["Adu", "Anu", ...] }
    """
    users = g.db.users.distinct("username")
    return jsonify({"users": [u for u in users if u != g.current_user]}), 200