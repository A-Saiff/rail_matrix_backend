import base64
import hashlib
import hmac
from flask import Flask, request, jsonify
from pymongo import MongoClient
import bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import datetime
from bson import ObjectId, Binary
from flask_cors import CORS
import os
from dotenv import load_dotenv

app = Flask(__name__)
CORS(app)

load_dotenv()

app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
jwt = JWTManager(app)
HMAC_SECRET_KEY = os.getenv("HMAC_SECRET_KEY").encode()

MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client["RailMatrix_db"]
users_collection = db["users"]
parts_collection = db["parts"]
defects_collection = db["defects"]


@app.route("/")
def home():
    return "Hello from flask", 200


@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    user = users_collection.find_one({"username": username})
    if not user:
        return jsonify({"error": "Invalid username or password"}), 401

    if not bcrypt.checkpw(password.encode(), user["password"].encode()):
        return jsonify({"error": "Invalid username or password"}), 401

    # Create JWT token (expires in 1 hour by default)
    access_token = create_access_token(identity=username)

    return jsonify({"access_token": access_token}), 200


@app.route("/verify-token", methods=["GET"])
@jwt_required()
def verify_token():
    user = get_jwt_identity()
    return jsonify({"valid": True, "username": user}), 200


@app.route("/details", methods=["POST"])
@jwt_required()
def details():
    data = request.json
    uid = data['uid']
    hmac_recieved = data['hmac']

    digest = hmac.new(
        HMAC_SECRET_KEY,
        uid.encode(),
        hashlib.sha256
    ).digest()

    computed_hmac = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    if hmac.compare_digest(computed_hmac, hmac_recieved):
        details = parts_collection.find_one({"uid_payload": uid})

        if details:
            defects = []
            for Oid in details["defects"]:
                defect = defects_collection.find_one({"_id": ObjectId(Oid)})
                defects.append(defect.get("title"))
            answer = {
                "uid": details['uid_payload'],
                "item_type": details["item_type"],
                "vendor_id": details["vendor_id"],
                "vendor_name": details["vendor_name"],
                "po_number": details["po_number"],
                "lot_no": details["lot_no"],
                "manufacture_date": details["manufacture_date"],
                "supply_date": details["supply_date"],
                "material": details["material"],
                "dimensions": details["dimensions"],
                "weight_g": details["weight_g"],
                "surface_finish": details["surface_finish"],
                "qc_pass": details["qc_pass"],
                "qc_cert_no": details["qc_cert_no"],
                "batch_quality_grade": details["batch_quality_grade"],
                "warranty_months": details["warranty_months"],
                "expected_life_years": details["expected_life_years"],
                "inspection_notes": details["inspection_notes"],
                "defects": defects
            }
            return jsonify(answer), 200
        else:
            return jsonify({"error": "QR Data not available"}), 403
    else:
        return jsonify({"error": "Invalid QR"}), 403


@app.route('/defect', methods=['POST'])
@jwt_required()
def raise_defect():
    try:
        current_user = get_jwt_identity()

        uid = request.form.get('uid')
        title = request.form.get('title')
        description = request.form.get('description')

        if not uid or not title or not description:
            return jsonify({"msg": "Missing fields"}), 400

        images = []
        if 'images' in request.files:
            files = request.files.getlist('images')
            for f in files:
                images.append(Binary(f.read()))

        defect = {
            "uid_payload": uid,
            "title": title,
            "description": description,
            "images": images,
            "raised_by": current_user,
            "created_at": datetime.datetime.now()
        }

        defect_result = defects_collection.insert_one(defect)
        defect_id = defect_result.inserted_id

        result = parts_collection.update_one(
            {"uid_payload": uid},
            {"$push": {"defects": defect_id}}
        )

        if result.modified_count == 0:
            return jsonify({"msg": "Part not found or defect ID not added"}), 404

        return jsonify({"msg": "Issue raised", "defect_id": str(defect_id)}), 201

    except Exception as e:
        return jsonify({"msg": "Error", "error": str(e)}), 500


# if __name__ == "__main__":
#     debug = os.getenv("FLASK_DEBUG", "False") == "True"
#     app.run(host="0.0.0.0", port=5000, debug=debug)
