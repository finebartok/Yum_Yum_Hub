from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from flask_jwt_extended import get_jwt_identity
from sqlalchemy.exc import IntegrityError
from datetime import timedelta
from dbase import User, Restaurant, db  

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'yumyum123'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

db.init_app(app)
jwt = JWTManager(app)

# Register route for users
@app.route('/register/user', methods=['POST','GET'])
def register_user():
    if(request.method == 'POST'):
        data = request.get_json()

        name = data.get('name')
        email = data.get('email')
        password = data.get('password')
        phone_number = data.get('phone_number')
        address = data.get('address')

        # Validate the input
        if not name or not email or not password:
            return jsonify({"message": "Name, email, and password are required"}), 400

        # Check if user already exists
        user_exists = User.query.filter_by(email=email).first()
        if user_exists:
            return jsonify({"message": "User already exists"}), 400

        # Hash the password
        hashed_password = generate_password_hash(password)

        new_user = User(
            name=name,
            email=email,
            password=hashed_password,
            phone_number=phone_number,
            address=address
        )

        # Add the user to the database
        try:
            db.session.add(new_user)
            db.session.commit()
            return jsonify({"message": "User registered successfully"}), 201
        except IntegrityError:
            db.session.rollback()
            return jsonify({"message": "An error occurred while registering the user"}), 500
    else:
        return render_template('register_user.html')
# Login route for users
@app.route('/login/user', methods=['POST','GET'])
def login_user():
    if(request.method == 'POST'):
        data = request.get_json()

        email = data.get('email')
        password = data.get('password')

        # Validate the input
        if not email or not password:
            return jsonify({"message": "Email and password are required"}), 400

        # Find the user
        user = User.query.filter_by(email=email).first()
        print(f"User found: {user}")
        if not user or not check_password_hash(user.password, password):
            return jsonify({"message": "Invalid credentials"}), 401

        # Create a JWT token
        access_token = create_access_token(identity=user.user_id)
        return jsonify({"access_token": access_token}), 200
    else:
        return render_template('userlogin.html')   


# Register route for restaurants
@app.route('/register/restaurant', methods=['POST'])
def register_restaurant():
    data = request.get_json()

    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    phone_number = data.get('phone_number')
    address = data.get('address')
    description = data.get('description')

    # Validate the input
    if not name or not email or not password:
        return jsonify({"message": "Name, email, and password are required"}), 400

    # Check if restaurant already exists
    restaurant_exists = Restaurant.query.filter_by(email=email).first()
    if restaurant_exists:
        return jsonify({"message": "Restaurant already exists"}), 400

    # Hash the password
    hashed_password = generate_password_hash(password)

    new_restaurant = Restaurant(
        name=name,
        email=email,
        password=hashed_password,
        phone_number=phone_number,
        address=address,
        description=description
    )

    # Add the restaurant to the database
    try:
        db.session.add(new_restaurant)
        db.session.commit()
        return jsonify({"message": "Restaurant registered successfully"}), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({"message": "An error occurred while registering the restaurant"}), 500


# Login route for restaurants
@app.route('/login/restaurant', methods=['POST'])
def login_restaurant():
    data = request.get_json()

    email = data.get('email')
    password = data.get('password')

    # Validate the input
    if not email or not password:
        return jsonify({"message": "Email and password are required"}), 400

    # Find the restaurant
    restaurant = Restaurant.query.filter_by(email=email).first()
    print(f"Restaurant found: {restaurant}")
    if not restaurant or not check_password_hash(restaurant.password, password):
        return jsonify({"message": "Invalid credentials"}), 401

    access_token = create_access_token(identity=restaurant.restaurant_id)
    return jsonify({"access_token": access_token}), 200


@app.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if user:
        return jsonify({
            "user_id": user.user_id,
            "name": user.name,
            "email": user.email,
            "phone_number": user.phone_number,
            "address": user.address
        })
    return jsonify({"message": "User not found"}), 404


if __name__ == '__main__':
    with app.app_context():
        
        db.create_all()  
    app.run(debug=True)