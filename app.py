from flask import Flask, request, jsonify, render_template, flash, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from flask_jwt_extended import get_jwt_identity
from sqlalchemy.exc import IntegrityError
from datetime import timedelta
from dbase import User, Restaurant, MenuItem, Order, OrderItem, db  
import os
import re
from flask_limiter import Limiter
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'yumyum123'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.secret_key = 'yummy'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

db.init_app(app)
jwt = JWTManager(app)
limiter = Limiter(app)

# Create validation functions
def validate_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None

def validate_phone(phone):
    pattern = r'^\+?1?\d{9,15}$'
    return re.match(pattern, phone) is not None

def validate_password(password):
    if len(password) < 8:
        return False
    if not re.search("[0-9]", password):
        return False
    if not re.search("[A-Z]", password):
        return False
    return True

def register_entity(EntityClass, data):
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    
    if not all([name, email, password]):
        return jsonify({"message": "Name, email, and password are required"}), 400
    
    if not validate_email(email):
        return jsonify({"message": "Invalid email format"}), 400
        
    if data.get('phone_number') and not validate_phone(data.get('phone_number')):
        return jsonify({"message": "Invalid phone number format"}), 400

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
        return render_template('registerUser.html')
# Login route for users
@app.route('/login/user', methods=['POST','GET'])
@limiter.limit("5 per minute")
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

        # Create a JWT token and set session variables
        access_token = create_access_token(identity=user.user_id)
        session['user_id'] = user.user_id
        session['user_email'] = user.email
        session['user_name'] = user.name
        session['is_authenticated'] = True
        session.permanent = True  # Make session persistent
        
        return jsonify({
            "message": "Login successful",
            "access_token": access_token
        }), 200
    else:
        return render_template('userlogin.html')   


# Register route for restaurants
@app.route('/register/restaurant', methods=['POST','GET'])
def register_restaurant():
    if request.method == 'GET':
        return render_template('registerRestaurant.html')
    data = request.get_json()

    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    phone_number = data.get('phone_number')
    address = data.get('address')
    description = data.get('description')

    # Validate the input
    if not all([name, email, password, description]):
        return jsonify({"message": "Name, email, password, and description are required"}), 400

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
@app.route('/login/restaurant', methods=['POST', 'GET'])
def login_restaurant():
    if request.method == 'GET':
        return render_template('restaurantLogin.html')

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
    session['restaurant_id'] = restaurant.restaurant_id
    session['restaurant_email'] = restaurant.email
    session['restaurant_name'] = restaurant.name
    session['is_authenticated'] = True
    session['is_restaurant'] = True
    session.permanent = True

    return jsonify({
        "message": "Login successful",
        "access_token": access_token
    }), 200


@app.route('/profile', methods=['GET', 'POST','PUT'])
def profile():
    # First check if user is authenticated via session
    if not session.get('is_authenticated'):
        return redirect(url_for('login_user'))
    
    # Handle different types of users (restaurant vs regular user)
    if session.get('is_restaurant'):
        current_id = session.get('restaurant_id')
        user = Restaurant.query.get(current_id)
        menu_items = MenuItem.query.filter_by(restaurant_id=current_id).all()
        template = 'restaurantProfile.html'
        
        if request.method == 'POST':
            # Handle password update
            if 'update_password' in request.form:
                current_password = request.form.get('current_password')
                new_password = request.form.get('new_password')
                
                # Verify current password
                if not check_password_hash(user.password, current_password):
                    flash('Current password is incorrect', 'danger')  # Changed to 'danger' for Bootstrap
                    return render_template(template, user=user, menu_items=menu_items)
                
                # Validate new password
                if not validate_password(new_password):
                    flash('New password must be at least 8 characters long and contain a number and uppercase letter', 'danger')
                    return render_template(template, user=user, menu_items=menu_items)
                
                user.password = generate_password_hash(new_password)
                db.session.commit()
                flash('Password updated successfully', 'success')
            
            # Handle profile updates
            elif 'update_profile' in request.form:
                try:
                    # Update restaurant-specific fields
                    if request.form.get('email'):
                        user.email = request.form.get('email')
                    if request.form.get('phone_number'):
                        user.phone_number = request.form.get('phone_number')
                    if request.form.get('address'):
                        user.address = request.form.get('address')
                    if request.form.get('description'):
                        user.description = request.form.get('description')
                    
                    db.session.commit()
                    flash('Profile updated successfully', 'success')
                except IntegrityError:
                    db.session.rollback()
                    flash('An error occurred while updating profile', 'danger')
                except Exception as e:
                    db.session.rollback()
                    flash(f'An error occurred: {str(e)}', 'danger')
        
        return render_template(template, user=user, menu_items=menu_items)
    else:
        current_id = session.get('user_id')
        user = User.query.get(current_id)
        template = 'userProfile.html'
    
    if not user:
        return jsonify({"message": "User not found"}), 404

    if request.method == 'POST':
        # Handle profile updates
        if 'update_password' in request.form:
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            
            # Verify current password
            if not check_password_hash(user.password, current_password):
                flash('Current password is incorrect', 'error')
                return render_template(template, user=user)
            
            # Validate new password
            if not validate_password(new_password):
                flash('New password must be at least 8 characters long and contain a number and uppercase letter', 'error')
                return render_template(template, user=user)
            
            user.password = generate_password_hash(new_password)
            db.session.commit()
            flash('Password updated successfully', 'success')

        # Handle other profile updates
        elif 'update_profile' in request.form:
            new_phone = request.form.get('phone_number')
            new_email = request.form.get('email')
            
            # Validate phone number if provided
            if new_phone and not validate_phone(new_phone):
                flash('Invalid phone number format', 'error')
                return render_template(template, user=user)
            
            # Validate and check if email already exists
            if new_email and new_email != user.email:
                if not validate_email(new_email):
                    flash('Invalid email format', 'error')
                    return render_template(template, user=user)
                
                # Check if email already exists for the appropriate user type
                if session.get('is_restaurant'):
                    existing_user = Restaurant.query.filter_by(email=new_email).first()
                else:
                    existing_user = User.query.filter_by(email=new_email).first()
                
                if existing_user and existing_user.id != user.id:  # Add check for same user
                    flash('Email already in use', 'error')
                    return render_template(template, user=user)
                
                user.email = new_email
            
            # Update common fields
            if new_phone:  # Only update if new phone number provided
                user.phone_number = new_phone
            if request.form.get('address'):  # Only update if new address provided
                user.address = request.form.get('address')
            
            # Handle restaurant-specific fields
            if session.get('is_restaurant'):
                if request.form.get('description'):  # Only update if new description provided
                    user.description = request.form.get('description')
            
            try:
                db.session.commit()
                flash('Profile updated successfully', 'success')
            except IntegrityError:
                db.session.rollback()
                flash('An error occurred while updating profile', 'error')

    return render_template(template, user=user)


# Route to view available restaurants
@app.route('/view/restaurants', methods=['GET'])
def view_restaurants():
    return render_template('viewRestaurants.html')


# Add global error handler
@app.errorhandler(Exception)
def handle_error(error):
    return jsonify({
        "message": "An unexpected error occurred",
        "error": str(error)
    }), 500


# Add logout route
@app.route('/logout')
def logout():
    # Store the user type before clearing session
    was_restaurant = session.get('is_restaurant', False)
    session.clear()
    
    # Redirect based on previous user type
    if was_restaurant:
        return redirect(url_for('login_restaurant'))
    return redirect(url_for('login_user'))


# Add these routes after your existing routes

@app.route('/add-menu-item', methods=['POST'])
def add_menu_item():
    if not session.get('is_restaurant'):
        return jsonify({"message": "Unauthorized"}), 401
    
    try:
        name = request.form.get('name')
        description = request.form.get('description')
        price = request.form.get('price')
        is_available = bool(request.form.get('is_available'))
        
        if not all([name, price]):
            flash('Name and price are required', 'error')
            return redirect(url_for('profile'))
        
        new_item = MenuItem(
            restaurant_id=session['restaurant_id'],
            name=name,
            description=description,
            price=price,
            is_available=is_available
        )
        
        db.session.add(new_item)
        db.session.commit()
        flash('Menu item added successfully', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash('Failed to add menu item', 'error')
        print(f"Error adding menu item: {str(e)}")
    
    return redirect(url_for('profile'))

@app.route('/menu-item/<int:item_id>/availability', methods=['PUT'])
def update_menu_item_availability(item_id):
    if not session.get('is_restaurant'):
        return jsonify({"message": "Unauthorized"}), 401
    
    try:
        data = request.get_json()
        if 'is_available' not in data:
            return jsonify({"message": "is_available field is required"}), 400
            
        menu_item = MenuItem.query.get_or_404(item_id)
        
        # Verify the restaurant owns this menu item
        if menu_item.restaurant_id != session['restaurant_id']:
            return jsonify({"message": "Unauthorized"}), 401
        
        # Convert to boolean and update
        menu_item.is_available = bool(data['is_available'])
        db.session.commit()
        
        return jsonify({
            "message": "Updated successfully",
            "is_available": menu_item.is_available
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error updating menu item availability: {str(e)}")  # Add logging
        return jsonify({"message": "An error occurred while updating availability"}), 500

@app.route('/menu-item/<int:item_id>', methods=['DELETE'])
def delete_menu_item(item_id):
    if not session.get('is_restaurant'):
        return jsonify({"message": "Unauthorized"}), 401
    
    try:
        menu_item = MenuItem.query.get_or_404(item_id)
        
        # Verify the restaurant owns this menu item
        if menu_item.restaurant_id != session['restaurant_id']:
            return jsonify({"message": "Unauthorized"}), 401
        
        db.session.delete(menu_item)
        db.session.commit()
        return jsonify({"message": "Deleted successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": str(e)}), 500

@app.route('/api/restaurants', methods=['GET'])
def get_restaurants():
    try:
        restaurants = Restaurant.query.all()
        return jsonify([{
            'id': r.restaurant_id,
            'name': r.name,
            'description': r.description,
            'address': r.address,
            'phone_number': r.phone_number
        } for r in restaurants])
    except Exception as e:
        return jsonify({"message": "Error fetching restaurants", "error": str(e)}), 500

@app.route('/restaurant/<int:restaurant_id>/menu', methods=['GET'])
def view_restaurant_menu(restaurant_id):
    try:
        restaurant = Restaurant.query.get_or_404(restaurant_id)
        menu_items = MenuItem.query.filter_by(restaurant_id=restaurant_id, is_available=True).all()
        return render_template('viewMenu.html', restaurant=restaurant, menu_items=menu_items)
    except Exception as e:
        flash('Error loading menu', 'error')
        return redirect(url_for('view_restaurants'))

@app.route('/orderManagment/<int:restaurant_id>', methods=['GET'])
def order_management(restaurant_id):
    if not session.get('is_authenticated'):
        return redirect(url_for('login_user'))
    try:
        restaurant = Restaurant.query.get_or_404(restaurant_id)
        # Get all orders for this restaurant
        orders = Order.query.filter_by(restaurant_id=restaurant_id).order_by(Order.created_at.desc()).all()
        return render_template('order_management.html', restaurant_id=restaurant_id)
    except Exception as e:
        print(f"Error in view_cart: {str(e)}")  # Add logging for debugging
        flash('Error loading orders', 'error')
        return redirect(url_for('view_restaurants'))

@app.route('/api/place-order', methods=['POST'])
def place_order():
    if not session.get('is_authenticated'):
        return jsonify({"message": "Please login first"}), 401
    
    data = request.get_json()
    restaurant_id = data.get('restaurant_id')
    items = data.get('items')  # Format: [{"id": menu_item_id, "quantity": quantity}, ...]
    
    if not items:
        return jsonify({"message": "Cart is empty"}), 400
        
    try:
        # Verify restaurant exists
        restaurant = Restaurant.query.get(restaurant_id)
        if not restaurant:
            return jsonify({"message": "Restaurant not found"}), 404
            
        # Get all requested menu items in a single query
        menu_items = MenuItem.query.filter(
            MenuItem.menu_item_id.in_([item['id'] for item in items]),
            MenuItem.restaurant_id == restaurant_id,
            MenuItem.is_available == True
        ).all()
        
        # Create a lookup dictionary for menu items
        menu_items_dict = {item.menu_item_id: item for item in menu_items}
        
        # Validate all items exist and are available
        missing_items = [item['id'] for item in items if item['id'] not in menu_items_dict]
        if missing_items:
            return jsonify({
                "message": "Some menu items are unavailable or invalid",
                "invalid_items": missing_items
            }), 400
            
        # Create new order
        new_order = Order(
            user_id=session['user_id'],
            restaurant_id=restaurant_id,
            status='pending',
            total_amount=0  # Initialize total amount here
        )
        db.session.add(new_order)
        db.session.flush()  # Get the order_id without committing
        
        # Create order items and calculate total amount
        total_amount = 0  # Initialize total amount
        for item in items:
            menu_item = menu_items_dict.get(item['id'])
            order_item = OrderItem(
                order_id=new_order.order_id,
                menu_item_id=menu_item.menu_item_id,
                quantity=item['quantity'],
                price=menu_item.price
            )
            db.session.add(order_item)
            total_amount += menu_item.price * item['quantity']  # Calculate total amount
        
        # Set the total amount
        new_order.total_amount = total_amount  # Ensure this line is present
        
        db.session.commit()
        
        return jsonify({
            "message": "Order placed successfully",
            "order_id": new_order.order_id,
            "total_amount": float(new_order.total_amount)  # Convert Decimal to float for JSON
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error placing order: {str(e)}")  # For debugging
        return jsonify({"message": "Error placing order"}), 500

@app.route('/restaurant/orders', methods=['GET'])
def restaurant_orders():
    if not session.get('is_restaurant'):
        return redirect(url_for('login_restaurant'))
    
    orders = Order.query.filter_by(restaurant_id=session['restaurant_id']).order_by(Order.created_at.desc()).all()
    return render_template('restaurantOrders.html', orders=orders)

@app.route('/api/order/<int:order_id>/status', methods=['PUT'])
def update_order_status(order_id):
    if not session.get('is_restaurant'):
        return jsonify({"message": "Unauthorized"}), 401
    
    order = Order.query.get_or_404(order_id)
    if order.restaurant_id != session['restaurant_id']:
        return jsonify({"message": "Unauthorized"}), 401
    
    data = request.get_json()
    new_status = data.get('status')
    if new_status not in ['accepted', 'completed', 'cancelled']:
        return jsonify({"message": "Invalid status"}), 400
    
    try:
        order.status = new_status
        db.session.commit()
        return jsonify({"message": "Order status updated successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": f"Error updating order: {str(e)}"}), 500

# Add this route to view pending orders for restaurants
@app.route('/restaurant/pending-orders', methods=['GET'])
def view_pending_orders():
    if not session.get('is_restaurant'):
        return redirect(url_for('login_restaurant'))
    
    try:
        # Fetch pending orders for the restaurant
        orders = Order.query.filter_by(restaurant_id=session['restaurant_id'], status='pending').all()
        return render_template('pendingOrders.html', orders=orders)
    except Exception as e:
        print(f"Error fetching pending orders: {str(e)}")  # Add logging for debugging
        flash('Error loading pending orders', 'error')
        return redirect(url_for('restaurant_orders'))

# Add this route to update order status
@app.route('/api/order/<int:order_id>/done', methods=['PUT'])
def mark_order_done(order_id):
    if not session.get('is_restaurant'):
        return jsonify({"message": "Unauthorized"}), 401
    
    order = Order.query.get_or_404(order_id)
    if order.restaurant_id != session['restaurant_id']:
        return jsonify({"message": "Unauthorized"}), 401
    
    try:
        order.status = 'completed'  # Change status to completed
        db.session.commit()
        return jsonify({"message": "Order status updated to completed"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": f"Error updating order: {str(e)}"}), 500

# Add this route for the home page
@app.route('/', methods=['GET'])
def home():
    return render_template('home.html')  # Render a home page template

if __name__ == '__main__':
    with app.app_context():
        
        db.create_all()  
    app.run(debug=True)