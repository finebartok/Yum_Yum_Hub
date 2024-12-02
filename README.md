# Restaurant User Management System

## Overview
This project is a web application built using Flask that allows users and restaurants to register, log in, and manage their profiles making a platform for a marketplace business model for foodies and resurants. It utilizes a SQLite database for data storage and JWT for user authentication.

## Features
- User registration and login
- Restaurant registration and login
- Profile management for users
- Secure password storage using hashing
- JWT-based authentication for secure access

## Technologies Used
- Flask
- Flask-SQLAlchemy
- Flask-JWT-Extended
- SQLite
- HTML/CSS (Bootstrap for styling)

## Project Structure
SWE/
├── dbase.py # Database models for User and Restaurant
├── registration.py # Flask application with routes for user and restaurant management
├── templates/
│ ├── register_user.html # User registration form
│ └── userLogin.html # User login form
└── readme.md # Project documentation


## Setup Instructions

1. **Clone the repository:**

2. **Create a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install the required packages:**
   ```bash
   pip install Flask Flask-SQLAlchemy Flask-JWT-Extended
   ```

4. **Run the application:**
   ```bash
   python registration.py
   ```

5. **Access the application:**
   Open your web browser and navigate to `http://127.0.0.1:5000`.

## API Endpoints

### User Registration
- **Endpoint:** `/register/user`
- **Method:** `POST`
- **Request Body:**
  ```json
  {
      "name": "John Doe",
      "email": "john@example.com",
      "password": "securepassword",
      "phone_number": "1234567890",
      "address": "123 Main St"
  }
  ```

### User Login
- **Endpoint:** `/login/user`
- **Method:** `POST`
- **Request Body:**
  ```json
  {
      "email": "john@example.com",
      "password": "securepassword"
  }
  ```

### Restaurant Registration
- **Endpoint:** `/register/restaurant`
- **Method:** `POST`
- **Request Body:**
  ```json
  {
      "name": "Pizza Place",
      "email": "contact@pizzaplace.com",
      "password": "securepassword",
      "phone_number": "0987654321",
      "address": "456 Elm St",
      "description": "Best pizza in town!"
  }
  ```

### Restaurant Login
- **Endpoint:** `/login/restaurant`
- **Method:** `POST`
- **Request Body:**
  ```json
  {
      "email": "contact@pizzaplace.com",
      "password": "securepassword"
  }
  ```

### User Profile
- **Endpoint:** `/profile`
- **Method:** `GET`
- **Authentication:** Required (JWT)
