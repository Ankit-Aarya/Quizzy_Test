from flask import Flask
from dotenv import load_dotenv
import os

# Initialize Flask app
app = Flask(__name__)

# Load environment variables
load_dotenv()

# Configure the app
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS')

# Import routes
import routes
import models

if __name__ == '__main__':
    app.run(debug=True)
