from flask import Flask, render_template, url_for, redirect, request
import json
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import os
from marshmallow import Schema

app = Flask(__name__)

url = os.getenv('DATABASE_URL')

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Fullstackgamer1@localhost/moneybase'
app.config['SECRET_KEY'] = 'secretkey'

db = SQLAlchemy(app)

#def get_db_connection():
    #conn = sqlite3.connect('moneybase.db')
    #conn.row_factory = sqlite3.Row
    #return conn

class User(db.Model):
    __tablename__ = 'moneyusers'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

    def __init__(self, username, password):
        self.username=username
        self.password=password

#app.context().push() with this is goated for connecting db
with app.app_context():
    db.create_all()
    

@app.route('/')
def hmpg():
    return render_template('home.html')

@app.route('/register', methods=['POST', 'GET'])
def register():
    #if request.method == ['POST']:
        #username=request.form['Username']
        #password=request.form['Password']
    #user=User(username, password)
    #db.session.add(user)
    #db.session.commit()
    return render_template('submit.html')

@app.route('/submit', methods=['POST', 'GET'])
def submit():
    if request.method == 'POST':
        username=request.form['username']
        password=request.form['password']
        
    
    user=User(username, password)
    db.session.add(user)
    db.session.commit()


#@app.route('/getposts')
#def getposts():
    #conn = get_db_connection()
    #posts = conn.execute('SELECT * FROM posts').fetchall()
    #conn.close()
    #return render_template('forum.html',  posts=posts)    

if __name__== '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)