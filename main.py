from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask import render_template
from flask import request
from flask import url_for
from flask import redirect
from flask_bootstrap import Bootstrap
from flask_login import UserMixin , login_required , LoginManager , login_user , logout_user ,current_user
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired , InputRequired , Email , Length 
from wtforms import validators , StringField ,SubmitField , BooleanField , PasswordField
import datetime
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
app = Flask(__name__)

Bootstrap(app)

app.config['SECRET_KEY'] = "#@@$FSDFVdasd4$@#2$@34dasD#@E@$#$@"

app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///db.sqlite3"

db = SQLAlchemy(app)

loginmanager= LoginManager()

loginmanager.init_app(app)

@loginmanager.user_loader

def loaduser(id):

    user = User.query.get(int(id))


class User(UserMixin , db.Model):

    id = db.Column(db.Integer , primary_key = True)

    username = db.Column(db.String(40) , unique = True)

    email = db.Column(db.String(100) , unique=True)

    password = db.Column(db.String(200) , nullable = False)

    date_created = db.Column(db.DateTime , default = datetime.datetime.utcnow)


    def __repr__(self):

        return " user %r" %str(self.username)

class UserLoginForm(FlaskForm):

    username = StringField('username' , validators = [InputRequired() , Length(min=3 , max=30)])

    password = PasswordField('password' , validators = [InputRequired() , Length(min=6 , max = 40)])

    remember = BooleanField('remember me')

class UserRegisterForm(FlaskForm):

    email = StringField('email' , validators = [Email(" invalid Email ")])

    username = StringField('username' , validators = [InputRequired() , Length(min=3 , max=30)])

    password = PasswordField('password' , validators = [InputRequired() , Length(min=6 , max = 40)])

    cpass = PasswordField('password confirmation' , validators = [InputRequired() , Length(min=6 , max = 40)])




@app.route('/')

def homepage():


    return "homepage"


@app.route('/user/login' , methods= ['GET' , 'POST'])

def login():
    
    form = UserLoginForm()

    if form.validate_on_submit():

        user = {
            "username": form.username.data,
            "password":form.password.data
        }

        query = User.query.filter_by(username = user["username"]).first()

        if query:

            if check_password_hash(query.password , user['password']):

                login_user(query , remember = form.remember.data)

                return redirect('/')

            else:
                return "password didnt match"

        else:

            return "failed to fetch user"

    
        return redirect('/user/login')



    

    return render_template("login.html" , title = "user login" , form = form)


@app.route('/register' , methods = ['GET', 'POST'])

def register():
    
    form = UserRegisterForm()


    if form.validate_on_submit():

        newuser = {
            "username"  :form.username.data , 
            "email" : form.email.data ,
            "password" : form.password.data ,
            "cpass" : form.cpass.data 
        }

        authenticate_query = User.query.filter_by(username = newuser["username"]).first()
        authenticate_query2 = User.query.filter_by(email = newuser["email"]).first()

        if not authenticate_query:

            if not authenticate_query2:

                

                validatedpw1 = generate_password_hash(newuser['password'])
                validatedpw2 = generate_password_hash(newuser["cpass"])

                if newuser["password"] == newuser["cpass"]:

                    nuser = User(username = newuser['username'] , email = newuser['email'] , password = validatedpw1)

                    db.session.add(nuser)

                    db.session.commit()

                    return redirect('/user/login')

                else:

                    return "<script>alert('two password didnt match')</script>"

            else:
                return "<script>alert('user with that email exists try a different one')</script>"

            
            return "<script>alert('try a different username')</script>"

        



                






    

    return render_template("register.html" , title = "user register" , form = form)


if __name__ == "__main__":

    app.run(debug=True)

