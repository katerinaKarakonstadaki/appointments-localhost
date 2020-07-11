import sys
from flask import Flask
from flask import session
from flask_sqlalchemy  import SQLAlchemy
from flask import Flask, render_template, redirect, url_for, request, make_response, g
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_security import Security, SQLAlchemyUserDatastore,current_user,login_required, UserMixin,RoleMixin
from flask_security.utils import hash_password
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask import Flask, render_template, request, redirect, url_for, flash
from flask import jsonify
from wtforms import StringField, PasswordField, BooleanField, SubmitField, DateTimeField
from wtforms.validators import InputRequired, Email, Length
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask import jsonify
from datetime import datetime, timedelta
from functools import wraps
import http.client
from flask import abort
from flask_restplus import Namespace, Resource, fields
import string
import email
import uuid
import jwt
from flask_restplus import Api
from parse import parse
import json  
import urllib
from urllib.request import urlopen
import logging
import urllib.request


logger = logging.getLogger(__name__)


import os
class Configuration(object):
  APPLICATION_DIR = os.path.dirname(os.path.realpath(__file__))
  DEBUG = True
  SECRET_KEY= 'Thisisasecretkey'
  PUBLIC_KEY = 'Thisisapublickey'
  PRIVATE_KEY= 'Thisisaprivatekey'
  #SQLALCHEMY_DATABASE_URI = 'sqlite:///%s/db.sqlite3' % APPLICATION_DIR  
  SQLALCHEMY_DATABASE_URI = 'postgresql+psycopg2://appuser:123@localhost/appdb'
#app.config['SECURITY_PASSWORD_HASH'] =  "bcrypt"

app = Flask(__name__)

app.config.from_object(Configuration)
app.config['SECRET_KEY']= 'Thisisasecretkey'
private_key= 'Thisisaprivatekey'
public_key = 'Thisisapublickey'

#application.config['RESTPLUS_MASK_SWAGGER'] = False

# use values from our configuration project
db=SQLAlchemy(app) #instruct SQLAlchemy how to interact with our database

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)

bootstrap = Bootstrap(app)

@login_manager.user_loader
def get_user(ident):
    return User.query.get(int(ident))



roles_users = db.Table('role_users',
    db.Column('user_id',db.Integer,db.ForeignKey('user.id')),
    db.Column('role_id',db.Integer,db.ForeignKey('role.id')))


class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(200), unique=True)
    username = db.Column(db.String(64), unique=True, index=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(200))
    creation = db.Column(db.DateTime, nullable=False)
    active = db.Column(db.Boolean())
    admin=db.Column(db.Boolean)
    roles = db.relationship('Role',
                             secondary=roles_users,
                             backref=db.backref('user', lazy='dynamic')
                            )
    def has_roles(self, *args):
        return set(args).issubset({role.name for role in self.roles})




class Role(RoleMixin,db.Model):
    __tablename__ = 'role'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80))
    #users = db.relationship('User', backref='role')
    description =db.Column(db.String(255))


user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

db.create_all()







class RegisterForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=2, max=15)])
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=2, max=15)],render_kw={"placeholder": "username"})
    password = PasswordField('Password', validators=[InputRequired()])
    remember = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')


#@app.before_request
#def create_user():
    # Create the Roles "admin" and "end-user" -- unless they already exist
    # Create the Roles "admin" and "end-user" -- unless they already exist
    #user_datastore.find_or_create_role(name='admin', description='Administrator')
    #user_datastore.find_or_create_role(name='employee', description='employee')
    #user_datastore.find_or_create_role(name='citizen', description='citizen')

    #user_datastore.add_role_to_user('admin@mail.com', 'admin')
    #user_datastore.add_role_to_user('employee@mail.com', 'employee')
    #db.session.commit()
    

@app.route("/api/register/", methods =['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(public_id=str(uuid.uuid4()), username=form.username.data, email=form.email.data, password=hashed_password,creation=datetime.utcnow(), active=True, admin=False)
        db.session.add(new_user)
        if (form.email.data =='employee@mail.com'):
            user_datastore.add_role_to_user(form.email.data, 'employee')
            db.session.commit()
        else:
            user_datastore.add_role_to_user(form.email.data, 'citizen')
            db.session.commit()
        return redirect(url_for('login'))
    else:
        return render_template('register.html', form=form)


@app.route("/api/login/", methods =['GET','POST'])
#@login_required
def login():
    form = LoginForm(request.form)
    user=User.query.filter_by(username = form.username.data).first()
    
    if user and check_password_hash(user.password, form.password.data):
        login_user(user,remember= form.remember.data)
        return redirect("http://localhost:5001/api/menu")
        #redirect(url_for('profile'))
    else:
        flash('Login failed!- Please check password')

        
    return render_template('login.html', form=form)

@app.route('/api/profile')
def profile():
    return render_template('profile.html')


@app.route('/api/home')
def home():
  return render_template('home.html')

@app.route("/api/aboutUs")
def about():
    g.user = current_user.username
    print(g.user)
    return render_template("aboutUs.html")

@app.route("/api/terms")
def terms():
  return render_template("terms.html")

@app.route("/api/Privacy")
def privacy():
  return render_template("privacy.html")







#------------------------------------Begin Api-----------------------------------

api = Api(app=app)

def encode_token(payload, private_key):
    return jwt.encode(payload, private_key, algorithm='HS256')

def decode_token(token, public_key):
    return jwt.decode(token, public_key, algoritms='HS256')


def generate_token_header(username, private_key
):
    '''
    Generate a token header base on the username. Sign using the private key.
    '''
    payload = {
        'username': username,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(days=2),
    }
    token = encode_token(payload, private_key)
    token = token.decode('utf8')
    return f'Bearer {token}'

def validate_token_header(header, public_key):
    '''
    Validate that a token header is correct
    If correct, it return the username, if not, it
    returns None
    '''
    if not header:
        logger.info('No header')
        return None

     # Retrieve the Bearer token
    parse_result = parse('Bearer {}', header)
    if not parse_result:
        logger.info(f'Wrong format for header "{header}"')
        return None
    token = parse_result[0]
    try:
        decoded_token = decode_token(token.encode('utf8'), public_key)
    except jwt.exceptions.DecodeError:
        logger.warning(f'Error decoding header "{header}". '
                       'This may be key missmatch or wrong key')
        return None
    except jwt.exceptions.ExpiredSignatureError:
        logger.error(f'Authentication header has expired')
        return None
        
    # Check expiry is in the token
    if 'exp' not in decoded_token:
        logger.warning('Token does not have expiry (exp)')
        return None

    # Check username is in the token
    if 'username' not in decoded_token:
        logger.warning('Token does not have username')
        return None

    logger.info('Header successfully validated')
    return decoded_token['username']


api_namespace = api.namespace('api', description='API operations')

def authentication_header_parser(value):
    username = validate_token_header(value, public_key)
    if username is None:
        abort(401)
    return username

model = {
    'id': fields.Integer(),
    'username': fields.String(),
    'password': fields.String(),
    'creation': fields.DateTime(),
}
user_model = api_namespace.model('User', model)

# Input and output formats for Users

authentication_parser = api_namespace.parser()
authentication_parser.add_argument('Authorization', location='headers',
                                   type=str,
                                   help='Bearer Access Token')

register_parser=api_namespace.parser()
register_parser.add_argument('username', type=str, required=False,
                              help='username')


register_parser.add_argument('email', type=str, required=False,
                              help='email')

register_parser.add_argument('password', type=str, required=False,
                              help='password')


login_parser = api_namespace.parser()
login_parser.add_argument('username', type=str, required=False,
                          help='username')
login_parser.add_argument('password', type=str, required=False,
                          help='password')    



@api_namespace.route('/register1/')
class UserCreate(Resource):
    @api_namespace.doc('register')
    @api_namespace.expect(register_parser)
    @api_namespace.marshal_with(user_model, code=http.client.CREATED)
    def post(self):
        '''
        Create a new user
        '''
        #form = RegisterForm()
        args = register_parser.parse_args()
        new_user = User(username=args['username'],
                        public_id=str(uuid.uuid4()),
                        email=args['email'],
                        password=generate_password_hash(args['password'], method='sha256'),
                        creation=datetime.utcnow(),
                        active=True,
                        admin = False
                        )
        db.session.add(new_user)
        db.session.commit()
        result = api_namespace.marshal(new_user, user_model)
        return result, http.client.CREATED
        




@api_namespace.route('/login1/')
class UserLogin(Resource):

    @api_namespace.doc('login')
    @api_namespace.expect(login_parser)
    def post(self):
        '''
        Login and return a valid Authorization header
        '''
        args = login_parser.parse_args()

        # Search for the user
        user = (User
                .query
                .filter(User.username == args['username'])
                .first())
        if not user:
            return '', http.client.UNAUTHORIZED
    

        # Check the password
        
        if not check_password_hash(user.password, args['password']):
            return '', http.client.UNAUTHORIZED

        #Generate the header
        header = generate_token_header(user.username, private_key)
        return {'Authorized': header}

        #return make_response(render_template('testlogin.html'))#http.client.OK



if __name__ == "__main__":
    app.run(debug=True,host='0.0.0.0', port=5000)
