import sys
from flask import Flask
from flask import session
import requests
from flask_sqlalchemy  import SQLAlchemy
from flask import Flask, render_template, redirect, url_for, request, make_response
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore,current_user,login_required, UserMixin,RoleMixin
from flask_security.utils import hash_password
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask import Flask, render_template, request, redirect, url_for, flash
from flask import jsonify
from wtforms import StringField, PasswordField, BooleanField, SubmitField, DateTimeField, TimeField
from wtforms.validators import InputRequired, Email, Length
from flask import jsonify
from flask_mail import Mail
from flask_mail import Message
from datetime import datetime, timedelta
from functools import wraps
import http.client
from flask_user import roles_required, login_required
from flask import abort
from flask_restplus import Namespace, Resource, fields
import string
import email
import uuid
import jwt
from flask_restplus import Api
from parse import parse
import json  
from wtforms.fields.html5 import DateField
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
  SQLALCHEMY_TRACK_MODIFICATIONS = False
  MAIL_SERVER='smtp.gmail.com'
  MAIL_PORT= 465
  #MAIL_USERNAME = '2epal@gmail.com' 
  #MAIL_PASSWORD = '*****'
  MAIL_USE_TLS = False
  MAIL_USE_SSL = True
  #SQLALCHEMY_DATABASE_URI = 'sqlite:///%s/db.sqlite3' % APPLICATION_DIR  
  SQLALCHEMY_DATABASE_URI = 'postgresql+psycopg2://appuser:123@localhost/appdb'
#app.config['SECURITY_PASSWORD_HASH'] =  "bcrypt"

app = Flask(__name__)
app.config.from_object(Configuration)
app.config['SECRET_KEY']= 'Thisisasecretkey'
private_key= 'Thisisaprivatekey'
public_key = 'Thisisapublickey'
app.config['SQLALCHEMY_DATABASE_URI']='postgresql+psycopg2://appuser:123@localhost/appdb'
app.config['MAIL_SERVER']= 'linux110.papaki.gr'
app.config['MAIL_PORT']=587
app.config['MAIL_USE_SSL']=False
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_DEBUG']=True
app.config['MAIL_USERNAME']='info@public-services.site'
app.config['MAIL_PASSWORD']='pas!!123'

# use values from our configuration project
db=SQLAlchemy(app) #instruct SQLAlchemy how to interact with our database

#import sqlite3
import psycopg2

login_manager = LoginManager()
login_manager.init_app(app)

bootstrap = Bootstrap(app)

#security = Security()
#security.init_app(app)


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







class Appointment(db.Model):

    """An appointment on the calendar."""
    __tablename__ = 'appointment'
 
    id = db.Column(db.Integer, primary_key=True)
    created = db.Column(db.DateTime) #, default=datetime.now)
    modified = db.Column(db.DateTime) #, default=datetime.now, onupdate=datetime.now)
    #user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    #user = db.relationship(User, lazy='joined', join_depth=1, viewonly=True)
    username = db.Column(db.String(255))
    email = db.Column(db.String(255))
    start = db.Column(db.DateTime)
    time = db.Column(db.String)
    location = db.Column(db.String(255))
    approved =db.Column(db.Boolean)


class AppointmentForm(FlaskForm):
    username = StringField('Username', [Length(max=255)])
    email =StringField('Email', [Length(max=255)])
    start =DateField('Start')
    #start = DateTimeField('Start','%Y-%m-%d %H:%M:%S')
    time=StringField('Time')
    location = StringField('Location', [Length(max=255)])
    



db.create_all()

#@app.before_request
#def create_user():
    #user_datastore.add_role_to_user('jenny@mail.com', 'citizen')
    #user_datastore.find_or_create_role(name='employee', description='Employee')
    #user_datastore.find_or_create_role(name='citizen', description='Citizen')
    #user_datastore.find_or_create_role(name='admin', description='Administrator')
    #db.session.commit()

@login_manager.user_loader
def get_user(ident):
    return User.query.get(int(ident))

@app.route('/api/menu/')
def menu():
    return render_template('application.html')

@app.route('/api/add/', methods=['GET','POST'])
def appointment_create():
    form= AppointmentForm()
    url_api =urlopen('https://hr.apografi.gov.gr/api/public/organizations').read()
    parsed=json.loads(url_api)
    if request.method == 'POST' and form.validate():
        apt=Appointment(created=datetime.utcnow(),
                    modified=datetime.utcnow(),
                    username=form.username.data,
                    email = form.email.data,
                    start=(form.start.data),
                    time=form.time.data,
                    location=form.location.data,
                    approved=False)
     

      
      
        db.session.add(apt)
        db.session.commit()
    return render_template('add.html', form=form, parsed=parsed)



@app.route('/api/approve/',  methods=['GET','POST'])
#@roles_required('employee')
def approve_appointment():
    if current_user.has_roles('citizen'):
        print('hello1')
        flash('You are not allowed')
        return render_template('flash.html')
        return redirect(url_for('menu'))
    else:
        
        conn = psycopg2.connect("dbname='appdb' user='appuser' host='localhost' password='123'")
    #conn = psycopg2.connect(app.config['SQLALCHEMY_DATABASE_URI']=postgresql+psycopg2://appuser:123@localhost/appdb)
    #except:
    #    print("I am unable to connect to the database")

    #conn = sqlite3.connect('db.sqlite3')
        c = conn.cursor()
        c.execute("SELECT username,email,start,time,location, approved FROM appointment where approved=False")
        data = c.fetchall()
        if request.method == 'POST':
            if request.form['submit-button'] == "Submit":
                for checkbox in request.form.getlist('check'):
                    print(checkbox)
                    sql_query = """UPDATE appointment SET approved=True where email=%s"""
                    c.execute(sql_query,(checkbox,))
                    conn.commit()
                    #count=c.rowcount
                    res = requests.post('http://127.0.0.1:5002/api/notify/', json={"email":checkbox})
                #redirect("http://127.0.0.1:5001/api/notify/<email>",checkbox)
    return render_template('approve.html', data=data)
   # return ('',204)





@app.route("/api/logout", methods =['GET','POST'])
def logout_appoint():
    logout_user()
    #return "hello"
    return redirect('http://127.0.0.1:5000/api/home')
  #return render_template("dashboard.html")



#-------------------------Begin Api------------------------------------------------

import logging
logger = logging.getLogger(__name__)

api = Api(app=app)



def encode_token(payload, private_key):
    return jwt.encode(payload, private_key, algorithm='HS256')

def decode_token(token, public_key):
    return jwt.decode(token, public_key, algoritms='HS256')

def generate_token_header(username, private_key):
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
'''
    Generate a token header base on the username. Sign using the private key.
'''

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


def authentication_header_parser(value):
    username = validate_token_header(value, config.PUBLIC_KEY)
    if username is None:
        abort(401)
    return username



api_namespace = api.namespace('api', description='API operations')

authentication_parser = api_namespace.parser()



appointment_parser = api_namespace.parser()
allappoint_parser=api_namespace.parser()

allappoint_parser.add_argument('username', type=str, required = False,
                            help='username')

appointment_parser.add_argument('username', type=str, required=False,
                            help= 'username')
appointment_parser.add_argument('email', type=str, required=False,
                            help='email')
#appointment_parser.add_argument('start', type=inputs.date(), required=False,
                            #help='date')
appointment_parser.add_argument('TimeAppoint', type=str, required=False,
                            help= 'time of appoint')
appointment_parser.add_argument('location', type=str, required=False,
                            help='location')                           
                          

model = {
    'id': fields.Integer(),
    #'modified': fields.DateTime(),
    'username': fields.String(),
    'email': fields.String(),
    'start': fields.DateTime(),
    'location': fields.String(),
}

appointment_model = api_namespace.model('Appointment', model)



@api_namespace.route('/appointment')
class AppointListCreate(Resource):
    @api_namespace.doc('list_appointments')
    #@api_namespace.expect(authentication_parser)
    @api_namespace.expect(allappoint_parser)
    @api_namespace.marshal_with(appointment_model, as_list=True)
    def get(self):
        '''
        Retrieves all the appointments
        '''
        args1=allappoint_parser.parse_args()
        appointments = (Appointment
                        .query
                        .filter(Appointment.username == args1['username'])
                        .order_by('id')
                        .all())
        return appointments
    
    @api_namespace.doc('create_appointment')
    @api_namespace.expect(appointment_parser)
    @api_namespace.marshal_with(appointment_model, code=http.client.CREATED)
    def post(self):
        '''
        Create appointments
        '''
        args = appointment_parser.parse_args()
        #username = authentication_header_parser(args['Authorization'])
        new_appoint = Appointment(created=datetime.utcnow(),
                                  modified = datetime.utcnow(),
                                  username=args['username'],
                                  email= args['email'],
                                  start=datetime.utcnow(),
                                  time=args['TimeAppoint'],
                                  location=args['location'],
                                  approved= False)

        db.session.add(new_appoint)
        db.session.commit()

        result = api_namespace.marshal(new_appoint, appointment_model)
        return result, http.client.CREATED

@api_namespace.route('/appointments/<int:id>')
class OneAppointment(Resource):
    @api_namespace.doc('retrieve_appointment')
    @api_namespace.marshal_with(appointment_model)
    def get(self, id):
        """
        Displays an appointment  details
        """  
        appointment_one = appointment.query.get(id)
        if not appointment_one:
        # The appointment is not present
            return '', http.client.NOT_FOUND 
        return appointment_id 

    def put(self, id):
        """
        Edits a selected appointment
        """

if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0', port=5001)





