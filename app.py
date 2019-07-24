from flask import Flask, request, make_response, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import os
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer as vsa


### initialization : create a user 'admin' - then login and promote admin to admin

app = Flask(__name__)

app.config['SECRET_KEY'] = '@Saturday&Sunday!'

file_path = os.path.abspath(os.getcwd())+"/dbtodo.db"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'+file_path

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    isAdmin = db.Column(db.Boolean)
    pass

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(50))
    isComplete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)
    pass


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        if not 'x-access-token' in request.headers:
            return jsonify({'message' : 'Token is missing!'}), 401

        token = request.headers['x-access-token']

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id = data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs) # current_user is SQLAlchemy object

    return decorated
# end of token_required

@app.route('/', methods=['GET'])
def readme():
    return render_template('readme.html')
# end of readme


@app.route('/user', methods=['GET'])
@token_required
def get_all_user(current_user):
    if not current_user.isAdmin:
        return jsonify({"message" : "Cannot perform this function"}),403

    users = User.query.all()

    output = []
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['isAdmin'] = user.isAdmin
        output.append(user_data)

    return jsonify({"users" : output})
# end of get_all_user

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({"message" : "User not found"})

    if not current_user.isAdmin and not current_user.public_id == user.public_id:
        return jsonify({"message" : "Cannot perform this function"}),403

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['isAdmin'] = user.isAdmin
    return user_data
# end of get_one_user

@app.route('/user', methods=['POST'])
#@token_required
def create_user():
    data = request.get_json()

    if User.query.filter_by(name = data['name']).first():
        return jsonify({'message': 'User Name already exists, choose another one'}), 422

    hashed_password = generate_password_hash(data['password'], method = 'sha256')

    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, isAdmin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'New User created !'})
# end of create_user

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"message" : "User not found"})

    if not current_user.isAdmin and not user.name == 'admin': # not Admin and also name is not admin then return
        return jsonify({"message" : "Cannot perform this function"}),403

    user.isAdmin = True
    db.session.commit()

    return jsonify({"message" : "User has been promoted to admin"})
# end of promote_user

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({"message": "User not found"})

    if not current_user.isAdmin and not current_user.public_id == user.public_id: # not Admin and also not current = user then return
        return jsonify({"message" : "Cannot perform this function"}),403

    db.session.delete(user)
    db.session.commit()

    return jsonify({"message" : "User has been deleted"})
# end of delete_user


@app.route('/login', methods=['GET'])
def login():

    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('<h1>Could not verify !</h1>', 401, {'WWW-Authenticate' : 'Basic realm="Login Required"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('<h1>Could not verify !</h1>', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

    if not check_password_hash(user.password, auth.password):
        return make_response('<h1>Could not verify !</h1>', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

    payload = {'public_id' : user.public_id,
               #'name' : user.name,
               'exp' : datetime.datetime.utcnow()+datetime.timedelta(minutes=30)}

    ## app.config['SECRET_KEY'] by default is none, but currently value assigned at top of program
    token = jwt.encode(payload, app.config['SECRET_KEY'])
    #print('Secret Key is :::: ', app.config['SECRET_KEY'])

    return jsonify({'token' : token.decode('UTF-8')})
# end of login


@app.route('/token', methods=['POST'])
def get_token():
    data = request.get_json()

    data_user_name = data['name']
    data_user_password = data['password']

    user = User.query.filter_by(name=data_user_name).first()
    if not user:
        return make_response('<h1>Could not verify !</h1>', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})
    if not check_password_hash(user.password, data_user_password):
        return make_response('<h1>Could not verify !</h1>', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

    payload = {'public_id': user.public_id,
               # 'name' : user.name,
               'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}

    ## app.config['SECRET_KEY'] by default is none, but currently value assigned at top of program
    token = jwt.encode(payload, app.config['SECRET_KEY'])
    # print('Secret Key is :::: ', app.config['SECRET_KEY'])

    return jsonify({'token': token.decode('UTF-8')})
# end of get_token

@app.route('/sentiment', methods=['POST'])
@token_required
def get_sentiment(current_user):
    data = request.get_json()

    #crating a sentiment analyser object
    sao = vsa()
    sentiment_dict = sao.polarity_scores(data['sentence'])

    sentiment = {}
    sentiment['positive'] = sentiment_dict['pos']
    sentiment['neutral'] = sentiment_dict['neu']
    sentiment['negative'] = sentiment_dict['neg']
    sentiment['compound'] = sentiment_dict['compound']

    return jsonify({"sentiment" : sentiment})
# end of get_sentiment

if __name__ == '__main__':
    app.run(debug=True)
