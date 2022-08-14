import base64
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
from functools import wraps
import os

app = Flask(__name__)

app.config['SECRET_KEY'] = '004f2af45d3a4e161a7dd2d17fdae47f'
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + \
    os.path.join(basedir, 'app.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.Integer)
    name = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)


class Courses(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rate = db.Column(db.Integer)
    views = db.Column(db.Integer)
    title = db.Column(db.String(300), nullable=False)
    link = db.Column(db.String(300), nullable=False)
    dis = db.Column(db.String(1000), nullable=False)


class Tags(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fid = db.Column(db.Integer, db.ForeignKey('courses.id'), nullable=False)
    tags = db.Column(db.String(100), nullable=False)


class Instructors(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fid = db.Column(db.Integer, db.ForeignKey('courses.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    image = db.Column(db.BLOB)


class Images(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fid = db.Column(db.Integer, db.ForeignKey('courses.id'), nullable=False)
    image = db.Column(db.BLOB)


class Index(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fid = db.Column(db.Integer, db.ForeignKey('courses.id'), nullable=False)
    json = db.Column(db.JSON)


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']

        if not token:
            return jsonify({'message': 'a valid token is missing'})

        try:
            data = jwt.decode(
                token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Users.query.filter_by(
                public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'token is invalid'})

        return f(current_user, *args, **kwargs)
    return decorator


@app.route('/register', methods=['POST'])
def signup_user():
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = Users(public_id=str(uuid.uuid4()),
                     name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'registeration successfully'})


@app.route('/login', methods=['POST'])
def login_user():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('could not verify', 401, {'Authentication': 'login required"'})

    user = Users.query.filter_by(name=auth.username).first()

    if check_password_hash(user.password, auth.password):

        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow(
        ) + datetime.timedelta(minutes=45)}, app.config['SECRET_KEY'], "HS256")
        return jsonify({'token': token})

    return make_response('could not verify',  401, {'Authentication': '"login required"'})


@app.route('/course', methods=['POST'])
@token_required
def create_course(current_user):

    data = request.get_json()

    new_course = Courses(rate=data['rate'], views=data['views'], title=data['title'],
                         link=data['link'], dis=data['dis'])
    db.session.add(new_course)

    names = db.session.query(Courses).order_by(Courses.id.desc()).first()
    if names is not None:
        names = names.id
    else:
        names = 1

    for child in data['tags']:
        new_tags = Tags(fid=names, tags=child)
        db.session.add(new_tags)

    for child in data['image']:
        new_images = Images(
            fid=names, image=base64.encodebytes(child.encode()))
        db.session.add(new_images)

    for child in data['Instructors']:
        new_instructors = Instructors(
            fid=names, name=child['instructor'], image=base64.encodebytes(child['instructorImage'].encode()))
        db.session.add(new_instructors)

    new_index = Index(fid=names, json=data['Index'])
    db.session.add(new_index)

    db.session.commit()

    return jsonify({'message': 'new course added'})


@app.route('/allcourses', methods=['GET'])
@token_required
def get_allcourses(current_user):

    books = db.session.query(
        Courses,
        Tags,
        Instructors,
        Images,
        Index
    ).filter(
        Courses.id == Tags.fid
    ).filter(
        Courses.id == Instructors.fid
    ).filter(
        Courses.id == Images.fid
    ).filter(
        Courses.id == Index.fid
    ).all()

    # output = []
    # for book in books:
    #     book_data = {}
    #     book_data['id'] = book.id
    #     book_data['name'] = book.name
    #     book_data['Author'] = book.Author
    #     book_data['Publisher'] = book.Publisher
    #     book_data['book_prize'] = book.book_prize
    #     output.append(book_data)

    return jsonify(books)


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
