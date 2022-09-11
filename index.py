from flask import send_from_directory
from uuid import uuid4
from flask import Flask, request, jsonify
from flask import make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import UUID
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import jwt
import datetime
import uuid
from functools import wraps
import os
import flask_cors
cors = flask_cors.CORS()
app = Flask(__name__)

app.config['SECRET_KEY'] = '004f2af45d3a4e161a7dd2d17fdae47f'
basedir = os.path.abspath(os.path.dirname(__file__))

# username = 'freakstar03'
# password = 'password'
# database = 'devbootcamp'
url = "172.18.0.2"
app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://freakstar03:password@" + \
    url + ":5432/devbootcamp"

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)
cors.init_app(app)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(UUID(as_uuid=True))
    name = db.Column(db.String(300))
    email = db.Column(db.String(300))
    password = db.Column(db.String(300))
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
    image = db.Column(db.String(300), nullable=False)


class Images(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fid = db.Column(db.Integer, db.ForeignKey('courses.id'), nullable=False)
    image = db.Column(db.String(300), nullable=False)


class Index(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # indexid = db.Column(db.Integer, db.ForeignKey('index.id'), nullable=False)
    fid = db.Column(db.Integer, db.ForeignKey('courses.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    parent = db.Column(db.String(100), nullable=False)
    key = db.Column(db.String(300), nullable=False)


class Certificate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    certificate = db.Column(db.String(300), nullable=False)


class Enrollment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uid = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    cid = db.Column(db.Integer, db.ForeignKey('courses.id'), nullable=False)
    certificateid = db.Column(db.Integer, db.ForeignKey(
        'certificate.id'), nullable=True)


class Completion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cid = db.Column(db.Integer, db.ForeignKey('courses.id'), nullable=False)
    uid = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    indexid = db.Column(db.Integer, db.ForeignKey(
        'index.id'), nullable=False)


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']

        if not token:
            # return jsonify({'message': 'a valid token is missing'})
            return make_response(jsonify({'message': 'a valid token is missing'}), 404)

        try:
            data = jwt.decode(
                token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Users.query.filter_by(
                public_id=data['public_id']).first()
        except:
            # return jsonify({'message': 'token is invalid'})
            return make_response(jsonify({'message': 'token is invalid'}), 404)

        return f(current_user, *args, **kwargs)
    return decorator


UPLOAD_FOLDER = app.root_path
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def make_unique(string):
    ident = uuid4().__str__()
    return f"{ident}-{string}"


@app.route('/')
def hello_world():
    return 'Hello, World!'


@app.route('/upload/images', methods=['POST'])
def fileUpload():
    names = []
    target = os.path.join(UPLOAD_FOLDER, "static", 'images')
    if not os.path.isdir(target):
        os.mkdir(target)
    print("welcome to upload`")
    # file = request.files['file']
    files = request.files.getlist("file")
    for file in files:
        filename = secure_filename(make_unique(file.filename))
        destination = "/".join([target, filename])
        file.save(destination)
        names.append(filename)
    # session['uploadFilePath'] = destination
    response = jsonify({'message': 'uploaded', 'names': names})
    return response


@app.route('/upload/instructor', methods=['POST'])
def fileUploadForInstructor():
    # names = []
    # titles_arr = []
    output = []

    target = os.path.join(UPLOAD_FOLDER, "static", 'instructor')
    if not os.path.isdir(target):
        os.mkdir(target)
    print("welcome to upload`")
    # file = request.files['file']
    files = request.files.getlist("file")
    titles = request.form.getlist("input")

    if len(files) == len(titles):
        for i in range(len(files)):
            filename = secure_filename(make_unique(files[i].filename))
            destination = "/".join([target, filename])
            files[i].save(destination)
            dictn = {
                "instructor": titles[i],
                "instructorImage": filename,
            }
            output.append(dictn)
            # names.append(filename)
            # titles_arr.append(titles[i])
        response = jsonify(
            {'message': 'uploaded', 'Instructors': output})
    else:
        response = jsonify(
            {'message': 'diff lenght'})

    return response


@app.route('/upload/markdown', methods=['POST'])
def fileUploadForMaarkdown():
    names = []
    target = os.path.join(UPLOAD_FOLDER + "protected", 'markdown')
    if not os.path.isdir(target):
        os.mkdir(target)
    print("welcome to upload`")
    # file = request.files['file']
    files = request.files.getlist("file")
    for file in files:
        filename = secure_filename(make_unique(file.filename))
        destination = "/".join([target, filename])
        file.save(destination)
        names.append(filename)
    # session['uploadFilePath'] = destination
    response = jsonify({'message': 'uploaded', 'names': names})
    return response


@app.route('/register', methods=['POST'])
def signup_user():
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = Users(public_id=str(uuid.uuid4()),
                     name=data['name'], email=data['email'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    user = Users.query.filter_by(email=data['email']).first()

    token = jwt.encode({'public_id': str(user.public_id), 'exp': datetime.datetime.utcnow(
    ) + datetime.timedelta(minutes=45)}, app.config['SECRET_KEY'], "HS256")
    return jsonify({'user': {'name': data['name'], 'email': data['email']}, 'token': token, 'message': 'registeration successfully'})


@app.route('/login', methods=['POST'])
def login_user():

    # req = request.get_json(force=True)
    # username = req.get('username', None)
    # password = req.get('password', None)

    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response(jsonify(message="Wrong Username or Password!"), 404)

    user = Users.query.filter_by(email=auth.username).first()

    if user and check_password_hash(user.password, auth.password):

        token = jwt.encode({'public_id': str(user.public_id), 'exp': datetime.datetime.utcnow(
        ) + datetime.timedelta(minutes=45)}, app.config['SECRET_KEY'], "HS256")
        return jsonify({'token': token, 'data': auth.username, 'name': user.name, 'email': user.email, 'message': 'registeration successfully'})

    # return make_response('could not verify',  401, {'Authentication': '"login required"'})
    return make_response(jsonify(message="Wrong Username or Password!"), 404)


@app.route('/login', methods=['GET'])
@token_required
def fetchUserByToken(currentUser):
    data = currentUser
    return jsonify({'user': {'name': data.name, 'email': data.email}, 'message': 'registeration successfully'})


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
            fid=names, image=child)
        db.session.add(new_images)

    for child in data['Instructors']:
        new_instructors = Instructors(
            fid=names, name=child['instructor'], image=child['instructorImage'])
        db.session.add(new_instructors)

    dictnry = data['Index']
    keys = dictnry.keys()
    for child in keys:
        for subchild in dictnry[child]:
            new_index = Index(
                fid=names, title=subchild["title"], key=subchild["key"], parent=child)
            db.session.add(new_index)

    # new_index = Index(fid=names, json=data['Index'])
    # db.session.add(new_index)

    db.session.commit()

    return jsonify({'message': 'new course added'})


@app.route('/allcoursesDetail', methods=['GET'])
@token_required
def get_allcoursesDetail(current_user):

    courses = db.session.query(Courses).all()
    print(courses)
    output = []
    for course in courses:
        # print('first')

        index = db.session.query(Index).filter(Index.fid == course.id).all()
        tags = db.session.query(Tags).filter(Tags.fid == course.id).all()
        images = db.session.query(Images).filter(Images.fid == course.id).all()
        instructors = db.session.query(Instructors).filter(
            Instructors.fid == course.id).all()

        course_data = {}
        course_data['id'] = course.id
        course_data['rate'] = course.rate
        course_data['views'] = course.views
        course_data['title'] = course.title
        course_data['link'] = course.link
        course_data['dis'] = course.dis

        # for i in index:
        #     course_data['Index'] = i.json

        IndexData = {}
        for i in index:
            if i.parent in index:
                IndexData[i.parent].append({
                    "title": i.title,
                    "key": i.key
                })
            else:
                IndexData[i.parent] = []
                IndexData[i.parent].append({
                    "title": i.title,
                    "key": i.key
                })
        course_data['Index'] = IndexData

        tag_data = []
        for i in tags:
            tag_data.append(i.tags)
        course_data['tags'] = tag_data

        tag_data = []
        for i in images:
            # tag_data.append(base64.b64decode(i.image).decode('ascii'))
            tag_data.append(i.image)
        course_data['image'] = tag_data

        tag_data = []
        for i in instructors:
            temp = {
                'instructor': i.name,
                # 'instructorImage': base64.b64decode(i.image).decode('ascii')
                'instructorImage': i.image
            }
            tag_data.append(temp)
        course_data['Instructors'] = tag_data
        tag_data = []

        output.append(course_data)

    return jsonify({'list_of_books': output})


@app.route('/allcourses', methods=['GET'])
@token_required
def get_allcourses(current_user):
    courses = db.session.query(Courses).all()
    print(courses)
    output = []
    for course in courses:
        # print('first')
        images = db.session.query(Images).filter(
            Images.fid == course.id).first()

        course_data = {}
        course_data['id'] = course.id
        course_data['rate'] = course.rate
        course_data['views'] = course.views
        course_data['title'] = course.title
        course_data['link'] = course.link
        course_data['dis'] = course.dis
        # course_data['image'] = base64.b64decode(images.image).decode('ascii')
        course_data['image'] = images.image

        output.append(course_data)

    return jsonify({'list_of_books': output})


@app.route('/course/<course_link>', methods=['GET'])
@token_required
def get_coursebyLInk(current_user, course_link):

    course = db.session.query(Courses).filter_by(link=course_link).first()
    # print(courses)
    output = {}
    if course:
        # print('first')

        index = db.session.query(Index).filter(Index.fid == course.id).all()
        completion = db.session.query(Completion).filter(
            Completion.cid == course.id, Completion.uid == int(current_user.id)).all()
        tags = db.session.query(Tags).filter(Tags.fid == course.id).all()
        images = db.session.query(Images).filter(Images.fid == course.id).all()
        instructors = db.session.query(Instructors).filter(
            Instructors.fid == course.id).all()

        course_data = {}
        course_data['id'] = course.id
        course_data['rate'] = course.rate
        course_data['views'] = course.views
        course_data['title'] = course.title
        course_data['link'] = course.link
        course_data['dis'] = course.dis

        IndexData = {}

        completionArr = []
        for c in completion:
            completionArr.append(c.indexid)

        print(completionArr)

        for i in index:
            if i.id in completionArr:
                if i.parent in IndexData:
                    IndexData[i.parent].append({
                        "title": i.title,
                        "key": i.key,
                        "completion": True
                    })
                else:
                    IndexData[i.parent] = []
                    IndexData[i.parent].append({
                        "title": i.title,
                        "key": i.key,
                        "completion": True
                    })
            else:
                if i.parent in IndexData:
                    IndexData[i.parent].append({
                        "title": i.title,
                        "key": i.key,
                        "completion": False
                    })
                else:
                    IndexData[i.parent] = []
                    IndexData[i.parent].append({
                        "title": i.title,
                        "key": i.key,
                        "completion": False
                    })
        course_data['Index'] = IndexData

        tag_data = []
        for i in tags:
            tag_data.append(i.tags)
        course_data['tags'] = tag_data

        tag_data = []
        for i in images:
            # tag_data.append(base64.b64decode(i.image).decode('ascii'))
            tag_data.append(i.image)
        course_data['image'] = tag_data

        tag_data = []
        for i in instructors:
            temp = {
                'instructor': i.name,
                # 'instructorImage': base64.b64decode(i.image).decode('ascii')
                'instructorImage': i.image
            }
            tag_data.append(temp)
        course_data['Instructors'] = tag_data
        tag_data = []

        output = course_data

        return jsonify({'book': output})
    else:
        return make_response(jsonify(message="no course found"), 404)


@app.route('/md/<path>')
@token_required
def send_report(current_user, path):
    updatepath = path + ".md"
    target = os.path.join(UPLOAD_FOLDER, "protected", 'markdown')
    target2 = os.path.join(UPLOAD_FOLDER, "protected", 'markdown', updatepath)
    if os.path.isfile(target2):
        return send_from_directory(target, updatepath)
    else:
        return make_response(jsonify(message="no such content!"), 404)


@app.route('/enroll/<course_id>', methods=['POST'])
@token_required
def enrollUser(current_user, course_id):
    data = request.get_json()
    course = db.session.query(Courses).filter_by(link=course_id).first()
    if course:
        courseID = course.id
        eroll_User = Enrollment(cid=int(courseID), uid=current_user.id)
        db.session.add(eroll_User)
        db.session.commit()
        return jsonify({'message': 'user enrolled'})
    else:
        return make_response(jsonify(message="wrong course"), 404)


@app.route('/enroll/<course_id>', methods=['GET'])
@token_required
def enrollUserGet(current_user, course_id):
    course = db.session.query(Courses).filter_by(link=course_id).first()
    if course:
        courseID = course.id
        eroll_User = db.session.query(
            Enrollment).filter_by(uid=int(current_user.id)).all()
        for child in eroll_User:
            if int(courseID) == child.cid:
                return jsonify({'message': 'user enrolled'})
        return make_response(jsonify(message="not enrolled"), 404)
    else:
        return make_response(jsonify(message="wrong course"), 404)


@app.route('/completion/<course_link>/<index_id>', methods=['POST'])
@token_required
def updateCompletion(current_user, course_link, index_id):
    course = db.session.query(Courses).filter_by(link=course_link).first()
    index = db.session.query(Index).filter_by(key=index_id).first()
    if index:
        indexID = index.id
        courseID = course.id
        completion = db.session.query(Completion).filter(
            Completion.uid == current_user.id, Completion.cid == courseID, Completion.indexid == indexID).all()
        if completion:
            return make_response(jsonify(message="already marked completed"), 404)
        eroll_User = Completion(cid=int(courseID), uid=int(
            current_user.id), indexid=indexID)
        db.session.add(eroll_User)
        db.session.commit()
        return jsonify({'message': 'updated completion'})
    else:
        return make_response(jsonify(message="failed update completion"), 404)


db.create_all()
if __name__ == '__main__':
    app.run(debug=True)
