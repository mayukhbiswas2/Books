from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_restful  import Resource, Api
from flask_jwt_extended import create_access_token, JWTManager, get_jwt_identity, jwt_required

app = Flask(__name__)

app.config['SECRET_KEY'] = 'SUPER-SECRET-KEY'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///jwt.db'


db = SQLAlchemy(app)
api = Api(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(100), nullable=False)

with app.app_context():
    db.create_all()

class UserRegister(Resource):
    def post(self):
        data = request.get_json()
        username = data['username']
        password = data['password']

        if not username or not password:
            return {'message': 'Missing username or password...'}, 400
        if User.query.filter_by(username=username).first():
            return {'message': 'Username already taken...'}, 400

        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        return {'message': 'User created successfully..'}, 200


class UserLogin(Resource):
    def post(self):
        data = request.get_json()
        username = data['username']
        password = data['password']

        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            access_token = create_access_token(identity=user.id)
            return {'access_token': access_token}, 200

        return {'message': 'Invalid credentials...'}, 401

class BookList(Resource):
    @jwt_required()
    def get(self):
        books = Book.query.all()
        return[{'id': book.id, 'title': book.title, 'author': book.author} for book in books], 200

    @jwt_required()
    def post(self):
        # Add a new book
        data = request.get_json()
        title = data['title']
        author = data['author']

        if not title or not author:
            return {'message': 'Missing title or author...'}, 400

        new_book = Book(title=title, author=author)
        db.session.add(new_book)
        db.session.commit()
        return {'message': 'Book added successfully..'}, 201


api.add_resource(UserRegister, '/register')
api.add_resource(UserLogin, '/login')
api.add_resource(BookList, '/books')

if __name__ == '__main__':
    app.run(debug=True)