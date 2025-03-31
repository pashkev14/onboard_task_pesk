from datetime import timedelta
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required,
    get_jwt_identity, get_jwt
)
from werkzeug.security import generate_password_hash, check_password_hash
import redis


ACCESS_EXPIRES = timedelta(hours=1) # здесь указываем срок годности токена

app = Flask(__name__)

# Настройка SQLite базы с данными пользователей
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    # хоть поле и называется password, здесь нужно хранить хэш
    # введенного пользователем пароля
    password = db.Column(db.String, nullable=False)


# Триггерим создание базы из конфига и модели при первом запуске приложения
# (все сохранится в папке instance, ее включим в .gitignore)
with app.app_context():
    db.create_all()

# Настройка JWT
app.config['JWT_SECRET_KEY'] = 'very-secret-key' # мок ключ
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = ACCESS_EXPIRES
jwt = JWTManager(app)

# Настройка Redis, для задания установим стандартное соединение (на localhost:6379)
rds = redis.Redis()


@jwt.token_in_blocklist_loader
def is_token_in_blocklist(jwt_header, jwt_payload):
    jti = jwt_payload['jti'] # получаем ID токена

    # Если токен находится в черном списке - доступ запрещен
    if rds.get(f'jwt_blacklist:{jti}'):
        return True

    # Если токен не находится в белом списке - доступ запрещен
    if not rds.get(f'jwt_whitelist:{jti}'):
        return True

    return False # токена нет в черном списке, есть в белом - доступ разрешен


@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')

    if User.query.filter_by(username=username).first():
        return jsonify({'msg': 'Username already exists'}), 400

    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'msg': 'User created'}), 201


@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({'msg': 'Bad credentials'}), 401

    # Создаем JWT токен и заносим его в белый список
    access_token = create_access_token(identity=username)
    jti = get_jwt()['jti']
    expires_in = app.config['JWT_ACCESS_TOKEN_EXPIRES']
    rds.setex(f'jwt_whitelist:{jti}', expires_in, 'true')

    return jsonify(access_token=access_token)


@app.route('/logout', methods=['DELETE'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    # Логаут - один из кейсов отзыва токена - заносим токен в черный список
    rds.setex(f'jwt_blacklist:{jti}', app.config['JWT_ACCESS_TOKEN_EXPIRES'], 'true')
    return jsonify({'msg': 'Successfully logged out'})


# Пример доступа к контенту авторизованным пользователям
@app.route('/whoami', methods=['GET'])
@jwt_required()
def whoami():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


if __name__ == '__main__':
    app.run(debug=True)
