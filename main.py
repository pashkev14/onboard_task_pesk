from datetime import timedelta
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, decode_token, jwt_required,
    get_jwt_identity, get_jwt, set_access_cookies, unset_jwt_cookies
)
from flask.logging import default_handler
from werkzeug.security import generate_password_hash, check_password_hash
import redis
import hashlib
import logging


ACCESS_EXPIRES = timedelta(minutes=15) # здесь указываем срок годности токена


app = Flask(__name__)

# Настройка SQLite базы с данными пользователей
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db' # путь к базе с пользователями
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # отключаем отслеживание операций изменения моделей
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    # хоть поле и называется password, здесь нужно хранить хэш
    # введенного пользователем пароля
    password = db.Column(db.String, nullable=False)
    # пусть для примера будут роли role1 и role2, по умолчанию role1
    role = db.Column(db.String, nullable=False, default='role1')


# Триггерим создание базы из конфига и модели при первом запуске приложения
# (все сохранится в папке instance, ее включим в .gitignore)
with app.app_context():
    db.create_all()

# Настройка JWT
app.config['JWT_TOKEN_LOCATION'] = ['cookies']  # храним в куках
app.config["JWT_COOKIE_SECURE"] = False  # передаем данные только по HTTPS
# для теста ставим False, потому что соединение по HTTP
app.config["JWT_COOKIE_HTTPONLY"] = True  # используем только HttpOnly куки
app.config['JWT_SECRET_KEY'] = 'very-secret-key' # мок ключ, в проде его использовать чревато
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = ACCESS_EXPIRES
jwt = JWTManager(app)

# Настройка Redis, для задания установим стандартное соединение (на localhost:6379)
rds = redis.Redis()


# Настройка фильтра логов
class JWTFilter(logging.Filter):
    def filter(self, record):
        if "token=" in record.getMessage():
            record.msg = record.msg.replace("token=", "token=***")
        return True


app.logger.addFilter(JWTFilter())


# Проверка на разрешение доступа по токену
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


# Здесь могло быть больше проверок на подозрительные активности,
# но оставим проверку несовпадения отпечатков
@app.before_request
@jwt_required(optional=True)
def check_device():
    if get_jwt_identity():
        # Берем "отпечаток" с устройства, пославшего запрос
        current_ip = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')
        current_device_id = hashlib.sha256(f'{current_ip}-{user_agent}'.encode()).hexdigest()
        token_device_id = get_jwt().get('device_id')
        if token_device_id != current_device_id:
            # Проверка провалена - принудительно отзываем токен
            jti = get_jwt()['jti']
            expires_in = app.config['JWT_ACCESS_TOKEN_EXPIRES']
            rds.setex(f'jwt_blacklist:{jti}', expires_in, 'true')

            response = jsonify({'msg': 'Suspicious activity detected!'})
            unset_jwt_cookies(response)
            return response, 401


@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')
    role = request.json.get('role', 'role1')

    if User.query.filter_by(username=username).first():
        return jsonify({'msg': 'Username already exists'}), 400

    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password=hashed_password, role=role)
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

    # Создаем fingerprint для токена
    user_agent = request.headers.get('User-Agent', '')
    ip = request.remote_addr
    device_id = hashlib.sha256(f'{ip}-{user_agent}'.encode()).hexdigest()

    # Создаем JWT токен и заносим его в белый список
    access_token = create_access_token(
        identity=username,
        additional_claims={
            'role': user.role,
            'device_id': device_id
        }
    )
    decoded_token = decode_token(access_token)
    jti = decoded_token['jti']
    expires_in = app.config['JWT_ACCESS_TOKEN_EXPIRES']
    rds.setex(f'jwt_whitelist:{jti}', expires_in, 'true')

    # Формируем ответ, добавляем токен в куки, возвращаем ответ
    response = jsonify({'msg': 'Successfully logged in'})
    set_access_cookies(response, access_token)
    return response


@app.route('/logout', methods=['DELETE'])
def logout():
    # Логаут - один из кейсов отзыва токена - заносим токен в черный список
    jti = get_jwt()['jti']
    expires_in = app.config['JWT_ACCESS_TOKEN_EXPIRES']
    rds.setex(f'jwt_blacklist:{jti}', expires_in, 'true')

    # Формируем ответ, удаляем куки с токеном, возвращаем ответ
    response = jsonify({'msg': 'Successfully logged out'})
    unset_jwt_cookies(response)
    return response


# Пример доступа к защищенному эндпоинту
@app.route('/whoami', methods=['GET'])
@jwt_required()
def whoami():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


# Пример общего для обеих ролей контента
@app.route('/common-content')
@jwt_required()
def common_content():
    return jsonify({'data': 'Общий контент для всех ролей'})


# Пример контента только для role1
@app.route('/role1-content')
@jwt_required()
def role1_content():
    if get_jwt().get('role') != 'role1':
        return jsonify({'msg': 'Forbidden'}), 403
    return jsonify({'data': 'Секретный контент role1'})


# Пример контента только для role2
@app.route('/role2-content')
@jwt_required()
def role2_content():
    if get_jwt().get('role') != 'role2':
        return jsonify({'msg': 'Forbidden'}), 403
    return jsonify({'data': 'Секретный контент role2'})


if __name__ == '__main__':
    app.run(debug=True)
