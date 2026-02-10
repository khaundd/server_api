from flask import Flask, jsonify, request, session
import mysql.connector
import hashlib
from utils import generate_verification_code, store_verification_code, send_verification_email
from verification import verify_email_code
from config import Config
import jwt
import datetime
import os
from functools import wraps
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Установите секретный ключ для сессий

cfg = Config.get_db_config()

# Хеширование пароля
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30) # Токен живет 30 дней
    }
    return jwt.encode(payload, os.getenv('SECRET_KEY'), algorithm='HS256') #че-то тут не работало с os.getenv

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # Обычно токен передается в заголовке 'Authorization' в формате 'Bearer <token>'
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1] # Берем вторую часть (сам токен)
            except IndexError:
                return jsonify({'message': 'Неверный формат заголовка Authorization!'}), 401

        if not token:
            return jsonify({'message': 'Токен отсутствует!'}), 401

        try:
            # Декодируем токен, используя тот же SECRET_KEY
            data = jwt.decode(token, os.getenv('SECRET_KEY'), algorithms=["HS256"])
            # Можно сразу получить ID текущего пользователя
            current_user_id = data['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Срок действия токена истек!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Неверный токен!'}), 401

        # Передаем id пользователя в функцию, если это необходимо
        return f(current_user_id, *args, **kwargs)

    return decorated

# Регистрация пользователя
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    height = data.get('height')
    bodyweight = data.get('bodyweight')
    age = data.get('age')

    if not username or not password or not email:
        return jsonify({'error': 'Не все данные указаны'}), 400

    hashed_password = hash_password(password)
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor()

    try:
        # Проверяем, существует ли уже пользователь с такой почтой в основной таблице
        check_query = "SELECT email FROM users WHERE email = %s"
        cursor.execute(check_query, (email,))
        if cursor.fetchone():
            return jsonify({'error': f'Эта почта ({email}) уже зарегистрирована'}), 400
        
        # Проверяем, нет ли уже временной записи
        check_temp_query = "SELECT email FROM temp_registrations WHERE email = %s"
        cursor.execute(check_temp_query, (email,))
        if cursor.fetchone():
            # Удаляем предыдущую временную запись
            cursor.execute("DELETE FROM temp_registrations WHERE email = %s", (email,))
            conn.commit()
        
        # Сохраняем данные пользователя во временной таблице
        verification_code = generate_verification_code()
        success = store_verification_code(email, username, hashed_password, height, bodyweight, age, verification_code)
        if not success:
            return jsonify({'error': 'Ошибка базы данных при регистрации'}), 500
            
        # Отправка кода подтверждения
        if send_verification_email(email, verification_code):
            return jsonify({'message': 'Регистрация почти завершена. Проверьте email для подтверждения.'}), 201
        else:
            return jsonify({'error': 'Не удалось отправить код подтверждения на email'}), 500
            
    except mysql.connector.Error as err:
        return jsonify({'error': str(err)}), 400
    finally:
        cursor.close()
        conn.close()

# Авторизация пользователя
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({'error': 'Email и пароль обязательны'}), 400

        hashed_password = hash_password(password)
        conn = mysql.connector.connect(**cfg)
        cursor = conn.cursor()

        try:
            cursor.callproc('authorization', [email, hashed_password])
            for result in cursor.stored_results():
                response = result.fetchone()
                if response and response[0] == 'Авторизация успешна':
                    # Получаем данные пользователя после успешной авторизации
                    cursor.execute("SELECT user_id FROM users WHERE email = %s", (email,))
                    user_id = int(cursor.fetchone()[0])
                    print("user_id:",user_id) # Выводим id пользователя в консоль для проверки
                    token = generate_token(user_id)
                    print("token - ", token)
                    response_dict = {
                        'message': 'Вход выполнен успешно',
                        'token': str(token),
                        'user_id': user_id
                    }
                    print("json response - ", response_dict)
                    return jsonify(response_dict), 200
                else:
                    return jsonify({'error': response[0] if response else 'Ошибка авторизации'}), 401
        except mysql.connector.Error as err:
            return jsonify({'error': str(err)}), 401
        finally:
            cursor.close()
            conn.close()
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Подтверждение email
@app.route('/verify-email', methods=['POST'])
def verify_email():
    """Эндпоинт для подтверждения email по коду."""
    data = request.get_json()
    email = data.get('email')
    code = data.get('code')

    if not email or not code:
        return jsonify({'error': 'Email и код обязательны'}), 400

    success, response, status_code = verify_email_code(email, code)
    return jsonify(response), status_code

# Выход из аккаунта
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Выход выполнен успешно'}), 200

# Получение данных из таблицы products
@app.route('/products', methods=['GET'])
@token_required
def get_products(current_user_id):
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    
    print(f"Пользователь {current_user_id} запрашивает список продуктов")

    cursor.execute("SELECT product_name, proteins, fats, carbs, calories FROM products")
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(rows)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)