from flask import Flask, jsonify, request, session
import mysql.connector
import hashlib
from utils import generate_verification_code, store_verification_code, send_verification_email
from verification import verify_email_code
from config import Config

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Установите секретный ключ для сессий

cfg = Config.get_db_config()

# Хеширование пароля
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

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
                cursor.execute("SELECT user_id, username FROM users WHERE email = %s", (email,))
                user = cursor.fetchone()
                session['user_id'] = user[0]
                session['username'] = user[1]
                return jsonify({'message': 'Вход выполнен успешно'}), 200
            else:
                return jsonify({'error': response[0] if response else 'Ошибка авторизации'}), 401
    except mysql.connector.Error as err:
        return jsonify({'error': str(err)}), 401
    finally:
        cursor.close()
        conn.close()

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
def get_products():
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT product_name, proteins, fats, carbs, calories FROM products")
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(rows)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)