from flask import Flask, jsonify, request, session
import mysql.connector
import hashlib

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Установите секретный ключ для сессий

# Настройка подключения к MySQL
cfg = {
    'user': 'user',
    'password': 'qwerty123',
    'host': 'localhost',
    'database': 'project_course4',
    'raise_on_warnings': True
}

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
        cursor.callproc('registration', [username, hashed_password, email, height, bodyweight, age])
        conn.commit()
        return jsonify({'message': 'Пользователь успешно зарегистрирован'}), 201
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