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
import pytz

load_dotenv()

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Установите секретный ключ для сессий

cfg = Config.get_db_config()

# Хеширование пароля
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Конвертация времени из локального формата в UTC
def convert_to_utc(datetime_str):
    """Конвертирует строку datetime в UTC формат"""
    try:
        # Парсим локальное время
        local_dt = datetime.datetime.strptime(datetime_str, '%Y-%m-%d %H:%M:%S')
        # Определяем локальную временную зону
        local_tz = pytz.timezone('Asia/Novosibirsk')  # Или другая временная зона
        # Применяем локальную временную зону
        local_dt = local_tz.localize(local_dt)
        # Конвертируем в UTC
        utc_dt = local_dt.astimezone(pytz.UTC)
        return utc_dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception as e:
        print(f"Ошибка конвертации времени: {e}")
        return datetime_str

# Конвертация времени из UTC в локальный формат
def convert_from_utc(datetime_str):
    """Конвертирует строку UTC datetime в локальный формат"""
    try:
        # Парсим UTC время
        utc_dt = datetime.datetime.strptime(datetime_str, '%Y-%m-%d %H:%M:%S')
        # Применяем UTC временную зону
        utc_dt = pytz.UTC.localize(utc_dt)
        # Конвертируем в локальную временную зону
        local_tz = pytz.timezone('Asia/Novosibirsk')
        local_dt = utc_dt.astimezone(local_tz)
        return local_dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception as e:
        print(f"Ошибка конвертации времени из UTC: {e}")
        return datetime_str

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
    goal = data.get('goal', 'MAINTAIN')  # Значение по умолчанию
    gender = data.get('gender', 'MALE')  # Значение по умолчанию

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
        success = store_verification_code(email, username, hashed_password, height, bodyweight, age, goal, gender, verification_code)
        if not success:
            return jsonify({'error': 'Ошибка базы данных при регистрации'}), 500

        # Отправка кода подтверждения
        if send_verification_email(email, verification_code):
            return jsonify({'message': 'Регистрация почти завершена. Проверьте email для подтверждения.'}), 201
        else:
            return jsonify({'error': 'Не удалось отправить код подтверждения на email'}), 500

    except mysql.connector.Error as err:
        return jsonify({'error': str(err)}), 400 ##TODO аналогичная ошибка, как в логине, сделать понятной пользователю
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
                    print("user_id:",user_id)
                    token = generate_token(user_id)
                    print("token - ", token)
                    response_dict = {
                        'message': 'Вход выполнен успешно',
                        'token': str(token),
                        'userId': user_id
                    }
                    print("json response - ", response_dict)
                    return jsonify(response_dict), 200
                else:
                    return jsonify({'error': response[0] if response else 'Ошибка авторизации'}), 401
        except mysql.connector.Error as err:
            print(err)
            return jsonify({'error': str(err).split(':')[1].strip()}), 401
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
@token_required
def logout(current_user_id):
    session.clear()
    return jsonify({'message': f'Пользователь {current_user_id} успешно вышел'}), 200

# Получение данных из таблицы products
@app.route('/products', methods=['GET'])
@token_required
def get_products(current_user_id):
    limit = request.args.get('limit', default=None, type=int)
    only_mine = request.args.get('only_mine', default=False, type=bool)

    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)

    if only_mine:
        query = "SELECT * FROM products WHERE created_by = %s"
        cursor.execute(query, (current_user_id,))
    elif limit:
        query = "SELECT * FROM products LIMIT %s"
        cursor.execute(query, (limit,))
    else:
        query = "SELECT * FROM products"
        cursor.execute(query)

    rows = cursor.fetchall()
    
    # Форматируем строки в нужный формат
    formatted_rows = []
    for row in rows:
        formatted_row = {
            'product_id': row['product_id'],
            'product_name': row['product_name'],
            'proteins': float(row['proteins']),
            'fats': float(row['fats']),
            'carbs': float(row['carbs']),
            'calories': float(row['calories']),
            'barcode': row['barcode'] if row['barcode'] else None,
            'isDish': bool(row['is_dish']) if 'is_dish' in row else False,
            'createdBy': row['created_by']
        }
        formatted_rows.append(formatted_row)
    
    cursor.close()
    conn.close()
    return jsonify(formatted_rows)

# Проверка уникальности названия продукта
@app.route('/products/check-name', methods=['POST'])
@token_required
def check_product_name(current_user_id):
    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        
        if not name:
            return jsonify({'error': 'Название продукта обязательно'}), 400
        
        conn = mysql.connector.connect(**cfg)
        cursor = conn.cursor()
        
        # Проверяем, существует ли продукт с таким названием
        query = "SELECT COUNT(*) FROM products WHERE product_name = %s"
        cursor.execute(query, (name,))
        count = cursor.fetchone()[0]
        
        cursor.close()
        conn.close()
        
        return jsonify({'exists': count > 0}), 200
        
    except Exception as e:
        print(f"Ошибка при проверке названия продукта: {e}")
        return jsonify({'error': 'Ошибка сервера при проверке названия'}), 500

# Добавление нового продукта
@app.route('/products', methods=['POST'])
@token_required
def add_product(current_user_id):
    try:
        data = request.get_json()
        
        name = data.get('product_name', '').strip()
        protein = float(data.get('proteins', 0))
        fats = float(data.get('fats', 0))
        carbs = float(data.get('carbs', 0))
        barcode = data.get('barcode', '').strip()
        barcode = barcode if barcode else None
        
        # Валидация данных
        if not name:
            return jsonify({'error': 'Название продукта обязательно'}), 400
        
        if protein < 0 or fats < 0 or carbs < 0:
            return jsonify({'error': 'Значения БЖУ не могут быть отрицательными'}), 400
        
        # Проверка суммы БЖУ
        if protein + fats + carbs > 100:
            return jsonify({'error': 'Сумма БЖУ не может превышать 100 граммов'}), 400
        
        conn = mysql.connector.connect(**cfg)
        cursor = conn.cursor()
        
        try:
            # Проверяем уникальность названия
            check_query = "SELECT COUNT(*) FROM products WHERE product_name = %s"
            cursor.execute(check_query, (name,))
            if cursor.fetchone()[0] > 0:
                return jsonify({'error': 'Продукт с таким названием уже существует'}), 400
            
            # Вставляем новый продукт
            insert_query = """
                INSERT INTO products (product_name, proteins, fats, carbs, barcode, created_by)
                VALUES (%s, %s, %s, %s, %s, %s)
            """
            cursor.execute(insert_query, (name, protein, fats, carbs, barcode, current_user_id))
            product_id = cursor.lastrowid
            
            conn.commit()
            
            # Получаем созданный продукт для ответа
            cursor.execute("SELECT * FROM products WHERE product_id = %s", (product_id,))
            product = cursor.fetchone()
            print(product)
            
            # Формируем ответ в формате, ожидаемом клиентом
            product_response = {
                'product_id': product[0],
                'product_name': product[1],
                'proteins': float(product[2]),
                'fats': float(product[3]),
                'carbs': float(product[4]),
                'calories': float(product[5]),
                'barcode': product[6] if product[6] else None,
                'isDish': False,
                'createdBy': current_user_id
            }
            
            return jsonify({
                'success': True,
                'product': product_response,
                'message': 'Продукт успешно добавлен'
            }), 201
            
        except mysql.connector.Error as err:
            conn.rollback()
            print(f"Ошибка MySQL при добавлении продукта: {err}")
            return jsonify({'error': f'Ошибка базы данных: {str(err)}'}), 400
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        print(f"Ошибка при добавлении продукта: {e}")
        return jsonify({'error': 'Ошибка сервера при добавлении продукта'}), 500

@app.route('/meals/sync', methods=['POST'])
@token_required
def sync_meals(current_user_id):
    try:
        data = request.get_json()
        print(f"Полученные данные: {data}")  # Отладочный лог
        
        meals_data = data.get('meals', [])
        print(f"Meals data: {meals_data}")  # Отладочный лог

        if not meals_data:
            return jsonify({'success': True, 'message': 'Нет данных для синхронизации'}), 200

        conn = mysql.connector.connect(**cfg)
        cursor = conn.cursor()

        try:
            # Отключаем авто-коммит для транзакции
            conn.autocommit = False

            # Очищаем все записи о приемах пищи пользователя перед синхронизацией
            delete_query = "DELETE FROM meal WHERE user_id = %s"
            cursor.execute(delete_query, (current_user_id,))
            print(f"Удалено записей о приемах пищи для пользователя {current_user_id}")

            for meal in meals_data:
                print(f"Обработка приема пищи: {meal}")  # Отладочный лог
                
                # Конвертируем время в UTC
                utc_meal_time = convert_to_utc(meal['mealTime'])
                print(f"Время конвертировано в UTC: {meal['mealTime']} -> {utc_meal_time}")
                
                # 1. Вставка в таблицу meal (только meal_time в формате DATETIME)
                meal_query = """
                    INSERT INTO meal (user_id, name, meal_time) 
                    VALUES (%s, %s, %s)
                """
                cursor.execute(meal_query, (
                    current_user_id, 
                    meal['name'], 
                    utc_meal_time  # Используем сконвертированное время
                ))

                # Получаем ID только что созданного приема пищи
                new_meal_id = cursor.lastrowid
                print(f"Создан meal с ID: {new_meal_id}")  # Отладочный лог

                components = meal.get('components', [])
                print(f"Компоненты: {components}")  # Отладочный лог
                
                for component in components:
                    # 2. Вставка в таблицу meal_meal_component (связь)
                    link_query = "INSERT INTO meal_meal_component (meal_id) VALUES (%s)"
                    cursor.execute(link_query, (new_meal_id,))
                    new_link_id = cursor.lastrowid
                    print(f"Создана связь с ID: {new_link_id}")  # Отладочный лог

                    # 3. Вставка в таблицу meal_component (компоненты)
                    comp_query = """
                        INSERT INTO meal_component (meal_meal_component_id, product_id, weight) 
                        VALUES (%s, %s, %s)
                    """
                    cursor.execute(comp_query, (
                        new_link_id, 
                        component['productId'], 
                        component['weight']
                    ))
                    print(f"Добавлен компонент: productId={component['productId']}, weight={component['weight']}")  # Отладочный лог

            conn.commit()
            return jsonify({
                'success': True, 
                'message': f'Успешно синхронизировано {len(meals_data)} приемов пищи'
            }), 201

        except mysql.connector.Error as err:
            conn.rollback()
            print(f"Ошибка MySQL: {err}")  # Отладочный лог
            return jsonify({
                'success': False, 
                'message': f'Ошибка синхронизации: {str(err)}'
            }), 400
        except Exception as err:
            conn.rollback()
            print(f"Общая ошибка: {err}")  # Отладочный лог
            return jsonify({
                'success': False, 
                'message': f'Ошибка синхронизации: {str(err)}'
            }), 400
        finally:
            cursor.close()
            conn.close()
    except Exception as e:
        print(f"Ошибка при обработке запроса: {e}")  # Отладочный лог
        return jsonify({
            'success': False, 
            'message': f'Ошибка обработки запроса: {str(e)}'
        }), 400

@app.route('/meals/clear', methods=['DELETE'])
@token_required
def clear_meals(current_user_id):
    try:
        conn = mysql.connector.connect(**cfg)
        cursor = conn.cursor()

        try:
            # Удаляем все записи о приемах пищи пользователя
            delete_query = "DELETE FROM meal WHERE user_id = %s"
            cursor.execute(delete_query, (current_user_id,))
            
            deleted_count = cursor.rowcount
            conn.commit()
            
            print(f"Удалено {deleted_count} записей о приемах пищи для пользователя {current_user_id}")
            
            return jsonify({
                'success': True, 
                'message': f'Успешно удалено {deleted_count} записей о приемах пищи'
            }), 200

        except mysql.connector.Error as err:
            conn.rollback()
            print(f"Ошибка MySQL при очистке: {err}")
            return jsonify({
                'success': False, 
                'message': f'Ошибка очистки данных: {str(err)}'
            }), 400
        finally:
            cursor.close()
            conn.close()
    except Exception as e:
        print(f"Ошибка при обработке запроса очистки: {e}")
@app.route('/meals', methods=['GET'])
@token_required
def get_meals(current_user_id):
    try:
        print(f"Запрос приемов пищи для пользователя: {current_user_id}")  # Отладочный лог
        
        conn = mysql.connector.connect(**cfg)
        cursor = conn.cursor(dictionary=True)
        
        try:
            # Получаем все приемы пищи пользователя
            meals_query = """
                SELECT meal_id, name, meal_time 
                FROM meal 
                WHERE user_id = %s 
                ORDER BY meal_time
            """
            cursor.execute(meals_query, (current_user_id,))
            meals = cursor.fetchall()
            
            print(f"Найдено приемов пищи: {len(meals)}")  # Отладочный лог
            
            # Для каждого приема пищи получаем его компоненты и форматируем дату
            for meal in meals:
                # Форматируем дату в нужный формат, конвертируя из UTC в локальное время
                if meal['meal_time']:
                    utc_time_str = meal['meal_time'].strftime('%Y-%m-%d %H:%M:%S')
                    meal['mealTime'] = convert_from_utc(utc_time_str)
                    print(f"Время сконвертировано из UTC: {utc_time_str} -> {meal['mealTime']}")
                else:
                    meal['mealTime'] = ''
                
                components_query = """
                    SELECT mc.product_id, mc.weight
                    FROM meal_component mc
                    JOIN meal_meal_component mmc ON mc.meal_meal_component_id = mmc.id
                    WHERE mmc.meal_id = %s
                """
                cursor.execute(components_query, (meal['meal_id'],))
                components = cursor.fetchall()
                
                # Преобразуем компоненты в нужный формат
                meal['components'] = [
                    {
                        'productId': comp['product_id'],
                        'weight': comp['weight']
                    }
                    for comp in components
                ]
                
                # Удаляем meal_id и meal_time из ответа (они не нужны в клиентской части)
                del meal['meal_id']
                del meal['meal_time']
                
                print(f"Обработан прием пищи: {meal['name']}, время: {meal['mealTime']}")  # Отладочный лог
            
            return jsonify({
                'success': True,
                'meals': meals
            }), 200
        finally:
            cursor.close()
            conn.close()
    except Exception as e:
        print(f"Ошибка при обработке запроса: {e}")
        return jsonify({
            'success': False,
            'message': f'Ошибка обработки запроса: {str(e)}'
        }), 400

@app.route('/profile', methods=['GET'])
@token_required
def get_profile(current_user_id):
    try:
        print(f"=== GET /profile ЗАПРОС НАЧАТ ===")
        print(f"User ID: {current_user_id}")
        
        conn = mysql.connector.connect(**cfg)
        cursor = conn.cursor(dictionary=True)
        
        try:
            print(f"Выполнение SQL запроса для user_id: {current_user_id}")
            # Получаем данные профиля пользователя включая goal и gender
            profile_query = """
                SELECT height, bodyweight, age, goal, gender
                FROM users 
                WHERE user_id = %s
            """
            cursor.execute(profile_query, (current_user_id,))
            profile = cursor.fetchone()
            
            print(f"Результат SQL запроса: {profile}")
            
            if profile:
                # Форматируем ответ в соответствии с моделью ProfileData
                profile_data = {
                    'height': float(profile['height']),
                    'bodyweight': float(profile['bodyweight']),
                    'age': int(profile['age']),
                    'goal': profile.get('goal', 'MAINTAIN'),  # Используем данные из БД с запасным значением
                    'gender': profile.get('gender', 'MALE')  # Используем данные из БД с запасным значением
                }
                
                print(f"Сформированные данные профиля: {profile_data}")
                
                response_data = {
                    'success': True,
                    'profile': profile_data
                }
                
                print(f"Ответ сервера: {response_data}")
                print(f"=== GET /profile ЗАПРОС УСПЕШНО ЗАВЕРШЕН ===")
                
                return jsonify(response_data), 200
            else:
                print(f"Профиль не найден для user_id: {current_user_id}")
                error_response = {
                    'success': False,
                    'message': 'Данные профиля не найдены'
                }
                print(f"Ошибка: {error_response}")
                print(f"=== GET /profile ЗАПРОС ЗАВЕРШЕН С ОШИБКОЙ ===")
                return jsonify(error_response), 404
                
        except mysql.connector.Error as err:
            print(f"Ошибка MySQL при получении профиля: {err}")
            error_response = {
                'success': False,
                'message': f'Ошибка базы данных: {str(err)}'
            }
            print(f"Ошибка MySQL: {error_response}")
            print(f"=== GET /profile ЗАПРОС ЗАВЕРШЕН С ОШИБКОЙ MYSQL ===")
            return jsonify(error_response), 400
        finally:
            cursor.close()
            conn.close()
            print("Соединение с БД закрыто")
            
    except Exception as e:
        print(f"Критическая ошибка в get_profile: {e}")
        error_response = {
            'success': False,
            'message': f'Ошибка обработки запроса: {str(e)}'
        }
        print(f"Критическая ошибка: {error_response}")
        print(f"=== GET /profile ЗАПРОС ЗАВЕРШЕН С КРИТИЧЕСКОЙ ОШИБКОЙ ===")
        return jsonify(error_response), 500

@app.route('/profile', methods=['POST'])
@token_required
def update_profile(current_user_id):
    try:
        print(f"=== POST /profile ЗАПРОС НАЧАТ ===")
        print(f"User ID: {current_user_id}")
        
        data = request.get_json()
        print(f"Полученные данные: {data}")
        
        conn = mysql.connector.connect(**cfg)
        cursor = conn.cursor(dictionary=True)
        
        # Сначала получаем текущие значения из базы данных
        current_query = "SELECT height, bodyweight, age, goal, gender FROM users WHERE user_id = %s"
        cursor.execute(current_query, (current_user_id,))
        current_data = cursor.fetchone()
        
        if not current_data:
            return jsonify({
                'success': False,
                'message': 'Профиль не найден'
            }), 404
        
        # Извлекаем данные из запроса, используя текущие значения если не предоставлены
        height = data.get('height', current_data['height'])
        bodyweight = data.get('bodyweight', current_data['bodyweight'])
        age = data.get('age', current_data['age'])
        goal = data.get('goal', current_data['goal'])  # Используем текущее значение из БД
        gender = data.get('gender', current_data['gender'])  # Используем текущее значение из БД
        
        cursor.close()
        
        # Валидация данных
        if not height or not bodyweight or not age:
            return jsonify({
                'success': False,
                'message': 'Не все обязательные данные указаны (height, bodyweight, age)'
            }), 400
        
        conn = mysql.connector.connect(**cfg)
        cursor = conn.cursor()
        
        try:
            print(f"Обновление профиля для user_id: {current_user_id}")
            # Обновляем данные профиля пользователя включая goal и gender
            update_query = """
                UPDATE users 
                SET height = %s, bodyweight = %s, age = %s, goal = %s, gender = %s
                WHERE user_id = %s
            """
            cursor.execute(update_query, (height, bodyweight, age, goal, gender, current_user_id))
            
            if cursor.rowcount > 0:
                conn.commit()
                print(f"Профиль успешно обновлен для user_id: {current_user_id}")
                
                # Формируем обновленные данные для ответа
                profile_data = {
                    'height': float(height),
                    'bodyweight': float(bodyweight),
                    'age': int(age),
                    'goal': goal,
                    'gender': gender
                }
                
                response_data = {
                    'success': True,
                    'message': 'Данные профиля успешно обновлены',
                    'profile': profile_data
                }
                
                print(f"Ответ сервера: {response_data}")
                print(f"=== POST /profile ЗАПРОС УСПЕШНО ЗАВЕРШЕН ===")
                
                return jsonify(response_data), 200
            else:
                print(f"Профиль не найден для обновления: user_id: {current_user_id}")
                error_response = {
                    'success': False,
                    'message': 'Профиль не найден'
                }
                print(f"Ошибка: {error_response}")
                print(f"=== POST /profile ЗАПРОС ЗАВЕРШЕН С ОШИБКОЙ ===")
                return jsonify(error_response), 404
                
        except mysql.connector.Error as err:
            conn.rollback()
            print(f"Ошибка MySQL при обновлении профиля: {err}")
            error_response = {
                'success': False,
                'message': f'Ошибка базы данных: {str(err)}'
            }
            print(f"Ошибка MySQL: {error_response}")
            print(f"=== POST /profile ЗАПРОС ЗАВЕРШЕН С ОШИБКОЙ MYSQL ===")
            return jsonify(error_response), 400
        finally:
            cursor.close()
            conn.close()
            print("Соединение с БД закрыто")
            
    except Exception as e:
        print(f"Критическая ошибка в update_profile: {e}")
        error_response = {
            'success': False,
            'message': f'Ошибка обработки запроса: {str(e)}'
        }
        print(f"Критическая ошибка: {error_response}")
        print(f"=== POST /profile ЗАПРОС ЗАВЕРШЕН С КРИТИЧЕСКОЙ ОШИБКОЙ ===")
        return jsonify(error_response), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)