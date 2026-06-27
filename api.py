from flask import Flask, jsonify, request, session, send_from_directory
import mysql.connector
import hashlib
import hmac
import secrets
import logging
from utils import generate_verification_code, store_verification_code, send_verification_email
from verification import verify_email_code
from config import Config
import jwt
import datetime
import os
from functools import wraps
from dotenv import load_dotenv
import pytz
import productfinder as pf
import json
from advanced_search import advanced_search, init_symspell
from fcm_utils import send_fcm_notification, get_user_fcm_token

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
logger = logging.getLogger(__name__)

cfg = Config.get_db_config()

@app.route('/.well-known/assetlinks.json')
def assetlinks():
    return send_from_directory(
        os.path.join(os.path.dirname(__file__), '.well-known'),
        'assetlinks.json',
        mimetype='application/json'
    )

# Хеширование пароля
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Конвертация времени из локального формата в UTC
def convert_to_utc(datetime_str):
    try:
        local_dt = datetime.datetime.strptime(datetime_str, '%Y-%m-%d %H:%M:%S')
        # Определяем локальную временную зону
        local_tz = pytz.timezone('Asia/Novosibirsk')  
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
    return jwt.encode(payload, os.getenv('SECRET_KEY'), algorithm='HS256')

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
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

        return f(current_user_id, *args, **kwargs)

    return decorated


def get_user_role_by_id(cursor, user_id):
    cursor.execute("SELECT user_role FROM users WHERE user_id = %s", (user_id,))
    row = cursor.fetchone()
    if not row:
        return None

    if isinstance(row, dict):
        value = row.get('user_role')
    else:
        value = row[0]

    return int(value) if value is not None else 1


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    height = data.get('height')
    bodyweight = data.get('bodyweight')
    age = data.get('age')
    goal = data.get('goal', 'MAINTAIN')
    gender = data.get('gender', 'MALE')

    if not username or not password or not email:
        return jsonify({'error': 'Не все данные указаны'}), 400

    hashed_password = hash_password(password)
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor()

    try:
        # Проверяем существование email с помощью функции базы данных
        cursor.execute("SELECT is_email_exist(%s)", (email,))
        email_exists = cursor.fetchone()[0]
        if email_exists == 1:
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
        return jsonify({'error': str(err)}), 400
    finally:
        cursor.close()
        conn.close()

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
                    cursor.execute("SELECT user_id, user_role FROM users WHERE email = %s", (email,))
                    user_row = cursor.fetchone()
                    if not user_row:
                        return jsonify({'error': 'Не удалось получить данные пользователя'}), 500
                    user_id = int(user_row[0])
                    user_role = int(user_row[1]) if len(user_row) > 1 and user_row[1] is not None else 1
                    print("user_id:", user_id)
                    print("user_role:", user_role)
                    token = generate_token(user_id)
                    print("token - ", token)
                    response_dict = {
                        'message': 'Вход выполнен успешно',
                        'token': str(token),
                        'userId': user_id,
                        'userRole': user_role
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


@app.route('/admin/users', methods=['GET'])
@token_required
def get_admin_users(current_user_id):
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    try:
        current_role = get_user_role_by_id(cursor, current_user_id)
        if current_role != 3:
            return jsonify({'error': 'Недостаточно прав'}), 403

        cursor.execute("""
            SELECT user_id, username, email, user_role
            FROM users
            ORDER BY user_role DESC, username ASC
        """)
        users = cursor.fetchall()
        return jsonify({'users': users}), 200
    except mysql.connector.Error as err:
        return jsonify({'error': str(err)}), 400
    finally:
        cursor.close()
        conn.close()


@app.route('/admin/users/<int:user_id>/role', methods=['PUT'])
@token_required
def update_admin_user_role(current_user_id, user_id):
    data = request.get_json(silent=True) or {}
    new_role = int(data.get('user_role', 1))
    if new_role not in (1, 2, 3):
        return jsonify({'error': 'Некорректная роль'}), 400

    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor()
    try:
        current_role = get_user_role_by_id(cursor, current_user_id)
        if current_role != 3:
            return jsonify({'error': 'Недостаточно прав'}), 403

        cursor.execute("SELECT user_id FROM users WHERE user_id = %s", (user_id,))
        if not cursor.fetchone():
            return jsonify({'error': 'Пользователь не найден'}), 404

        cursor.execute("UPDATE users SET user_role = %s WHERE user_id = %s", (new_role, user_id))
        conn.commit()
        return jsonify({'message': 'Роль пользователя обновлена', 'userId': user_id, 'userRole': new_role}), 200
    except mysql.connector.Error as err:
        conn.rollback()
        return jsonify({'error': str(err)}), 400
    finally:
        cursor.close()
        conn.close()


@app.route('/admin/stats', methods=['GET'])
@token_required
def get_admin_stats(current_user_id):
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    try:
        current_role = get_user_role_by_id(cursor, current_user_id)
        if current_role < 2:
            return jsonify({'error': 'Недостаточно прав'}), 403
        cursor.execute("SELECT COUNT(*) as total FROM users")
        total_users = cursor.fetchone()['total']
        cursor.execute("SELECT COUNT(*) as total FROM users WHERE user_role = 2")
        active_trainers = cursor.fetchone()['total']
        return jsonify({'total_users': total_users, 'active_trainers': active_trainers}), 200
    except mysql.connector.Error as err:
        return jsonify({'error': str(err)}), 400
    finally:
        cursor.close()
        conn.close()


@app.route('/trainer/stats', methods=['GET'])
@token_required
def get_trainer_stats(current_user_id):
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    try:
        current_role = get_user_role_by_id(cursor, current_user_id)
        if current_role < 2:
            return jsonify({'error': 'Недостаточно прав'}), 403
        cursor.execute(
            "SELECT COUNT(*) as total FROM training_plan WHERE creator_id = %s",
            (current_user_id,)
        )
        plans_count = cursor.fetchone()['total']
        cursor.execute("SELECT COUNT(*) as total FROM users WHERE user_role = 1")
        clients_count = cursor.fetchone()['total']
        return jsonify({'plans_count': plans_count, 'clients_count': clients_count}), 200
    except mysql.connector.Error as err:
        return jsonify({'error': str(err)}), 400
    finally:
        cursor.close()
        conn.close()


@app.route('/verify-email', methods=['POST'])
def verify_email():
    data = request.get_json()
    email = data.get('email')
    code = data.get('code')

    if not email or not code:
        return jsonify({'error': 'Email и код обязательны'}), 400

    success, response, status_code = verify_email_code(email, code)
    return jsonify(response), status_code

@app.route('/logout', methods=['POST'])
@token_required  #вероятно нужно убрать требование токена для выхода
def logout(current_user_id):
    session.clear()
    return jsonify({'message': f'Пользователь {current_user_id} успешно вышел'}), 200

@app.route('/products', methods=['GET'])
@token_required
def get_products(current_user_id):
    limit = request.args.get('limit', default=None, type=int)
    offset = request.args.get('offset', default=0, type=int)
    only_mine = request.args.get('only_mine', default=False, type=bool)

    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)

    if only_mine:
        query = "SELECT * FROM products WHERE created_by = %s LIMIT %s OFFSET %s"
        cursor.execute(query, (current_user_id, limit or 1000, offset))
    elif limit:
        query = "SELECT * FROM products LIMIT %s OFFSET %s"
        cursor.execute(query, (limit, offset))
    else:
        query = "SELECT * FROM products LIMIT 1000 OFFSET %s"
        cursor.execute(query, (offset,))

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

@app.route('/products/search', methods=['GET'])
@token_required
def search_products(current_user_id):
    search_query = "SELECT * FROM products WHERE product_id = %s"
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify([]), 200

    try:
        conn = mysql.connector.connect(**cfg)
        cursor = conn.cursor(dictionary=True)
        finded_products = advanced_search(query)
        rows = []
        for t in finded_products:
            p_id = t[0]
            cursor.execute(search_query, (p_id,))
            result = cursor.fetchone()
            if result:
                rows.append(result)

        formatted_rows = []
        for row in rows:
            formatted_rows.append({
                'product_id': row['product_id'],
                'product_name': row['product_name'],
                'proteins': float(row['proteins']),
                'fats': float(row['fats']),
                'carbs': float(row['carbs']),
                'calories': float(row['calories']),
                'barcode': row['barcode'] if row['barcode'] else None,
                'isDish': bool(row['is_dish']) if 'is_dish' in row else False,
                'createdBy': row['created_by']
            })
        return jsonify(formatted_rows), 200
    except mysql.connector.Error as err:
        print(f"Ошибка MySQL при поиске продуктов: {err}")
        return jsonify({'error': str(err)}), 400
    finally:
        cursor.close()
        conn.close()

@app.route('/products/by-barcode', methods=['GET'])
@token_required
def get_product_by_barcode(current_user_id):
    barcode = request.args.get('barcode')
    print(f"Получен запрос на поиск продукта по штрихкоду: {barcode}")
    product = pf.get_product_by_barcode(barcode)
    print(f"Поиск продукта по штрихкоду завершён для: {barcode}")
    return product

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
        
        if not name:
            return jsonify({'error': 'Название продукта обязательно'}), 400
        
        if protein < 0 or fats < 0 or carbs < 0:
            return jsonify({'error': 'Значения БЖУ не могут быть отрицательными'}), 400
        
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
            
            product_id = 0
            cursor.callproc('add_simple_product', (
                name, protein, fats, carbs, barcode, current_user_id, product_id
            ))
            
            conn.commit()
            # Получаем ID созданного продукта
            for result in cursor.stored_results():
                product_id = result.fetchone()[0]
                break
            
            # Получаем созданный продукт для ответа
            cursor.execute("SELECT * FROM products WHERE product_id = %s", (product_id,))
            product = cursor.fetchone()
            
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
        print(f"Полученные данные: {data}")
        
        meals_data = data.get('meals', [])
        print(f"Meals data: {meals_data}")

        if not meals_data:
            return jsonify({'success': True, 'message': 'Нет данных для синхронизации'}), 200

        conn = mysql.connector.connect(**cfg)
        cursor = conn.cursor()

        try:
            conn.autocommit = False

            # Очищаем все записи о приемах пищи пользователя перед синхронизацией
            # НЕ трогаем записи, привязанные к плану питания через meal_meal_plan_day или from_plan_id
            delete_query = """
                DELETE FROM meal WHERE user_id = %s
                AND meal_id NOT IN (SELECT meal_id FROM meal_meal_plan_day)
                AND from_plan_id IS NULL
            """
            cursor.execute(delete_query, (current_user_id,))
            print(f"Удалено записей о приемах пищи для пользователя {current_user_id}")

            for meal in meals_data:
                print(f"Обработка приема пищи: {meal}")
                
                # Конвертируем время в UTC
                utc_meal_time = convert_to_utc(meal['mealTime'])
                print(f"Время конвертировано в UTC: {meal['mealTime']} -> {utc_meal_time}")
                
                meal_query = """
                    INSERT INTO meal (user_id, name, meal_time) 
                    VALUES (%s, %s, %s)
                """
                cursor.execute(meal_query, (
                    current_user_id, 
                    meal['name'], 
                    utc_meal_time 
                ))

                # Получаем ID только что созданного приема пищи
                new_meal_id = cursor.lastrowid
                print(f"Создан meal с ID: {new_meal_id}")

                components = meal.get('components', [])
                print(f"Компоненты: {components}")
                
                for component in components:
                    # Вставка в таблицу meal_meal_component
                    link_query = "INSERT INTO meal_meal_component (meal_id) VALUES (%s)"
                    cursor.execute(link_query, (new_meal_id,))
                    new_link_id = cursor.lastrowid
                    print(f"Создана связь с ID: {new_link_id}")

                    # Вставка в таблицу meal_component
                    comp_query = """
                        INSERT INTO meal_component (meal_meal_component_id, product_id, weight) 
                        VALUES (%s, %s, %s)
                    """
                    cursor.execute(comp_query, (
                        new_link_id, 
                        component['productId'], 
                        component['weight']
                    ))
                    print(f"Добавлен компонент: productId={component['productId']}, weight={component['weight']}")

            conn.commit()
            return jsonify({
                'success': True, 
                'message': f'Успешно синхронизировано {len(meals_data)} приемов пищи'
            }), 201

        except mysql.connector.Error as err:
            conn.rollback()
            print(f"Ошибка MySQL: {err}")
            return jsonify({
                'success': False, 
                'message': f'Ошибка синхронизации: {str(err)}'
            }), 400
        except Exception as err:
            conn.rollback()
            print(f"Общая ошибка: {err}")
            return jsonify({
                'success': False, 
                'message': f'Ошибка синхронизации: {str(err)}'
            }), 400
        finally:
            cursor.close()
            conn.close()
    except Exception as e:
        print(f"Ошибка при обработке запроса: {e}")
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
            # НЕ трогаем записи, привязанные к плану питания через meal_meal_plan_day или from_plan_id
            delete_query = """
                DELETE FROM meal WHERE user_id = %s
                AND meal_id NOT IN (SELECT meal_id FROM meal_meal_plan_day)
                AND from_plan_id IS NULL
            """
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
        print(f"Запрос приемов пищи для пользователя: {current_user_id}")
        
        conn = mysql.connector.connect(**cfg)
        cursor = conn.cursor(dictionary=True)
        
        try:
            meals_query = """
                SELECT meal_id, name, meal_time, from_plan_id
                FROM meal 
                WHERE user_id = %s
                AND meal_id NOT IN (SELECT meal_id FROM meal_meal_plan_day)
                ORDER BY meal_time
            """
            cursor.execute(meals_query, (current_user_id,))
            meals = cursor.fetchall()
            
            print(f"Найдено приемов пищи: {len(meals)}")
            
            # Для каждого приема пищи получаем его компоненты и форматируем дату
            for meal in meals:
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
                
                meal['components'] = [
                    {
                        'productId': comp['product_id'],
                        'weight': comp['weight']
                    }
                    for comp in components
                ]
                
                # Удаляем meal_id и meal_time из ответа (они не нужны в клиентской части)
                meal['from_plan_id'] = meal.get('from_plan_id')
                del meal['meal_id']
                del meal['meal_time']
                
                print(f"Обработан прием пищи: {meal['name']}, время: {meal['mealTime']}")
            
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
        print(f"GET /profile вызван")
        print(f"User ID: {current_user_id}")
        
        conn = mysql.connector.connect(**cfg)
        cursor = conn.cursor(dictionary=True)
        
        try:
            print(f"Выполнение SQL запроса для user_id: {current_user_id}")
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
                    'goal': profile.get('goal', 'MAINTAIN'),
                    'gender': profile.get('gender', 'MALE')
                }
                
                print(f"Сформированные данные профиля: {profile_data}")
                
                response_data = {
                    'success': True,
                    'profile': profile_data
                }
                
                print(f"Ответ сервера: {response_data}")
                print(f"GET /profile завершён")
                
                return jsonify(response_data), 200
            else:
                print(f"Профиль не найден для user_id: {current_user_id}")
                error_response = {
                    'success': False,
                    'message': 'Данные профиля не найдены'
                }
                print(f"Ошибка: {error_response}")
                print(f"GET /profile завершён с ошибкой")
                return jsonify(error_response), 404
                
        except mysql.connector.Error as err:
            print(f"Ошибка MySQL при получении профиля: {err}")
            error_response = {
                'success': False,
                'message': f'Ошибка базы данных: {str(err)}'
            }
            print(f"Ошибка MySQL: {error_response}")
            print(f"GET /profile завершён с ошибкой MySQL")
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
        print(f"GET /profile завершён с критическое ошибкой")
        return jsonify(error_response), 500

@app.route('/profile', methods=['POST'])
@token_required
def update_profile(current_user_id):
    try:
        print(f"POST /profile начат")
        print(f"User ID: {current_user_id}")
        
        data = request.get_json()
        print(f"Полученные данные: {data}")
        
        conn = mysql.connector.connect(**cfg)
        cursor = conn.cursor(dictionary=True)
        
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
        goal = data.get('goal', current_data['goal'])
        gender = data.get('gender', current_data['gender'])
        
        cursor.close()
        
        if not height or not bodyweight or not age:
            return jsonify({
                'success': False,
                'message': 'Не все обязательные данные указаны (height, bodyweight, age)'
            }), 400
        
        conn = mysql.connector.connect(**cfg)
        cursor = conn.cursor()
        
        try:
            print(f"Обновление профиля для user_id: {current_user_id}")
            # Обновляем данные профиля пользователя
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
                print(f"POST /profile успешно завершён")
                
                return jsonify(response_data), 200
            else:
                print(f"Профиль не найден для обновления: user_id: {current_user_id}")
                error_response = {
                    'success': False,
                    'message': 'Профиль не найден'
                }
                print(f"Ошибка: {error_response}")
                print(f"POST /profile завершён с ошибкой")
                return jsonify(error_response), 404
                
        except mysql.connector.Error as err:
            conn.rollback()
            print(f"Ошибка MySQL при обновлении профиля: {err}")
            error_response = {
                'success': False,
                'message': f'Ошибка базы данных: {str(err)}'
            }
            print(f"Ошибка MySQL: {error_response}")
            print(f"POST /profile завершён с ошибкой MySQL")
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
        print(f"POST /profile завершён с критической ошибкой")
        return jsonify(error_response), 500
    
@app.route('/recipes', methods=['GET'])
@token_required
def get_user_recipes(current_user_id):
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.callproc('get_all_recipes_for_user', (current_user_id,))
        print(f"Вызов процедуры get_all_recipes_for_user для user_id: {current_user_id}")
        recipes = []
        for result in cursor.stored_results():
            rows = result.fetchall()
            for row in rows:
                if row.get('dish_composition'):
                    try:
                        row['dish_composition'] = json.loads(row['dish_composition'])
                    except (ValueError, TypeError) as e:
                        print(f"Ошибка при парсинге dish_composition: {e}")
                        row['dish_composition'] = []
                recipes.append(row)
        print(f"Получено рецептов: {len(recipes)} для user_id: {current_user_id}")

        # Подтягиваем is_public и recipe_link из таблицы recipes
        if recipes:
            recipe_ids = [r['product_id'] for r in recipes if 'product_id' in r]
            if recipe_ids:
                conn2 = mysql.connector.connect(**cfg)
                cursor2 = conn2.cursor(dictionary=True)
                try:
                    fmt = ','.join(['%s'] * len(recipe_ids))
                    cursor2.execute(
                        f"SELECT recipe_id, is_public, recipe_link FROM recipes WHERE recipe_id IN ({fmt})",
                        recipe_ids
                    )
                    vis_rows = cursor2.fetchall()
                    vis_map = {}
                    for vrow in vis_rows:
                        raw = vrow['is_public']
                        # BIT(1) приходит как bytes, int или bool
                        if isinstance(raw, (bytes, bytearray)):
                            is_pub = 1 if raw and raw != b'\x00' else 0
                        else:
                            is_pub = 1 if raw else 0
                        vis_map[vrow['recipe_id']] = {
                            'is_public': is_pub,
                            'recipe_link': vrow['recipe_link']
                        }
                    for recipe in recipes:
                        pid = recipe.get('product_id')
                        vis = vis_map.get(pid, {})
                        recipe['is_public'] = vis.get('is_public', 0)
                        recipe['recipe_link'] = vis.get('recipe_link', None)
                finally:
                    cursor2.close()
                    conn2.close()

    except mysql.connector.Error as err:
        print(f"Ошибка MySQL при получении рецептов: {err}")
        return jsonify({'error': f'Ошибка базы данных: {str(err)}'}), 400
    finally:
        cursor.close()
        conn.close()
    return jsonify(recipes), 200

@app.route('/recipes', methods=['POST'])
@token_required
def add_recipe(current_user_id):
    try:
        data = request.get_json()
        dish_name = data.get('dish_name')
        ingredients = data.get('ingredients')
        after_cooking_weight = data.get('after_cooking_weight')
        ingredients_json = json.dumps(ingredients)
        print(f"Название блюда: {dish_name}\nСписок ингредиентов: {ingredients_json}")

        try:
            conn = mysql.connector.connect(**cfg)
            cursor = conn.cursor()
            cursor.callproc('add_dish', (dish_name, ingredients_json, current_user_id, after_cooking_weight))
            conn.commit()
            return jsonify({"result":"Рецепт успешно сохранён"}), 200
        except mysql.connector.Error as err:
            conn.rollback()
            print(f"Ошибка MySQL при добавлении рецепта: {err}")
            return jsonify({'error': f'Ошибка базы данных: {str(err)}'}), 400
        finally:
            cursor.close()
            conn.close()
    except Exception as e:
        print(f"Ошибка при добавлении рецепта: {e}")
        return jsonify({'error': str(e)}), 402

@app.route('/recipes/<int:product_id>', methods=['POST'])
@token_required
def update_recipe(current_user_id, product_id):
    try:
        data = request.get_json()
        dish_name = data.get('dish_name')
        ingredients = data.get('ingredients')
        after_cooking_weight = data.get('after_cooking_weight')
        ingredients_json = json.dumps(ingredients)
        print(f"Обновление рецепта product_id={product_id}: {dish_name}, ингредиенты: {ingredients_json}")

        try:
            conn = mysql.connector.connect(**cfg)
            cursor = conn.cursor()
            cursor.callproc('update_dish', (product_id, dish_name, ingredients_json, current_user_id, after_cooking_weight))
            conn.commit()
            return jsonify({"result": "Рецепт успешно обновлён"}), 200
        except mysql.connector.Error as err:
            conn.rollback()
            print(f"Ошибка MySQL при обновлении рецепта: {err}")
            return jsonify({'error': f'Ошибка базы данных: {str(err)}'}), 400
        finally:
            cursor.close()
            conn.close()
    except Exception as e:
        print(f"Ошибка при обновлении рецепта: {e}")
        return jsonify({'error': str(e)}), 402

@app.route('/recipes/<int:product_id>/visibility', methods=['POST'])
@token_required
def set_recipe_visibility(current_user_id, product_id):
    """Переключает is_public для рецепта. При выключении обнуляет recipe_link."""
    try:
        data = request.get_json()
        is_public = bool(data.get('is_public', False))

        conn = mysql.connector.connect(**cfg)
        cursor = conn.cursor()
        try:
            # Проверяем, что рецепт принадлежит пользователю
            cursor.execute(
                "SELECT r.id FROM recipes r "
                "JOIN products p ON r.recipe_id = p.product_id "
                "WHERE r.recipe_id = %s AND p.created_by = %s",
                (product_id, current_user_id)
            )
            if not cursor.fetchone():
                return jsonify({'error': 'Рецепт не найден или нет доступа'}), 404

            if is_public:
                # Генерируем токен, если его ещё нет
                cursor.execute(
                    "SELECT recipe_link FROM recipes WHERE recipe_id = %s", (product_id,)
                )
                row = cursor.fetchone()
                existing_link = row[0] if row else None

                if existing_link:
                    link = existing_link
                else:
                    token = secrets.token_urlsafe(16)
                    link = f"https://loftily-adequate-urchin.cloudpub.ru/recipes/shared/{token}"
                    cursor.execute(
                        "UPDATE recipes SET is_public = 1, recipe_link = %s WHERE recipe_id = %s",
                        (link, product_id)
                    )
                    conn.commit()
                    return jsonify({'success': True, 'is_public': 1, 'link': link}), 200

                cursor.execute(
                    "UPDATE recipes SET is_public = 1 WHERE recipe_id = %s", (product_id,)
                )
            else:
                cursor.execute(
                    "UPDATE recipes SET is_public = 0, recipe_link = NULL WHERE recipe_id = %s",
                    (product_id,)
                )
                link = None

            conn.commit()
            return jsonify({'success': True, 'is_public': 1 if is_public else 0, 'link': link}), 200

        except mysql.connector.Error as err:
            conn.rollback()
            return jsonify({'error': str(err)}), 400
        finally:
            cursor.close()
            conn.close()
    except Exception as e:
        print(f"Ошибка в set_recipe_visibility: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/recipes/<int:product_id>/share', methods=['POST'])
@token_required
def generate_recipe_link(current_user_id, product_id):
    """Генерирует (или возвращает существующую) публичную ссылку на рецепт."""
    try:
        conn = mysql.connector.connect(**cfg)
        cursor = conn.cursor()
        try:
            # Проверяем владельца
            cursor.execute(
                "SELECT r.recipe_link, r.is_public FROM recipes r "
                "JOIN products p ON r.recipe_id = p.product_id "
                "WHERE r.recipe_id = %s AND p.created_by = %s",
                (product_id, current_user_id)
            )
            row = cursor.fetchone()
            if not row:
                return jsonify({'error': 'Рецепт не найден или нет доступа'}), 404

            existing_link, is_public = row[0], bool(row[1])

            if existing_link and is_public:
                return jsonify({'link': existing_link}), 200

            # Генерируем новый токен
            token = secrets.token_urlsafe(16)
            link = f"https://loftily-adequate-urchin.cloudpub.ru/recipes/shared/{token}"
            cursor.execute(
                "UPDATE recipes SET is_public = 1, recipe_link = %s WHERE recipe_id = %s",
                (link, product_id)
            )
            conn.commit()
            return jsonify({'link': link}), 200

        except mysql.connector.Error as err:
            conn.rollback()
            print(f"Ошибка mysql.connector: {str(err)}")
            return jsonify({'error': str(err)}), 400
        finally:
            cursor.close()
            conn.close()
    except Exception as e:
        print(f"Ошибка в generate_recipe_link: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/recipes/shared/<token>', methods=['GET'])
def get_shared_recipe(token):
    """
    Публичный эндпоинт.
    - Браузеры/мессенджеры (нет заголовка Accept: application/json) получают HTML с OG-тегами.
    - Приложение (Accept: application/json) получает JSON с данными рецепта.
    """
    try:
        link = f"https://loftily-adequate-urchin.cloudpub.ru/recipes/shared/{token}"

        conn = mysql.connector.connect(**cfg)
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute(
                "SELECT r.recipe_id FROM recipes r "
                "WHERE r.recipe_link = %s AND r.is_public = b'1'",
                (link,)
            )
            row = cursor.fetchone()
            if not row:
                # Для браузера — человекочитаемая страница
                if 'application/json' not in request.headers.get('Accept', ''):
                    return "<html><body><h2>Рецепт не найден или доступ закрыт</h2></body></html>", 404
                return jsonify({'error': 'Рецепт не найден или доступ закрыт'}), 404

            recipe_id = row['recipe_id']

            cursor.execute(
                "SELECT product_name FROM products WHERE product_id = %s",
                (recipe_id,)
            )
            product_row = cursor.fetchone()
            if not product_row:
                return jsonify({'error': 'Рецепт не найден'}), 404

            dish_name = product_row['product_name']

            # Браузер / мессенджер — отдаём HTML с Open Graph тегами
            if 'application/json' not in request.headers.get('Accept', ''):
                html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta property="og:title" content="{dish_name}" />
  <meta property="og:description" content="Рецепт в приложении" />
  <meta property="og:url" content="{link}" />
  <title>{dish_name}</title>
</head>
<body>
  <p>Откройте ссылку в приложении, чтобы посмотреть рецепт.</p>
</body>
</html>"""
                return html, 200, {'Content-Type': 'text/html; charset=utf-8'}

            # Приложение — отдаём JSON
            cursor.execute(
                """
                SELECT p.product_id, p.product_name, p.proteins, p.fats, p.carbs, p.calories,
                       dc.product_weight AS weight
                FROM dish_composition dc
                JOIN products p ON dc.product_id = p.product_id
                WHERE dc.dish_id = %s
                """,
                (recipe_id,)
            )
            ingredients = cursor.fetchall()

            composition = [
                {
                    'product_id': ing['product_id'],
                    'product_name': ing['product_name'],
                    'proteins': float(ing['proteins']),
                    'fats': float(ing['fats']),
                    'carbs': float(ing['carbs']),
                    'calories': float(ing['calories']),
                    'weight': ing['weight']
                }
                for ing in ingredients
            ]

            return jsonify({
                'product_id': recipe_id,
                'product_name': dish_name,
                'dish_composition': composition,
                'is_public': 1,
                'recipe_link': link
            }), 200

        except mysql.connector.Error as err:
            return jsonify({'error': str(err)}), 400
        finally:
            cursor.close()
            conn.close()
    except Exception as e:
        print(f"Ошибка в get_shared_recipe: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/password-reset/request', methods=['POST'])
def password_reset_request():
    data = request.get_json()
    email = data.get('email', '').strip()
    if not email:
        return jsonify({'error': 'Email обязателен'}), 400

    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT user_id FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        if not user:
            return jsonify({'error': 'Пользователь с таким email не найден'}), 404

        code = generate_verification_code()
        cursor.execute("DELETE FROM password_reset_codes WHERE email = %s", (email,))
        cursor.execute(
            "INSERT INTO password_reset_codes (email, code, created_at) VALUES (%s, %s, NOW())",
            (email, code)
        )
        conn.commit()

        if send_verification_email(email, code):
            return jsonify({'message': 'Код отправлен на email'}), 200
        else:
            return jsonify({'error': 'Не удалось отправить код'}), 500
    except mysql.connector.Error as err:
        conn.rollback()
        return jsonify({'error': str(err)}), 400
    finally:
        cursor.close()
        conn.close()


@app.route('/password-reset/verify', methods=['POST'])
def password_reset_verify():
    data = request.get_json()
    email = data.get('email', '').strip()
    code = data.get('code', '').strip()
    if not email or not code:
        return jsonify({'error': 'Email и код обязательны'}), 400

    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT code FROM password_reset_codes WHERE email = %s AND created_at > NOW() - INTERVAL 15 MINUTE",
            (email,)
        )
        row = cursor.fetchone()
        if not row or row[0] != code:
            return jsonify({'error': 'Неверный или устаревший код'}), 400
        return jsonify({'message': 'Код верный'}), 200
    except mysql.connector.Error as err:
        return jsonify({'error': str(err)}), 400
    finally:
        cursor.close()
        conn.close()


@app.route('/password-reset/confirm', methods=['POST'])
def password_reset_confirm():
    data = request.get_json()
    email = data.get('email', '').strip()
    code = data.get('code', '').strip()
    new_password = data.get('new_password', '').strip()
    if not email or not code or not new_password:
        return jsonify({'error': 'Email, код и новый пароль обязательны'}), 400

    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT code FROM password_reset_codes WHERE email = %s AND created_at > NOW() - INTERVAL 15 MINUTE",
            (email,)
        )
        row = cursor.fetchone()
        if not row or row[0] != code:
            return jsonify({'error': 'Неверный или устаревший код'}), 400

        hashed = hash_password(new_password)
        cursor.execute("UPDATE users SET hashed_password = %s WHERE email = %s", (hashed, email))
        cursor.execute("DELETE FROM password_reset_codes WHERE email = %s", (email,))
        conn.commit()

        cursor.execute("SELECT user_id FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        if user:
            token = generate_token(user[0])
            return jsonify({'message': 'Пароль изменён', 'token': str(token), 'userId': user[0]}), 200
        return jsonify({'message': 'Пароль изменён'}), 200
    except mysql.connector.Error as err:
        conn.rollback()
        return jsonify({'error': str(err)}), 400
    finally:
        cursor.close()
        conn.close()


# ─────────────────────────────────────────────
#  MEAL PLANS
# ─────────────────────────────────────────────

def _load_plan_days(cursor, plan_id):
    """Вспомогательная функция: загружает дни плана с приёмами пищи и компонентами."""
    cursor.execute("""
        SELECT mpd.meal_plan_day_id, mpd.day_number, mpd.day_of_week, mpd.notes
        FROM meal_plan_day mpd
        WHERE mpd.plan_id = %s
        ORDER BY mpd.day_number
    """, (plan_id,))
    days = cursor.fetchall()
    for day in days:
        cursor.execute("""
            SELECT m.meal_id, m.name, m.meal_time
            FROM meal_meal_plan_day mmpd
            JOIN meal m ON mmpd.meal_id = m.meal_id
            WHERE mmpd.meal_plan_day_id = %s
        """, (day['meal_plan_day_id'],))
        meals = cursor.fetchall()
        for meal in meals:
            if meal['meal_time']:
                meal['meal_time'] = meal['meal_time'].strftime('%H:%M')
            cursor.execute("""
                SELECT mc.product_id, mc.weight
                FROM meal_component mc
                JOIN meal_meal_component mmc ON mc.meal_meal_component_id = mmc.id
                WHERE mmc.meal_id = %s
            """, (meal['meal_id'],))
            meal['components'] = [
                {'productId': c['product_id'], 'weight': c['weight']}
                for c in cursor.fetchall()
            ]
        day['meals'] = meals
    return days


@app.route('/meal-plans', methods=['GET'])
@token_required
def get_meal_plans(current_user_id):
    """Возвращает все планы питания пользователя (только свои)."""
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT mp.plan_id, mp.name, mp.description, mp.is_public, mp.created_by,
                   mp.target_calories, mp.protein_pct, mp.fats_pct, mp.carbs_pct,
                   NULL AS assigned_by_trainer_id
            FROM meal_plan mp
            WHERE mp.created_by = %s

            UNION ALL

            -- Планы питания, назначенные тренером
            SELECT mp.plan_id, mp.name, mp.description, mp.is_public, mp.created_by,
                   mp.target_calories, mp.protein_pct, mp.fats_pct, mp.carbs_pct,
                   ump.assigned_by_trainer_id
            FROM user_meal_plan ump
            JOIN meal_plan_user_meal_plan mpump ON mpump.user_meal_plan_id = ump.id
            JOIN meal_plan mp ON mp.plan_id = mpump.meal_plan_id
            WHERE ump.user_id = %s
              AND ump.ended_at IS NULL
              AND ump.assigned_by_trainer_id IS NOT NULL
              AND mp.created_by != %s

            ORDER BY plan_id DESC
        """, (current_user_id, current_user_id, current_user_id))
        plans = cursor.fetchall()
        for p in plans:
            raw = p['is_public']
            p['is_public'] = 1 if (isinstance(raw, (bytes, bytearray)) and raw != b'\x00') or (not isinstance(raw, (bytes, bytearray)) and raw) else 0
            p['assigned_by_trainer_id'] = p.get('assigned_by_trainer_id')
            p['days'] = _load_plan_days(cursor, p['plan_id'])
        return jsonify({'success': True, 'plans': plans}), 200
    except mysql.connector.Error as err:
        print(f"Ошибка MySQL в GET meal-plans: {err}")
        return jsonify({'success': False, 'message': str(err)}), 400
    finally:
        cursor.close()
        conn.close()


@app.route('/meal-plans', methods=['POST'])
@token_required
def create_meal_plan(current_user_id):
    """Создаёт новый план питания с днями и приёмами пищи."""
    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        description = data.get('description', '').strip()
        is_public = bool(data.get('is_public', False))
        days = data.get('days', [])
        target_calories = float(data.get('target_calories', 2000))
        protein_pct = float(data.get('protein_pct', 30))
        fats_pct = float(data.get('fats_pct', 30))
        carbs_pct = float(data.get('carbs_pct', 40))

        if not name:
            return jsonify({'success': False, 'message': 'Название плана обязательно'}), 400

        conn = mysql.connector.connect(**cfg)
        cursor = conn.cursor()
        conn.autocommit = False
        try:
            cursor.execute(
                """INSERT INTO meal_plan (name, description, is_public, created_by,
                   target_calories, protein_pct, fats_pct, carbs_pct)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                (name, description, 1 if is_public else 0, current_user_id,
                 target_calories, protein_pct, fats_pct, carbs_pct)
            )
            plan_id = cursor.lastrowid

            for day in days:
                cursor.execute(
                    "INSERT INTO meal_plan_day (plan_id, day_number, day_of_week, notes) VALUES (%s, %s, %s, %s)",
                    (plan_id, day['day_number'], day.get('day_of_week'), day.get('notes') or None)
                )
                day_id = cursor.lastrowid

                for meal in day.get('meals', []):
                    meal_time = meal.get('meal_time') or '12:00'
                    # Ensure HH:MM format (pad hour if needed)
                    if ':' not in meal_time:
                        meal_time = '12:00'
                    cursor.execute(
                        "INSERT INTO meal (user_id, name, meal_time) VALUES (%s, %s, %s)",
                        (current_user_id, meal['name'], f"2000-01-01 {meal_time}:00")
                    )
                    meal_id = cursor.lastrowid

                    for comp in meal.get('components', []):
                        cursor.execute("INSERT INTO meal_meal_component (meal_id) VALUES (%s)", (meal_id,))
                        link_id = cursor.lastrowid
                        cursor.execute(
                            "INSERT INTO meal_component (meal_meal_component_id, product_id, weight) VALUES (%s, %s, %s)",
                            (link_id, comp['productId'], comp['weight'])
                        )

                    cursor.execute(
                        "INSERT INTO meal_meal_plan_day (meal_id, meal_plan_day_id) VALUES (%s, %s)",
                        (meal_id, day_id)
                    )

            conn.commit()
            return jsonify({'success': True, 'plan_id': plan_id, 'message': 'План питания создан'}), 201
        except mysql.connector.Error as err:
            conn.rollback()
            print(f"Ошибка MySQL в POST meal-plans: {err}")
            return jsonify({'success': False, 'message': str(err)}), 400
        finally:
            cursor.close()
            conn.close()
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/meal-plans/<int:plan_id>', methods=['PUT'])
@token_required
def update_meal_plan(current_user_id, plan_id):
    """Обновляет план питания (пересоздаёт дни и приёмы пищи)."""
    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        description = data.get('description', '').strip()
        is_public = bool(data.get('is_public', False))
        days = data.get('days', [])
        target_calories = float(data.get('target_calories', 2000))
        protein_pct = float(data.get('protein_pct', 30))
        fats_pct = float(data.get('fats_pct', 30))
        carbs_pct = float(data.get('carbs_pct', 40))

        if not name:
            return jsonify({'success': False, 'message': 'Название плана обязательно'}), 400

        conn = mysql.connector.connect(**cfg)
        cursor = conn.cursor()
        conn.autocommit = False
        try:
            # Проверяем владельца
            cursor.execute("SELECT created_by FROM meal_plan WHERE plan_id = %s", (plan_id,))
            row = cursor.fetchone()
            if not row or row[0] != current_user_id:
                return jsonify({'success': False, 'message': 'План не найден или нет доступа'}), 404

            cursor.execute(
                """UPDATE meal_plan SET name=%s, description=%s, is_public=%s,
                   target_calories=%s, protein_pct=%s, fats_pct=%s, carbs_pct=%s
                   WHERE plan_id=%s""",
                (name, description, 1 if is_public else 0,
                 target_calories, protein_pct, fats_pct, carbs_pct, plan_id)
            )

            # Удаляем старые дни
            cursor.execute("SELECT meal_plan_day_id FROM meal_plan_day WHERE plan_id = %s", (plan_id,))
            old_day_ids = [r[0] for r in cursor.fetchall()]
            if old_day_ids:
                fmt = ','.join(['%s'] * len(old_day_ids))
                # Собираем meal_id, привязанные к этим дням
                cursor.execute(
                    f"SELECT meal_id FROM meal_meal_plan_day WHERE meal_plan_day_id IN ({fmt})",
                    tuple(old_day_ids)
                )
                meal_ids = [r[0] for r in cursor.fetchall()]
                # Сначала удаляем связи (FK на meal), потом сами meal, потом дни
                cursor.execute(
                    f"DELETE FROM meal_meal_plan_day WHERE meal_plan_day_id IN ({fmt})",
                    tuple(old_day_ids)
                )
                if meal_ids:
                    mfmt = ','.join(['%s'] * len(meal_ids))
                    cursor.execute(f"DELETE FROM meal WHERE meal_id IN ({mfmt})", tuple(meal_ids))
                cursor.execute("DELETE FROM meal_plan_day WHERE plan_id = %s", (plan_id,))

            # Вставляем новые дни
            for day in days:
                cursor.execute(
                    "INSERT INTO meal_plan_day (plan_id, day_number, day_of_week, notes) VALUES (%s, %s, %s, %s)",
                    (plan_id, day['day_number'], day.get('day_of_week'), day.get('notes') or None)
                )
                day_id = cursor.lastrowid

                for meal in day.get('meals', []):
                    meal_time = meal.get('meal_time') or '12:00'
                    # Ensure HH:MM format (pad hour if needed)
                    if ':' not in meal_time:
                        meal_time = '12:00'
                    cursor.execute(
                        "INSERT INTO meal (user_id, name, meal_time) VALUES (%s, %s, %s)",
                        (current_user_id, meal['name'], f"2000-01-01 {meal_time}:00")
                    )
                    meal_id = cursor.lastrowid

                    for comp in meal.get('components', []):
                        cursor.execute("INSERT INTO meal_meal_component (meal_id) VALUES (%s)", (meal_id,))
                        link_id = cursor.lastrowid
                        cursor.execute(
                            "INSERT INTO meal_component (meal_meal_component_id, product_id, weight) VALUES (%s, %s, %s)",
                            (link_id, comp['productId'], comp['weight'])
                        )

                    cursor.execute(
                        "INSERT INTO meal_meal_plan_day (meal_id, meal_plan_day_id) VALUES (%s, %s)",
                        (meal_id, day_id)
                    )

            conn.commit()
            return jsonify({'success': True, 'message': 'План питания обновлён'}), 200
        except mysql.connector.Error as err:
            conn.rollback()
            print(f"Ошибка в MySQL PUT meal-plans: {err}")
            return jsonify({'success': False, 'message': str(err)}), 400
        finally:
            cursor.close()
            conn.close()
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/meal-plans/<int:plan_id>', methods=['DELETE'])
@token_required
def delete_meal_plan(current_user_id, plan_id):
    """Удаляет план питания."""
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor()
    conn.autocommit = False
    try:
        cursor.execute("SELECT created_by FROM meal_plan WHERE plan_id = %s", (plan_id,))
        row = cursor.fetchone()
        if not row or row[0] != current_user_id:
            return jsonify({'success': False, 'message': 'План не найден или нет доступа'}), 404

        # Удаляем приёмы пищи плана
        cursor.execute("SELECT meal_plan_day_id FROM meal_plan_day WHERE plan_id = %s", (plan_id,))
        day_ids = [r[0] for r in cursor.fetchall()]
        if day_ids:
            fmt = ','.join(['%s'] * len(day_ids))
            cursor.execute(
                f"SELECT meal_id FROM meal_meal_plan_day WHERE meal_plan_day_id IN ({fmt})",
                tuple(day_ids)
            )
            meal_ids = [r[0] for r in cursor.fetchall()]
            cursor.execute(
                f"DELETE FROM meal_meal_plan_day WHERE meal_plan_day_id IN ({fmt})",
                tuple(day_ids)
            )
            if meal_ids:
                mfmt = ','.join(['%s'] * len(meal_ids))
                cursor.execute(f"DELETE FROM meal WHERE meal_id IN ({mfmt})", tuple(meal_ids))

        cursor.execute("DELETE FROM meal_plan WHERE plan_id = %s", (plan_id,))
        conn.commit()
        return jsonify({'success': True, 'message': 'План питания удалён'}), 200
    except mysql.connector.Error as err:
        conn.rollback()
        print(f"Ошибка MySQL в DELETE meal-plans: {err}")
        return jsonify({'success': False, 'message': str(err)}), 400
    finally:
        cursor.close()
        conn.close()



# ─────────────────────────────────────────────
#  MEAL PLAN SHARING / ASSIGNMENT
# ─────────────────────────────────────────────

@app.route('/meal-plans/public', methods=['GET'])
@token_required
def get_public_meal_plans(current_user_id):
    """Возвращает публичные планы питания других пользователей."""
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT plan_id, name, description, is_public, created_by,
                   target_calories, protein_pct, fats_pct, carbs_pct
            FROM meal_plan
            WHERE is_public = 1 AND created_by != %s
            ORDER BY plan_id DESC
        """, (current_user_id,))
        plans = cursor.fetchall()
        for p in plans:
            p['is_public'] = 1
            p['day_count'] = 0
            cursor.execute("SELECT COUNT(*) as cnt FROM meal_plan_day WHERE plan_id = %s", (p['plan_id'],))
            p['day_count'] = cursor.fetchone()['cnt']
            p['days'] = _load_plan_days(cursor, p['plan_id'])
        return jsonify({'success': True, 'plans': plans}), 200
    except mysql.connector.Error as err:
        return jsonify({'success': False, 'message': str(err)}), 400
    finally:
        cursor.close()
        conn.close()


@app.route('/meal-plans/<int:plan_id>/assign', methods=['POST'])
@token_required
def assign_meal_plan(current_user_id, plan_id):
    """Пользователь берёт план питания в работу (в т.ч. чужой публичный).
    При старте создаёт приёмы пищи в дневнике для каждого дня плана начиная с сегодня.
    """
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    conn.autocommit = False
    try:
        cursor.execute(
            "SELECT plan_id, is_public, created_by FROM meal_plan WHERE plan_id = %s",
            (plan_id,)
        )
        plan = cursor.fetchone()
        if not plan:
            return jsonify({'success': False, 'message': 'План не найден'}), 404

        raw = plan['is_public']
        is_public = (isinstance(raw, (bytes, bytearray)) and raw != b'\x00') or (not isinstance(raw, (bytes, bytearray)) and raw)
        if not is_public and plan['created_by'] != current_user_id:
            return jsonify({'success': False, 'message': 'Нет доступа к этому плану'}), 403

        # Проверяем, нет ли уже активной записи
        cursor.execute("""
            SELECT ump.id FROM user_meal_plan ump
            JOIN meal_plan_user_meal_plan mpump ON mpump.user_meal_plan_id = ump.id
            WHERE mpump.meal_plan_id = %s AND ump.user_id = %s AND ump.ended_at IS NULL
        """, (plan_id, current_user_id))
        if cursor.fetchone():
            return jsonify({'success': False, 'message': 'Вы уже используете этот план'}), 409

        # Создаём запись user_meal_plan
        cursor.execute(
            "INSERT INTO user_meal_plan (user_id, started_at) VALUES (%s, NOW())",
            (current_user_id,)
        )
        ump_id = cursor.lastrowid
        cursor.execute(
            "INSERT INTO meal_plan_user_meal_plan (meal_plan_id, user_meal_plan_id) VALUES (%s, %s)",
            (plan_id, ump_id)
        )

        # Загружаем дни плана с приёмами пищи
        cursor.execute("""
            SELECT mpd.meal_plan_day_id, mpd.day_number
            FROM meal_plan_day mpd
            WHERE mpd.plan_id = %s
            ORDER BY mpd.day_number
        """, (plan_id,))
        days = cursor.fetchall()

        # Определяем сегодняшнюю дату (локальная TZ сервера)
        local_tz = pytz.timezone('Asia/Novosibirsk')
        today_local = datetime.datetime.now(local_tz).date()

        for day in days:
            day_offset = day['day_number'] - 1  # день 1 = сегодня, день 2 = завтра и т.д.
            target_date = today_local + datetime.timedelta(days=day_offset)

            # Загружаем приёмы пищи этого дня плана
            cursor.execute("""
                SELECT m.meal_id, m.name, m.meal_time
                FROM meal_meal_plan_day mmpd
                JOIN meal m ON mmpd.meal_id = m.meal_id
                WHERE mmpd.meal_plan_day_id = %s
            """, (day['meal_plan_day_id'],))
            plan_meals = cursor.fetchall()

            for pm in plan_meals:
                # Время из плана хранится как datetime с фиктивной датой 2000-01-01
                plan_time = pm['meal_time']  # timedelta или datetime
                if isinstance(plan_time, datetime.timedelta):
                    total_seconds = int(plan_time.total_seconds())
                    hours = total_seconds // 3600
                    minutes = (total_seconds % 3600) // 60
                elif hasattr(plan_time, 'hour'):
                    hours = plan_time.hour
                    minutes = plan_time.minute
                else:
                    hours, minutes = 12, 0

                # Формируем datetime в локальной TZ
                meal_dt_local = local_tz.localize(
                    datetime.datetime(target_date.year, target_date.month, target_date.day, hours, minutes, 0)
                )
                # Конвертируем в UTC для хранения
                meal_dt_utc = meal_dt_local.astimezone(pytz.UTC)
                meal_time_utc_str = meal_dt_utc.strftime('%Y-%m-%d %H:%M:%S')

                # Создаём приём пищи в дневнике пользователя
                cursor.execute(
                    "INSERT INTO meal (user_id, name, meal_time, from_plan_id) VALUES (%s, %s, %s, %s)",
                    (current_user_id, pm['name'], meal_time_utc_str, ump_id)
                )
                new_meal_id = cursor.lastrowid

                # Копируем компоненты из плана
                cursor.execute("""
                    SELECT mc.product_id, mc.weight
                    FROM meal_component mc
                    JOIN meal_meal_component mmc ON mc.meal_meal_component_id = mmc.id
                    WHERE mmc.meal_id = %s
                """, (pm['meal_id'],))
                components = cursor.fetchall()

                for comp in components:
                    cursor.execute("INSERT INTO meal_meal_component (meal_id) VALUES (%s)", (new_meal_id,))
                    link_id = cursor.lastrowid
                    cursor.execute(
                        "INSERT INTO meal_component (meal_meal_component_id, product_id, weight) VALUES (%s, %s, %s)",
                        (link_id, comp['product_id'], comp['weight'])
                    )

        conn.commit()

        # Вычисляем дату/время последнего приёма пищи плана (для автозавершения)
        plan_end_datetime = None
        if days:
            last_day = max(days, key=lambda d: d['day_number'])
            last_day_offset = last_day['day_number'] - 1
            last_date = today_local + datetime.timedelta(days=last_day_offset)

            cursor2 = conn.cursor(dictionary=True)
            cursor2.execute("""
                SELECT m.meal_time
                FROM meal_meal_plan_day mmpd
                JOIN meal m ON mmpd.meal_id = m.meal_id
                WHERE mmpd.meal_plan_day_id = %s
                ORDER BY m.meal_time DESC
                LIMIT 1
            """, (last_day['meal_plan_day_id'],))
            last_meal_row = cursor2.fetchone()
            cursor2.close()

            if last_meal_row and last_meal_row['meal_time'] is not None:
                t = last_meal_row['meal_time']
                if isinstance(t, datetime.timedelta):
                    total_seconds = int(t.total_seconds())
                    h = total_seconds // 3600
                    m = (total_seconds % 3600) // 60
                elif hasattr(t, 'hour'):
                    h, m = t.hour, t.minute
                else:
                    h, m = 23, 59
                end_dt_local = local_tz.localize(
                    datetime.datetime(last_date.year, last_date.month, last_date.day, h, m, 0)
                )
                plan_end_datetime = end_dt_local.strftime('%Y-%m-%d %H:%M:%S')

        return jsonify({
            'success': True,
            'user_meal_plan_id': ump_id,
            'plan_end_datetime': plan_end_datetime,
            'message': 'План взят в работу'
        }), 201
    except mysql.connector.Error as err:
        conn.rollback()
        print(f"Ошибка MySQL в meal-plans/assign: {err}")
        return jsonify({'success': False, 'message': str(err)}), 400
    finally:
        cursor.close()
        conn.close()


@app.route('/meal-plans/<int:plan_id>/finish', methods=['POST'])
@token_required
def finish_meal_plan(current_user_id, plan_id):
    """Завершает активный план питания пользователя (проставляет ended_at).
    При ручном завершении удаляет все приёмы пищи, созданные этим планом.
    """
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    conn.autocommit = False
    try:
        cursor.execute("""
            SELECT ump.id FROM user_meal_plan ump
            JOIN meal_plan_user_meal_plan mpump ON mpump.user_meal_plan_id = ump.id
            WHERE mpump.meal_plan_id = %s AND ump.user_id = %s AND ump.ended_at IS NULL
            LIMIT 1
        """, (plan_id, current_user_id))
        row = cursor.fetchone()
        if not row:
            return jsonify({'success': False, 'message': 'Активный план не найден'}), 404

        ump_id = row['id']

        # Удаляем все приёмы пищи, созданные этим планом (ручное завершение)
        cursor.execute(
            "SELECT meal_id FROM meal WHERE user_id = %s AND from_plan_id = %s",
            (current_user_id, ump_id)
        )
        meal_ids = [r['meal_id'] for r in cursor.fetchall()]
        print(f"finish plan: ump_id={ump_id}, найдено приёмов пищи для удаления: {len(meal_ids)}, ids={meal_ids}")
        if meal_ids:
            mfmt = ','.join(['%s'] * len(meal_ids))
            cursor.execute(f"DELETE FROM meal WHERE meal_id IN ({mfmt})", tuple(meal_ids))

        cursor.execute(
            "UPDATE user_meal_plan SET ended_at = NOW() WHERE id = %s",
            (ump_id,)
        )
        conn.commit()
        return jsonify({'success': True, 'message': 'План завершён'}), 200
    except mysql.connector.Error as err:
        conn.rollback()
        print(f"Ошибка MySQL в meal-plans/finish: {err}")
        return jsonify({'success': False, 'message': str(err)}), 400
    finally:
        cursor.close()
        conn.close()


@app.route('/meal-plans/<int:plan_id>/finish-auto', methods=['POST'])
@token_required
def finish_meal_plan_auto(current_user_id, plan_id):
    """Автоматическое завершение плана — приёмы пищи НЕ удаляются."""
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    conn.autocommit = False
    try:
        cursor.execute("""
            SELECT ump.id FROM user_meal_plan ump
            JOIN meal_plan_user_meal_plan mpump ON mpump.user_meal_plan_id = ump.id
            WHERE mpump.meal_plan_id = %s AND ump.user_id = %s AND ump.ended_at IS NULL
            LIMIT 1
        """, (plan_id, current_user_id))
        row = cursor.fetchone()
        if not row:
            return jsonify({'success': False, 'message': 'Активный план не найден'}), 404

        cursor.execute(
            "UPDATE user_meal_plan SET ended_at = NOW() WHERE id = %s",
            (row['id'],)
        )
        conn.commit()
        return jsonify({'success': True, 'message': 'План завершён автоматически'}), 200
    except mysql.connector.Error as err:
        conn.rollback()
        print(f"Ошибка MySQL в meal-plans/finish-auto: {err}")
        return jsonify({'success': False, 'message': str(err)}), 400
    finally:
        cursor.close()
        conn.close()


@app.route('/meal-plans/<int:plan_id>/share-users', methods=['GET'])
@token_required
def get_plan_shared_users(current_user_id, plan_id):
    """Возвращает список пользователей, использующих план (только для создателя)."""
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT created_by FROM meal_plan WHERE plan_id = %s", (plan_id,))
        row = cursor.fetchone()
        if not row or row['created_by'] != current_user_id:
            return jsonify({'success': False, 'message': 'Нет доступа'}), 403

        cursor.execute("""
            SELECT u.user_id, u.username, ump.started_at, ump.ended_at
            FROM user_meal_plan ump
            JOIN meal_plan_user_meal_plan mpump ON mpump.user_meal_plan_id = ump.id
            JOIN users u ON u.user_id = ump.user_id
            WHERE mpump.meal_plan_id = %s
            ORDER BY ump.started_at DESC
        """, (plan_id,))
        users = cursor.fetchall()
        for u in users:
            if u['started_at']:
                u['started_at'] = u['started_at'].strftime('%Y-%m-%d %H:%M:%S')
            if u['ended_at']:
                u['ended_at'] = u['ended_at'].strftime('%Y-%m-%d %H:%M:%S')

        return jsonify({'success': True, 'users': users}), 200
    except mysql.connector.Error as err:
        print(f"Ошибка MySQL в meal-plans/share: {err}")
        return jsonify({'success': False, 'message': str(err)}), 400
    finally:
        cursor.close()
        conn.close()


# ─── FITNESS MODULE ───────────────────────────────────────────────────────────

# ── Muscles ──────────────────────────────────────────────────────────────────

@app.route('/muscles', methods=['GET'])
def get_muscles():
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT m.id, m.muscle_name, m.muscle_group_id, mg.group_name
            FROM muscles m
            JOIN muscle_groups mg ON m.muscle_group_id = mg.id
            ORDER BY mg.group_name, m.muscle_name
        """)
        muscles = cursor.fetchall()
        return jsonify(muscles), 200
    finally:
        cursor.close()
        conn.close()


# ── Exercises ─────────────────────────────────────────────────────────────────

@app.route('/exercises/equipment', methods=['GET'])
def get_equipment_list():
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT DISTINCT equipment
            FROM exercises
            WHERE equipment IS NOT NULL AND equipment != ''
            ORDER BY equipment
        """)
        equipment = [row[0] for row in cursor.fetchall()]
        return jsonify(equipment), 200
    finally:
        cursor.close()
        conn.close()


@app.route('/exercises', methods=['GET'])
def get_exercises():
    muscle_ids = request.args.getlist('muscle_id', type=int)
    equipments = request.args.getlist('equipment')
    levels = request.args.getlist('level')
    category = request.args.get('category')
    search = request.args.get('search')
    limit = request.args.get('limit', 30, type=int)
    offset = request.args.get('offset', 0, type=int)
    print(f"[GET /exercises] muscle_ids={muscle_ids} equipments={equipments} levels={levels} full_url={request.url}")

    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    try:
        where_clauses = []
        params = []

        if muscle_ids:
            fmt = ','.join(['%s'] * len(muscle_ids))
            where_clauses.append(f"e.target_muscle_id IN ({fmt})")
            params.extend(muscle_ids)
        if equipments:
            fmt = ','.join(['%s'] * len(equipments))
            where_clauses.append(f"e.equipment IN ({fmt})")
            params.extend(equipments)
        if levels:
            fmt = ','.join(['%s'] * len(levels))
            where_clauses.append(f"e.level IN ({fmt})")
            params.extend(levels)
        if category:
            where_clauses.append("e.category = %s")
            params.append(category)
        if search:
            where_clauses.append("(e.exercise_name_ru LIKE %s OR e.exercise_name LIKE %s)")
            like = f"%{search}%"
            params.extend([like, like])

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

        # Count total
        count_sql = f"""
            SELECT COUNT(*) as total
            FROM exercises e
            {where_sql}
        """
        cursor.execute(count_sql, params)
        total = cursor.fetchone()['total']

        # Fetch page
        data_sql = f"""
            SELECT e.id, e.exercise_name, e.exercise_name_ru, e.equipment,
                   e.gif_url, e.level, e.category, e.force_type, e.mechanic,
                   e.target_muscle_id, m.muscle_name AS target_muscle_name
            FROM exercises e
            LEFT JOIN muscles m ON m.id = e.target_muscle_id
            {where_sql}
            ORDER BY e.exercise_name_ru
            LIMIT %s OFFSET %s
        """
        cursor.execute(data_sql, params + [limit, offset])
        exercises = cursor.fetchall()

        return jsonify({"exercises": exercises, "total": total}), 200
    finally:
        cursor.close()
        conn.close()


@app.route('/exercises/<int:exercise_id>', methods=['GET'])
def get_exercise_by_id(exercise_id):
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT e.id, e.exercise_name, e.exercise_name_ru, e.equipment,
                   e.gif_url, e.level, e.category, e.force_type, e.mechanic,
                   e.target_muscle_id, m.muscle_name AS target_muscle_name
            FROM exercises e
            LEFT JOIN muscles m ON m.id = e.target_muscle_id
            WHERE e.id = %s
        """, (exercise_id,))
        exercise = cursor.fetchone()
        if not exercise:
            return jsonify({'error': 'Упражнение не найдено'}), 404

        # Secondary muscles
        cursor.execute("""
            SELECT m.id, m.muscle_name, m.muscle_group_id
            FROM secondary_muscles sm
            JOIN muscles m ON m.id = sm.muscle_id
            WHERE sm.exercise_id = %s
        """, (exercise_id,))
        exercise['secondary_muscles'] = cursor.fetchall()

        # Instructions
        cursor.execute("""
            SELECT id, step_order, instruction, instruction_ru
            FROM exercise_instructions
            WHERE exercise_id = %s
            ORDER BY step_order
        """, (exercise_id,))
        exercise['instructions'] = cursor.fetchall()

        return jsonify(exercise), 200
    finally:
        cursor.close()
        conn.close()


# ── Exercise images (static) ──────────────────────────────────────────────────

@app.route('/exercise_images/<path:filename>')
def serve_exercise_image(filename):
    images_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'exercise_images')
    return send_from_directory(images_dir, filename)

# ── Trainings ─────────────────────────────────────────────────────────────────

@app.route('/trainings', methods=['GET'])
@token_required
def get_trainings(current_user_id):
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT id, training_name, training_date, training_description, notes
            FROM training
            WHERE user_id = %s
            ORDER BY training_date DESC, id DESC
        """, (current_user_id,))
        trainings = cursor.fetchall()

        for t in trainings:
            if t['training_date']:
                t['training_date'] = str(t['training_date'])
            cursor.execute("""
                SELECT te.exercise_id, te.sets, te.reps, te.weight, te.exercise_time,
                       e.exercise_name, e.exercise_name_ru
                FROM training_exercises te
                JOIN exercises e ON e.id = te.exercise_id
                WHERE te.training_id = %s
                ORDER BY te.exercise_id
            """, (t['id'],))
            t['exercises'] = cursor.fetchall()
            for ex in t['exercises']:
                if ex['weight'] is not None:
                    ex['weight'] = float(ex['weight'])
                # Подгружаем детальные подходы из training_sets
                cursor.execute("""
                    SELECT set_number, weight_kg, reps, duration_sec
                    FROM training_sets
                    WHERE training_id = %s AND exercise_id = %s
                    ORDER BY set_number
                """, (t['id'], ex['exercise_id']))
                detailed = cursor.fetchall()
                for s in detailed:
                    if s['weight_kg'] is not None:
                        s['weight_kg'] = float(s['weight_kg'])
                ex['detailed_sets'] = detailed

        return jsonify({"trainings": trainings}), 200
    finally:
        cursor.close()
        conn.close()


@app.route('/trainings', methods=['POST'])
@token_required
def create_training(current_user_id):
    data = request.get_json()
    name = data.get('training_name', '').strip()
    date = data.get('training_date')
    description = data.get('training_description') or None
    notes = data.get('notes') or None
    exercises = data.get('exercises', [])

    if not name:
        return jsonify({'success': False, 'message': 'Название обязательно'}), 400

    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO training (user_id, training_name, training_date, training_description, notes) VALUES (%s, %s, %s, %s, %s)",
            (current_user_id, name, date, description, notes)
        )
        training_id = cursor.lastrowid

        for ex in exercises:
            cursor.execute("""
                INSERT INTO training_exercises (training_id, exercise_id, sets, reps, weight, exercise_time)
                VALUES (%s, %s, %s, %s, %s, %s) AS new_val
                ON DUPLICATE KEY UPDATE sets=new_val.sets, reps=new_val.reps,
                    weight=new_val.weight, exercise_time=new_val.exercise_time
            """, (
                training_id,
                ex.get('exercise_id'),
                ex.get('sets'),
                ex.get('reps'),
                ex.get('weight'),
                ex.get('exercise_time')
            ))

        conn.commit()
        return jsonify({'success': True, 'id': training_id}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/trainings/<int:training_id>', methods=['PUT'])
@token_required
def update_training(current_user_id, training_id):
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id FROM training WHERE id = %s AND user_id = %s", (training_id, current_user_id))
        if not cursor.fetchone():
            return jsonify({'success': False, 'message': 'Тренировка не найдена'}), 404

        data = request.get_json()
        name = data.get('training_name', '').strip()
        date = data.get('training_date')
        description = data.get('training_description') or None
        notes = data.get('notes') or None
        exercises = data.get('exercises', [])

        cursor.execute(
            "UPDATE training SET training_name = %s, training_date = %s, training_description = %s, notes = %s WHERE id = %s",
            (name, date, description, notes, training_id)
        )
        cursor.execute("DELETE FROM training_exercises WHERE training_id = %s", (training_id,))

        for ex in exercises:
            cursor.execute("""
                INSERT INTO training_exercises (training_id, exercise_id, sets, reps, weight, exercise_time)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                training_id,
                ex.get('exercise_id'),
                ex.get('sets'),
                ex.get('reps'),
                ex.get('weight'),
                ex.get('exercise_time')
            ))

        conn.commit()
        return jsonify({'success': True, 'id': training_id}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/trainings/<int:training_id>', methods=['DELETE'])
@token_required
def delete_training(current_user_id, training_id):
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id FROM training WHERE id = %s AND user_id = %s", (training_id, current_user_id))
        if not cursor.fetchone():
            return jsonify({'success': False, 'message': 'Тренировка не найдена'}), 404

        cursor.execute("DELETE FROM training WHERE id = %s", (training_id,))
        conn.commit()
        return jsonify({'success': True}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/trainings/<int:training_id>/sets', methods=['GET'])
@token_required
def get_training_sets(current_user_id, training_id):
    """Возвращает все подходы тренировки с детализацией по сетам."""
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    try:
        # Проверяем владельца
        cursor.execute("SELECT id FROM training WHERE id = %s AND user_id = %s", (training_id, current_user_id))
        if not cursor.fetchone():
            return jsonify({'success': False, 'message': 'Тренировка не найдена'}), 404

        cursor.execute("""
            SELECT ts.id, ts.exercise_id, ts.set_number,
                   ts.weight_kg, ts.reps, ts.duration_sec,
                   e.exercise_name, e.exercise_name_ru
            FROM training_sets ts
            JOIN exercises e ON e.id = ts.exercise_id
            WHERE ts.training_id = %s
            ORDER BY ts.exercise_id, ts.set_number
        """, (training_id,))
        sets = cursor.fetchall()
        for s in sets:
            if s['weight_kg'] is not None:
                s['weight_kg'] = float(s['weight_kg'])
        return jsonify({'success': True, 'sets': sets}), 200
    finally:
        cursor.close()
        conn.close()


@app.route('/trainings/with-sets', methods=['POST'])
@token_required
def create_training_with_sets(current_user_id):
    """Создаёт тренировку с детализацией по подходам.

    Тело запроса:
    {
        "training_name": "Памп",
        "training_date": "2026-04-27",
        "training_description": null,
        "notes": null,
        "exercises": [
            {
                "exercise_id": 42,
                "sets": [
                    {"set_number": 1, "weight_kg": 60.0, "reps": 10, "duration_sec": null},
                    {"set_number": 2, "weight_kg": 65.0, "reps": 8,  "duration_sec": null}
                ]
            }
        ]
    }

    Дополнительно заполняет training_exercises агрегированными данными
    (sets=кол-во подходов, reps=среднее, weight=макс) для обратной совместимости.
    """
    data = request.get_json()
    name = data.get('training_name', '').strip()
    date = data.get('training_date')
    description = data.get('training_description') or None
    notes = data.get('notes') or None
    exercises = data.get('exercises', [])

    if not name:
        return jsonify({'success': False, 'message': 'Название обязательно'}), 400

    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor()
    conn.autocommit = False
    try:
        # Создаём запись тренировки
        cursor.execute(
            "INSERT INTO training (user_id, training_name, training_date, training_description, notes) "
            "VALUES (%s, %s, %s, %s, %s)",
            (current_user_id, name, date, description, notes)
        )
        training_id = cursor.lastrowid

        for ex in exercises:
            exercise_id = ex.get('exercise_id')
            sets = ex.get('sets', [])
            if not sets:
                continue

            # Вставляем детализированные подходы
            for s in sets:
                cursor.execute("""
                    INSERT INTO training_sets (training_id, exercise_id, set_number, weight_kg, reps, duration_sec)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (
                    training_id,
                    exercise_id,
                    s.get('set_number', 1),
                    s.get('weight_kg'),
                    s.get('reps'),
                    s.get('duration_sec')
                ))

            # Агрегируем для training_exercises (обратная совместимость)
            reps_list = [s['reps'] for s in sets if s.get('reps') is not None]
            weights = [s['weight_kg'] for s in sets if s.get('weight_kg') is not None]
            durations = [s['duration_sec'] for s in sets if s.get('duration_sec') is not None]

            agg_sets = len(sets)
            agg_reps = round(sum(reps_list) / len(reps_list)) if reps_list else None
            agg_weight = max(weights) if weights else None
            agg_time = sum(durations) if durations else None

            cursor.execute("""
                INSERT INTO training_exercises (training_id, exercise_id, sets, reps, weight, exercise_time)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (training_id, exercise_id, agg_sets, agg_reps, agg_weight, agg_time))

        conn.commit()
        return jsonify({'success': True, 'id': training_id}), 201
    except Exception as e:
        conn.rollback()
        print(f"Ошибка в create_training_with_sets: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/trainings/<int:training_id>/with-sets', methods=['PUT'])
@token_required
def update_training_with_sets(current_user_id, training_id):
    """Обновляет тренировку с детализацией по подходам."""
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    conn.autocommit = False
    try:
        cursor.execute("SELECT id FROM training WHERE id = %s AND user_id = %s", (training_id, current_user_id))
        if not cursor.fetchone():
            return jsonify({'success': False, 'message': 'Тренировка не найдена'}), 404

        data = request.get_json()
        name = data.get('training_name', '').strip()
        date = data.get('training_date')
        description = data.get('training_description') or None
        notes = data.get('notes') or None
        exercises = data.get('exercises', [])

        if not name:
            return jsonify({'success': False, 'message': 'Название обязательно'}), 400

        cursor.execute(
            "UPDATE training SET training_name=%s, training_date=%s, training_description=%s, notes=%s WHERE id=%s",
            (name, date, description, notes, training_id)
        )
        # Удаляем старые детальные подходы и агрегаты
        cursor.execute("DELETE FROM training_sets WHERE training_id = %s", (training_id,))
        cursor.execute("DELETE FROM training_exercises WHERE training_id = %s", (training_id,))

        for ex in exercises:
            exercise_id = ex.get('exercise_id')
            sets = ex.get('sets', [])
            if not sets:
                continue

            for s in sets:
                cursor.execute("""
                    INSERT INTO training_sets (training_id, exercise_id, set_number, weight_kg, reps, duration_sec)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (training_id, exercise_id, s.get('set_number', 1),
                      s.get('weight_kg'), s.get('reps'), s.get('duration_sec')))

            reps_list = [s['reps'] for s in sets if s.get('reps') is not None]
            weights = [s['weight_kg'] for s in sets if s.get('weight_kg') is not None]
            durations = [s['duration_sec'] for s in sets if s.get('duration_sec') is not None]

            cursor.execute("""
                INSERT INTO training_exercises (training_id, exercise_id, sets, reps, weight, exercise_time)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (training_id, exercise_id,
                  len(sets),
                  round(sum(reps_list) / len(reps_list)) if reps_list else None,
                  max(weights) if weights else None,
                  sum(durations) if durations else None))

        conn.commit()
        return jsonify({'success': True, 'id': training_id}), 200
    except Exception as e:
        conn.rollback()
        print(f"Ошибка в update_training_with_sets: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()


# ── Training Plans ────────────────────────────────────────────────────────────

def _fetch_plan_with_days(cursor, plan_id):
    cursor.execute("""
        SELECT id, plan_name, plan_description, BIT_COUNT(is_public) as is_public, creator_id
        FROM training_plan WHERE id = %s
    """, (plan_id,))
    plan = cursor.fetchone()
    if not plan:
        return None
    plan['is_public'] = int(plan['is_public'])

    cursor.execute("SELECT id, day_number, day_name, notes FROM training_plan_day WHERE training_plan_id = %s ORDER BY day_number", (plan_id,))
    days = cursor.fetchall()
    for day in days:
        cursor.execute("""
            SELECT pde.exercise_id, pde.sets, pde.reps, pde.weight, pde.exercise_time,
                   e.exercise_name, e.exercise_name_ru
            FROM plan_day_exercises pde
            JOIN exercises e ON e.id = pde.exercise_id
            WHERE pde.training_plan_day_id = %s
        """, (day['id'],))
        day['exercises'] = cursor.fetchall()
        for ex in day['exercises']:
            if ex['weight'] is not None:
                ex['weight'] = float(ex['weight'])
    plan['days'] = days
    return plan


@app.route('/training-plans', methods=['GET'])
@token_required
def get_training_plans(current_user_id):
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    try:
        # Собственные планы пользователя
        cursor.execute("""
            SELECT tp.id, tp.plan_name, tp.plan_description,
                   BIT_COUNT(tp.is_public) as is_public,
                   tp.creator_id,
                   (SELECT COUNT(*) FROM training_plan_day WHERE training_plan_id = tp.id) as day_count,
                   NULL AS assigned_by_trainer_id
            FROM training_plan tp
            WHERE tp.creator_id = %s

            UNION ALL

            -- Планы, назначенные тренером (где пользователь не создатель)
            SELECT tp.id, tp.plan_name, tp.plan_description,
                   BIT_COUNT(tp.is_public) as is_public,
                   tp.creator_id,
                   (SELECT COUNT(*) FROM training_plan_day WHERE training_plan_id = tp.id) as day_count,
                   atp.assigned_by_trainer_id
            FROM active_training_plans atp
            JOIN training_plan tp ON tp.id = atp.training_plan_id
            WHERE atp.user_id = %s
              AND atp.ended_at IS NULL
              AND atp.assigned_by_trainer_id IS NOT NULL
              AND tp.creator_id != %s

            ORDER BY id DESC
        """, (current_user_id, current_user_id, current_user_id))
        plans = cursor.fetchall()
        for p in plans:
            p['is_public'] = int(p['is_public'] or 0)
            p['assigned_by_trainer_id'] = p.get('assigned_by_trainer_id')
            cursor.execute("""
                SELECT id, day_number, day_name, notes
                FROM training_plan_day
                WHERE training_plan_id = %s
                ORDER BY day_number
            """, (p['id'],))
            days = cursor.fetchall()
            for d in days:
                cursor.execute("""
                    SELECT pde.exercise_id, pde.sets, pde.reps, pde.weight, pde.exercise_time,
                           e.exercise_name, e.exercise_name_ru
                    FROM plan_day_exercises pde
                    JOIN exercises e ON e.id = pde.exercise_id
                    WHERE pde.training_plan_day_id = %s
                    ORDER BY pde.exercise_id
                """, (d['id'],))
                d['exercises'] = cursor.fetchall()
                for ex in d['exercises']:
                    if ex['weight'] is not None:
                        ex['weight'] = float(ex['weight'])
            p['days'] = days
        return jsonify({"plans": plans}), 200
    finally:
        cursor.close()
        conn.close()


@app.route('/training-plans/public', methods=['GET'])
@token_required
def get_public_training_plans(current_user_id):
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT id, plan_name, plan_description, BIT_COUNT(is_public) as is_public, creator_id,
                   (SELECT COUNT(*) FROM training_plan_day WHERE training_plan_id = tp.id) as day_count
            FROM training_plan tp
            WHERE BIT_COUNT(is_public) = 1
              AND creator_id != %s
            ORDER BY id DESC
        """, (current_user_id,))
        plans = cursor.fetchall()
        for p in plans:
            p['is_public'] = int(p['is_public'])
        return jsonify({"plans": plans}), 200
    finally:
        cursor.close()
        conn.close()


@app.route('/training-plans/<int:plan_id>', methods=['GET'])
def get_training_plan_by_id(plan_id):
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    try:
        plan = _fetch_plan_with_days(cursor, plan_id)
        if not plan:
            return jsonify({'error': 'План не найден'}), 404
        return jsonify(plan), 200
    finally:
        cursor.close()
        conn.close()


@app.route('/training-plans', methods=['POST'])
@token_required
def create_training_plan(current_user_id):
    data = request.get_json()
    name = data.get('plan_name', '').strip()
    description = data.get('plan_description', '')
    is_public = 1 if data.get('is_public') else 0
    days = data.get('days', [])

    if not name:
        return jsonify({'success': False, 'message': 'Название обязательно'}), 400

    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO training_plan (creator_id, plan_name, plan_description, is_public) VALUES (%s, %s, %s, %s)",
            (current_user_id, name, description, is_public)
        )
        plan_id = cursor.lastrowid

        for day in days:
            cursor.execute(
                "INSERT INTO training_plan_day (training_plan_id, day_number, day_name, notes) VALUES (%s, %s, %s, %s)",
                (plan_id, day.get('day_number', 1), day.get('day_name') or None, day.get('notes') or None)
            )
            day_id = cursor.lastrowid
            for ex in day.get('exercises', []):
                cursor.execute("""
                    INSERT INTO plan_day_exercises (training_plan_day_id, exercise_id, sets, reps, weight, exercise_time)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (
                    day_id,
                    ex.get('exercise_id'),
                    ex.get('sets'),
                    ex.get('reps'),
                    ex.get('weight'),
                    ex.get('exercise_time')
                ))

        conn.commit()
        return jsonify({'success': True, 'id': plan_id}), 201
    except Exception as e:
        conn.rollback()
        print(str(e))
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/training-plans/<int:plan_id>', methods=['PUT'])
@token_required
def update_training_plan(current_user_id, plan_id):
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id FROM training_plan WHERE id = %s AND creator_id = %s", (plan_id, current_user_id))
        if not cursor.fetchone():
            return jsonify({'success': False, 'message': 'План не найден'}), 404

        data = request.get_json()
        name = data.get('plan_name', '').strip()
        description = data.get('plan_description', '')
        is_public = 1 if data.get('is_public') else 0
        days = data.get('days', [])

        cursor.execute(
            "UPDATE training_plan SET plan_name=%s, plan_description=%s, is_public=%s WHERE id=%s",
            (name, description, is_public, plan_id)
        )

        # Delete old days (cascades to plan_day_exercises via FK)
        cursor.execute("SELECT id FROM training_plan_day WHERE training_plan_id = %s", (plan_id,))
        old_day_ids = [r['id'] for r in cursor.fetchall()]
        for did in old_day_ids:
            cursor.execute("DELETE FROM plan_day_exercises WHERE training_plan_day_id = %s", (did,))
        cursor.execute("DELETE FROM training_plan_day WHERE training_plan_id = %s", (plan_id,))

        for day in days:
            cursor.execute(
                "INSERT INTO training_plan_day (training_plan_id, day_number, day_name, notes) VALUES (%s, %s, %s, %s)",
                (plan_id, day.get('day_number', 1), day.get('day_name') or None, day.get('notes') or None)
            )
            day_id = cursor.lastrowid
            for ex in day.get('exercises', []):
                cursor.execute("""
                    INSERT INTO plan_day_exercises (training_plan_day_id, exercise_id, sets, reps, weight, exercise_time)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (
                    day_id,
                    ex.get('exercise_id'),
                    ex.get('sets'),
                    ex.get('reps'),
                    ex.get('weight'),
                    ex.get('exercise_time')
                ))

        conn.commit()
        return jsonify({'success': True, 'id': plan_id}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/training-plans/<int:plan_id>', methods=['DELETE'])
@token_required
def delete_training_plan(current_user_id, plan_id):
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id FROM training_plan WHERE id = %s AND creator_id = %s", (plan_id, current_user_id))
        if not cursor.fetchone():
            return jsonify({'success': False, 'message': 'План не найден'}), 404

        cursor.execute("SELECT id FROM training_plan_day WHERE training_plan_id = %s", (plan_id,))
        day_ids = [r['id'] for r in cursor.fetchall()]
        for did in day_ids:
            cursor.execute("DELETE FROM plan_day_exercises WHERE training_plan_day_id = %s", (did,))
        cursor.execute("DELETE FROM training_plan_day WHERE training_plan_id = %s", (plan_id,))
        cursor.execute("DELETE FROM training_plan WHERE id = %s", (plan_id,))
        conn.commit()
        return jsonify({'success': True}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/trainer/clients', methods=['GET'])
@token_required
def get_trainer_clients(current_user_id):
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    try:
        current_role = get_user_role_by_id(cursor, current_user_id)
        if current_role < 2:
            return jsonify({'error': 'Недостаточно прав'}), 403

        cursor.execute("""
            SELECT 
                u.user_id,
                u.username,
                u.email,
                (SELECT tp.plan_name 
                 FROM active_training_plans atp
                 JOIN training_plan tp ON tp.id = atp.training_plan_id
                 WHERE atp.user_id = u.user_id AND atp.ended_at IS NULL
                 ORDER BY atp.started_at DESC LIMIT 1) AS active_training_plan_name,
                (SELECT mp.name 
                 FROM user_meal_plan ump
                 JOIN meal_plan_user_meal_plan mpump ON mpump.user_meal_plan_id = ump.id
                 JOIN meal_plan mp ON mp.plan_id = mpump.meal_plan_id
                 WHERE ump.user_id = u.user_id AND ump.ended_at IS NULL
                 ORDER BY ump.started_at DESC LIMIT 1) AS active_meal_plan_name,
                (SELECT DATE_FORMAT(MAX(t.training_date), '%%Y-%%m-%%d')
                 FROM training t
                 WHERE t.user_id = u.user_id) AS last_training_date
            FROM trainer_clients tc
            JOIN users u ON u.user_id = tc.client_id
            WHERE tc.trainer_id = %s
            ORDER BY u.username ASC
        """, (current_user_id,))
        clients = cursor.fetchall()
        return jsonify({'clients': clients}), 200
    except mysql.connector.Error as err:
        return jsonify({'error': str(err)}), 400
    finally:
        cursor.close()
        conn.close()


@app.route('/trainer/requests', methods=['GET'])
@token_required
def get_trainer_requests(current_user_id):
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    try:
        current_role = get_user_role_by_id(cursor, current_user_id)
        if current_role < 2:
            return jsonify({'error': 'Недостаточно прав'}), 403

        cursor.execute("""
            SELECT tr.id AS request_id, tr.user_id, u.username, u.email, tr.status
            FROM trainer_requests tr
            JOIN users u ON u.user_id = tr.user_id
            WHERE tr.trainer_id = %s AND tr.status = 'pending'
            ORDER BY tr.created_at ASC
        """, (current_user_id,))
        requests = cursor.fetchall()
        return jsonify({'requests': requests}), 200
    except mysql.connector.Error as err:
        return jsonify({'error': str(err)}), 400
    finally:
        cursor.close()
        conn.close()


@app.route('/trainer/requests/<int:request_id>/accept', methods=['POST'])
@token_required
def accept_trainer_request(current_user_id, request_id):
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    conn.autocommit = False
    try:
        current_role = get_user_role_by_id(cursor, current_user_id)
        if current_role < 2:
            return jsonify({'error': 'Недостаточно прав'}), 403

        cursor.execute(
            "SELECT id, user_id, trainer_id FROM trainer_requests WHERE id = %s AND trainer_id = %s AND status = 'pending'",
            (request_id, current_user_id)
        )
        req = cursor.fetchone()
        if not req:
            return jsonify({'error': 'Заявка не найдена'}), 404

        cursor.execute(
            "UPDATE trainer_requests SET status = 'accepted' WHERE id = %s",
            (request_id,)
        )
        # Add to trainer_clients (ignore if already exists)
        cursor.execute(
            "INSERT IGNORE INTO trainer_clients (trainer_id, client_id) VALUES (%s, %s)",
            (current_user_id, req['user_id'])
        )
        conn.commit()

        # FCM-уведомление клиенту
        try:
            conn2 = mysql.connector.connect(**cfg)
            cursor2 = conn2.cursor(dictionary=True)
            fcm_token = get_user_fcm_token(cursor2, req['user_id'])
            cursor2.execute("SELECT username FROM users WHERE user_id = %s", (current_user_id,))
            trainer_row = cursor2.fetchone()
            trainer_name = trainer_row['username'] if trainer_row else "Тренер"
            cursor2.close()
            conn2.close()
            print(f"[FCM] accept: user_id={req['user_id']}, token={'present' if fcm_token else 'MISSING'}")
            if fcm_token:
                result = send_fcm_notification(
                    fcm_token,
                    title="Заявка принята",
                    body=f"Тренер {trainer_name} принял вашу заявку",
                    data={"deeplink": "app://trainer/request/accepted"}
                )
                print(f"[FCM] accept send result: {result}")
            else:
                print(f"[FCM] accept: no token for user_id={req['user_id']}")
        except Exception as e:
            print(f"[FCM] accept notification failed: {e}")

        return jsonify({'message': 'Заявка принята'}), 200
    except mysql.connector.Error as err:
        conn.rollback()
        return jsonify({'error': str(err)}), 400
    finally:
        cursor.close()
        conn.close()


@app.route('/trainer/requests/<int:request_id>/reject', methods=['POST'])
@token_required
def reject_trainer_request(current_user_id, request_id):
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    try:
        current_role = get_user_role_by_id(cursor, current_user_id)
        if current_role < 2:
            return jsonify({'error': 'Недостаточно прав'}), 403

        cursor.execute(
            "SELECT id FROM trainer_requests WHERE id = %s AND trainer_id = %s AND status = 'pending'",
            (request_id, current_user_id)
        )
        if not cursor.fetchone():
            return jsonify({'error': 'Заявка не найдена'}), 404

        cursor.execute(
            "UPDATE trainer_requests SET status = 'rejected' WHERE id = %s",
            (request_id,)
        )
        conn.commit()

        # FCM-уведомление клиенту
        try:
            conn2 = mysql.connector.connect(**cfg)
            cursor2 = conn2.cursor(dictionary=True)
            # Получаем данные заявки (user_id и trainer_id)
            cursor2.execute(
                "SELECT user_id, trainer_id FROM trainer_requests WHERE id = %s",
                (request_id,)
            )
            req_row = cursor2.fetchone()
            if req_row:
                fcm_token = get_user_fcm_token(cursor2, req_row['user_id'])
                cursor2.execute("SELECT username FROM users WHERE user_id = %s", (req_row['trainer_id'],))
                trainer_row = cursor2.fetchone()
                trainer_name = trainer_row['username'] if trainer_row else "Тренер"
                print(f"[FCM] reject: user_id={req_row['user_id']}, token={'present' if fcm_token else 'MISSING'}")
                if fcm_token:
                    result = send_fcm_notification(
                        fcm_token,
                        title="Заявка отклонена",
                        body=f"Тренер {trainer_name} отклонил вашу заявку",
                        data={"deeplink": "app://trainer/request/rejected"}
                    )
                    print(f"[FCM] reject send result: {result}")
                else:
                    print(f"[FCM] reject: no token for user_id={req_row['user_id']}")
            cursor2.close()
            conn2.close()
        except Exception as e:
            print(f"[FCM] reject notification failed: {e}")

        return jsonify({'message': 'Заявка отклонена'}), 200
    except mysql.connector.Error as err:
        conn.rollback()
        return jsonify({'error': str(err)}), 400
    finally:
        cursor.close()
        conn.close()


@app.route('/trainer/clients/<int:client_id>/assign-training-plan', methods=['POST'])
@token_required
def trainer_assign_training_plan(current_user_id, client_id):
    data = request.get_json(silent=True) or {}
    plan_id = data.get('plan_id')
    mode = data.get('mode', 'as_is')  # 'as_is' or 'copy'

    if not plan_id:
        return jsonify({'error': 'plan_id обязателен'}), 400

    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    conn.autocommit = False
    try:
        current_role = get_user_role_by_id(cursor, current_user_id)
        if current_role < 2:
            return jsonify({'error': 'Недостаточно прав'}), 403

        # Verify client belongs to this trainer
        cursor.execute(
            "SELECT id FROM trainer_clients WHERE trainer_id = %s AND client_id = %s",
            (current_user_id, client_id)
        )
        if not cursor.fetchone():
            return jsonify({'error': 'Клиент не найден или не является вашим подопечным'}), 403

        # Verify plan belongs to trainer
        cursor.execute(
            "SELECT id, plan_name, plan_description, is_public FROM training_plan WHERE id = %s AND creator_id = %s",
            (plan_id, current_user_id)
        )
        plan = cursor.fetchone()
        if not plan:
            return jsonify({'error': 'Нельзя назначить план другого тренера'}), 403

        assign_plan_id = plan_id

        if mode == 'copy':
            # Clone the plan
            cursor.execute(
                "INSERT INTO training_plan (creator_id, plan_name, plan_description, is_public) VALUES (%s, %s, %s, 0)",
                (current_user_id, plan['plan_name'] + ' (копия)', plan['plan_description'])
            )
            new_plan_id = cursor.lastrowid

            # Clone days and exercises
            cursor.execute(
                "SELECT id, day_number, day_name, notes FROM training_plan_day WHERE training_plan_id = %s ORDER BY day_number",
                (plan_id,)
            )
            days = cursor.fetchall()
            for day in days:
                cursor.execute(
                    "INSERT INTO training_plan_day (training_plan_id, day_number, day_name, notes) VALUES (%s, %s, %s, %s)",
                    (new_plan_id, day['day_number'], day['day_name'], day['notes'])
                )
                new_day_id = cursor.lastrowid
                cursor.execute(
                    "SELECT exercise_id, sets, reps, weight, exercise_time FROM plan_day_exercises WHERE training_plan_day_id = %s",
                    (day['id'],)
                )
                exercises = cursor.fetchall()
                for ex in exercises:
                    cursor.execute(
                        "INSERT INTO plan_day_exercises (training_plan_day_id, exercise_id, sets, reps, weight, exercise_time) VALUES (%s, %s, %s, %s, %s, %s)",
                        (new_day_id, ex['exercise_id'], ex['sets'], ex['reps'], ex['weight'], ex['exercise_time'])
                    )
            assign_plan_id = new_plan_id

        # End any currently active training plan for the client
        cursor.execute(
            "UPDATE active_training_plans SET ended_at = NOW() WHERE user_id = %s AND ended_at IS NULL",
            (client_id,)
        )

        # Assign the plan to the client
        cursor.execute(
            "INSERT INTO active_training_plans (training_plan_id, user_id, started_at, assigned_by_trainer_id) VALUES (%s, %s, NOW(), %s)",
            (assign_plan_id, client_id, current_user_id)
        )
        conn.commit()

        # FCM-уведомление клиенту о назначении плана тренировок
        try:
            conn2 = mysql.connector.connect(**cfg)
            cursor2 = conn2.cursor(dictionary=True)
            fcm_token = get_user_fcm_token(cursor2, client_id)
            cursor2.execute("SELECT username FROM users WHERE user_id = %s", (current_user_id,))
            trainer_row = cursor2.fetchone()
            trainer_name = trainer_row['username'] if trainer_row else "Тренер"
            cursor2.close()
            conn2.close()
            print(f"[FCM] training plan: client_id={client_id}, token={'present' if fcm_token else 'MISSING'}, trainer={trainer_name}")
            if fcm_token:
                result = send_fcm_notification(
                    fcm_token,
                    title="Вам назначен план тренировок",
                    body=f"Тренер {trainer_name} назначил вам тренировочный план",
                    data={"deeplink": f"app://plans/training/{assign_plan_id}"}
                )
                print(f"[FCM] training plan send result: {result}")
            else:
                print(f"[FCM] training plan: no FCM token for client_id={client_id}")
        except Exception as e:
            print(f"[FCM] training plan notification failed: {e}")

        return jsonify({'message': 'Тренировочный план назначен', 'plan_id': assign_plan_id}), 200
    except mysql.connector.Error as err:
        conn.rollback()
        return jsonify({'error': str(err)}), 400
    finally:
        cursor.close()
        conn.close()


@app.route('/trainer/clients/<int:client_id>/assign-meal-plan', methods=['POST'])
@token_required
def trainer_assign_meal_plan(current_user_id, client_id):
    data = request.get_json(silent=True) or {}
    plan_id = data.get('plan_id')
    mode = data.get('mode', 'as_is')

    if not plan_id:
        return jsonify({'error': 'plan_id обязателен'}), 400

    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    conn.autocommit = False
    try:
        current_role = get_user_role_by_id(cursor, current_user_id)
        if current_role < 2:
            return jsonify({'error': 'Недостаточно прав'}), 403

        # Verify client belongs to this trainer
        cursor.execute(
            "SELECT id FROM trainer_clients WHERE trainer_id = %s AND client_id = %s",
            (current_user_id, client_id)
        )
        if not cursor.fetchone():
            return jsonify({'error': 'Клиент не найден или не является вашим подопечным'}), 403

        # Verify plan belongs to trainer
        cursor.execute(
            "SELECT plan_id, name, description, target_calories, protein_pct, fats_pct, carbs_pct FROM meal_plan WHERE plan_id = %s AND created_by = %s",
            (plan_id, current_user_id)
        )
        plan = cursor.fetchone()
        if not plan:
            return jsonify({'error': 'Нельзя назначить план питания другого тренера'}), 403

        assign_plan_id = plan_id

        if mode == 'copy':
            # Clone the meal plan
            cursor.execute(
                "INSERT INTO meal_plan (name, description, is_public, created_by, target_calories, protein_pct, fats_pct, carbs_pct) VALUES (%s, %s, 0, %s, %s, %s, %s, %s)",
                (plan['name'] + ' (копия)', plan['description'], current_user_id,
                 plan['target_calories'], plan['protein_pct'], plan['fats_pct'], plan['carbs_pct'])
            )
            assign_plan_id = cursor.lastrowid
            # Note: meal plan days/meals cloning is complex; skip for MVP and assign the copy without days

        # End any currently active meal plan for the client
        cursor.execute("""
            UPDATE user_meal_plan SET ended_at = NOW()
            WHERE user_id = %s AND ended_at IS NULL
        """, (client_id,))

        # Create user_meal_plan entry
        cursor.execute(
            "INSERT INTO user_meal_plan (user_id, started_at, assigned_by_trainer_id) VALUES (%s, NOW(), %s)",
            (client_id, current_user_id)
        )
        ump_id = cursor.lastrowid
        cursor.execute(
            "INSERT INTO meal_plan_user_meal_plan (meal_plan_id, user_meal_plan_id) VALUES (%s, %s)",
            (assign_plan_id, ump_id)
        )
        conn.commit()

        # FCM-уведомление клиенту о назначении плана питания
        try:
            conn2 = mysql.connector.connect(**cfg)
            cursor2 = conn2.cursor(dictionary=True)
            fcm_token = get_user_fcm_token(cursor2, client_id)
            cursor2.execute("SELECT username FROM users WHERE user_id = %s", (current_user_id,))
            trainer_row = cursor2.fetchone()
            trainer_name = trainer_row['username'] if trainer_row else "Тренер"
            cursor2.close()
            conn2.close()
            print(f"[FCM] meal plan: client_id={client_id}, token={'present' if fcm_token else 'MISSING'}, trainer={trainer_name}")
            if fcm_token:
                result = send_fcm_notification(
                    fcm_token,
                    title="Вам назначен план питания",
                    body=f"Тренер {trainer_name} назначил вам план питания",
                    data={"deeplink": f"app://plans/meal/{assign_plan_id}"}
                )
                print(f"[FCM] meal plan send result: {result}")
            else:
                print(f"[FCM] meal plan: no FCM token for client_id={client_id}")
        except Exception as e:
            print(f"[FCM] meal plan notification failed: {e}")

        return jsonify({'message': 'План питания назначен', 'user_meal_plan_id': ump_id}), 200
    except mysql.connector.Error as err:
        conn.rollback()
        return jsonify({'error': str(err)}), 400
    finally:
        cursor.close()
        conn.close()


@app.route('/trainer/clients/<int:client_id>', methods=['DELETE'])
@token_required
def remove_trainer_client(current_user_id, client_id):
    """Тренер отказывается от клиента — удаляет его из своего списка."""
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    conn.autocommit = False
    try:
        current_role = get_user_role_by_id(cursor, current_user_id)
        if current_role < 2:
            return jsonify({'error': 'Недостаточно прав'}), 403

        cursor.execute(
            "SELECT id FROM trainer_clients WHERE trainer_id = %s AND client_id = %s",
            (current_user_id, client_id)
        )
        if not cursor.fetchone():
            return jsonify({'error': 'Клиент не найден'}), 404

        cursor.execute(
            "DELETE FROM trainer_clients WHERE trainer_id = %s AND client_id = %s",
            (current_user_id, client_id)
        )
        # Помечаем заявку как rejected чтобы клиент мог отправить новую заявку другому тренеру
        cursor.execute(
            "UPDATE trainer_requests SET status = 'rejected' WHERE trainer_id = %s AND user_id = %s AND status = 'accepted'",
            (current_user_id, client_id)
        )
        conn.commit()

        # FCM-уведомление клиенту
        try:
            conn2 = mysql.connector.connect(**cfg)
            cursor2 = conn2.cursor(dictionary=True)
            fcm_token = get_user_fcm_token(cursor2, client_id)
            cursor2.execute("SELECT username FROM users WHERE user_id = %s", (current_user_id,))
            trainer_row = cursor2.fetchone()
            trainer_name = trainer_row['username'] if trainer_row else "Тренер"
            cursor2.close()
            conn2.close()
            if fcm_token:
                send_fcm_notification(
                    fcm_token,
                    title="Тренер завершил работу с вами",
                    body=f"Тренер {trainer_name} прекратил сотрудничество",
                    data={"deeplink": "app://trainer/removed"}
                )
        except Exception as e:
            logger.warning(f"FCM remove client notification failed: {e}")

        return jsonify({'message': 'Клиент удалён из списка'}), 200
    except mysql.connector.Error as err:
        conn.rollback()
        return jsonify({'error': str(err)}), 400
    finally:
        cursor.close()
        conn.close()


@app.route('/trainer/clients/<int:client_id>/training-log', methods=['GET'])
@token_required
def get_client_training_log(current_user_id, client_id):
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    try:
        current_role = get_user_role_by_id(cursor, current_user_id)
        if current_role < 2:
            return jsonify({'error': 'Недостаточно прав'}), 403

        cursor.execute(
            "SELECT id FROM trainer_clients WHERE trainer_id = %s AND client_id = %s",
            (current_user_id, client_id)
        )
        if not cursor.fetchone():
            return jsonify({'error': 'Клиент не найден или не является вашим подопечным'}), 403

        cursor.execute("""
            SELECT id, training_name, training_date, training_description, notes
            FROM training
            WHERE user_id = %s
            ORDER BY training_date DESC, id DESC
        """, (client_id,))
        trainings = cursor.fetchall()

        for t in trainings:
            if t['training_date']:
                t['training_date'] = str(t['training_date'])
            cursor.execute("""
                SELECT te.exercise_id, te.sets, te.reps, te.weight, te.exercise_time,
                       e.exercise_name, e.exercise_name_ru
                FROM training_exercises te
                JOIN exercises e ON e.id = te.exercise_id
                WHERE te.training_id = %s
                ORDER BY te.exercise_id
            """, (t['id'],))
            t['exercises'] = cursor.fetchall()
            for ex in t['exercises']:
                if ex['weight'] is not None:
                    ex['weight'] = float(ex['weight'])
                cursor.execute("""
                    SELECT set_number, weight_kg, reps, duration_sec
                    FROM training_sets
                    WHERE training_id = %s AND exercise_id = %s
                    ORDER BY set_number
                """, (t['id'], ex['exercise_id']))
                detailed = cursor.fetchall()
                for s in detailed:
                    if s['weight_kg'] is not None:
                        s['weight_kg'] = float(s['weight_kg'])
                ex['detailed_sets'] = detailed

        return jsonify({'trainings': trainings}), 200
    except mysql.connector.Error as err:
        return jsonify({'error': str(err)}), 400
    finally:
        cursor.close()
        conn.close()


@app.route('/trainer/clients/<int:client_id>/nutrition-log', methods=['GET'])
@token_required
def get_client_nutrition_log(current_user_id, client_id):
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    try:
        current_role = get_user_role_by_id(cursor, current_user_id)
        if current_role < 2:
            return jsonify({'error': 'Недостаточно прав'}), 403

        cursor.execute(
            "SELECT id FROM trainer_clients WHERE trainer_id = %s AND client_id = %s",
            (current_user_id, client_id)
        )
        if not cursor.fetchone():
            return jsonify({'error': 'Клиент не найден или не является вашим подопечным'}), 403

        # Get meals (standalone, not from plan days)
        cursor.execute("""
            SELECT meal_id, name, meal_time, from_plan_id
            FROM meal
            WHERE user_id = %s
            AND meal_id NOT IN (SELECT meal_id FROM meal_meal_plan_day)
            ORDER BY meal_time
        """, (client_id,))
        meals = cursor.fetchall()

        for meal in meals:
            if meal['meal_time']:
                utc_str = meal['meal_time'].strftime('%Y-%m-%d %H:%M:%S')
                meal['mealTime'] = convert_from_utc(utc_str)
            else:
                meal['mealTime'] = ''
            cursor.execute("""
                SELECT mc.product_id, mc.weight,
                       p.product_name, p.proteins, p.fats, p.carbs, p.calories
                FROM meal_component mc
                JOIN meal_meal_component mmc ON mc.meal_meal_component_id = mmc.id
                JOIN products p ON p.product_id = mc.product_id
                WHERE mmc.meal_id = %s
            """, (meal['meal_id'],))
            raw_components = cursor.fetchall()
            meal['components'] = [
                {
                    'product_id': c['product_id'],
                    'weight': c['weight'],
                    'product_name': c['product_name'],
                    'proteins': float(c['proteins'] or 0),
                    'fats': float(c['fats'] or 0),
                    'carbs': float(c['carbs'] or 0),
                    'calories': float(c['calories'] or 0)
                }
                for c in raw_components
            ]

        # Get active meal plan targets
        target_calories = 0.0
        target_protein_g = 0.0
        target_fats_g = 0.0
        target_carbs_g = 0.0

        cursor.execute("""
            SELECT mp.target_calories, mp.protein_pct, mp.fats_pct, mp.carbs_pct
            FROM user_meal_plan ump
            JOIN meal_plan_user_meal_plan mpump ON mpump.user_meal_plan_id = ump.id
            JOIN meal_plan mp ON mp.plan_id = mpump.meal_plan_id
            WHERE ump.user_id = %s AND ump.ended_at IS NULL
            ORDER BY ump.started_at DESC LIMIT 1
        """, (client_id,))
        active_plan = cursor.fetchone()

        if active_plan and active_plan['target_calories']:
            cal = float(active_plan['target_calories'])
            target_calories = cal
            target_protein_g = round(cal * float(active_plan['protein_pct'] or 0) / 100 / 4, 1)
            target_fats_g = round(cal * float(active_plan['fats_pct'] or 0) / 100 / 9, 1)
            target_carbs_g = round(cal * float(active_plan['carbs_pct'] or 0) / 100 / 4, 1)

        # Calculate actual totals from today's meals
        actual_calories = 0.0
        actual_protein_g = 0.0
        actual_fats_g = 0.0
        actual_carbs_g = 0.0

        cursor.execute("""
            SELECT mc.product_id, mc.weight
            FROM meal m
            JOIN meal_meal_component mmc ON mmc.meal_id = m.meal_id
            JOIN meal_component mc ON mc.meal_meal_component_id = mmc.id
            WHERE m.user_id = %s
            AND DATE(m.meal_time) = CURDATE()
        """, (client_id,))
        today_comps = cursor.fetchall()

        for comp in today_comps:
            cursor.execute(
                "SELECT calories, proteins, fats, carbs FROM products WHERE product_id = %s",
                (comp['product_id'],)
            )
            prod = cursor.fetchone()
            if prod and comp['weight']:
                w = float(comp['weight']) / 100.0
                actual_calories += float(prod['calories'] or 0) * w
                actual_protein_g += float(prod['proteins'] or 0) * w
                actual_fats_g += float(prod['fats'] or 0) * w
                actual_carbs_g += float(prod['carbs'] or 0) * w

        return jsonify({
            'meals': meals,
            'target_calories': round(target_calories, 1),
            'target_protein_g': round(target_protein_g, 1),
            'target_fats_g': round(target_fats_g, 1),
            'target_carbs_g': round(target_carbs_g, 1),
            'actual_calories': round(actual_calories, 1),
            'actual_protein_g': round(actual_protein_g, 1),
            'actual_fats_g': round(actual_fats_g, 1),
            'actual_carbs_g': round(actual_carbs_g, 1),
        }), 200
    except mysql.connector.Error as err:
        return jsonify({'error': str(err)}), 400
    finally:
        cursor.close()
        conn.close()


@app.route('/user/trainer-request', methods=['POST'])
@token_required
def send_trainer_request(current_user_id):
    data = request.get_json(silent=True) or {}
    trainer_id = data.get('trainer_id')
    if not trainer_id:
        return jsonify({'error': 'trainer_id обязателен'}), 400

    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    conn.autocommit = False
    try:
        # Verify trainer exists and has trainer role
        cursor.execute("SELECT user_id, user_role FROM users WHERE user_id = %s", (trainer_id,))
        trainer = cursor.fetchone()
        if not trainer or trainer['user_role'] < 2:
            return jsonify({'error': 'Тренер не найден'}), 404

        # Check for existing request
        cursor.execute(
            "SELECT id, status FROM trainer_requests WHERE trainer_id = %s AND user_id = %s",
            (trainer_id, current_user_id)
        )
        existing = cursor.fetchone()
        if existing:
            if existing['status'] == 'pending':
                return jsonify({'error': 'Заявка уже отправлена'}), 409
            elif existing['status'] == 'accepted':
                return jsonify({'error': 'Вы уже являетесь клиентом этого тренера'}), 409
            else:
                # rejected — allow re-request by updating status
                cursor.execute(
                    "UPDATE trainer_requests SET status = 'pending', created_at = NOW() WHERE id = %s",
                    (existing['id'],)
                )
        else:
            cursor.execute(
                "INSERT INTO trainer_requests (trainer_id, user_id, status) VALUES (%s, %s, 'pending')",
                (trainer_id, current_user_id)
            )
        conn.commit()
        return jsonify({'message': 'Заявка тренеру отправлена'}), 200
    except mysql.connector.Error as err:
        conn.rollback()
        return jsonify({'error': str(err)}), 400
    finally:
        cursor.close()
        conn.close()


@app.route('/user/fcm-token', methods=['POST'])
@token_required
def save_fcm_token(current_user_id):
    data = request.get_json(silent=True) or {}
    fcm_token = data.get('fcm_token', '').strip()
    if not fcm_token:
        return jsonify({'error': 'fcm_token обязателен'}), 400

    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO user_fcm_tokens (user_id, fcm_token)
            VALUES (%s, %s) AS new_val
            ON DUPLICATE KEY UPDATE fcm_token = new_val.fcm_token, updated_at = NOW()
        """, (current_user_id, fcm_token))
        conn.commit()
        print(f"[FCM] token saved for user_id={current_user_id}, rows affected={cursor.rowcount}")
        return jsonify({'message': 'FCM-токен сохранён'}), 200
    except mysql.connector.Error as err:
        conn.rollback()
        print(f"[FCM] save_fcm_token MySQL error for user_id={current_user_id}: {err}")
        return jsonify({'error': str(err)}), 400
    finally:
        cursor.close()
        conn.close()


@app.route('/trainers', methods=['GET'])
@token_required
def get_trainers(current_user_id):
    """Возвращает список тренеров (user_role >= 2).
    Доступен любому авторизованному пользователю.
    Для каждого тренера возвращает количество принятых клиентов.
    """
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT
                u.user_id,
                u.username,
                u.email,
                COUNT(tr.id) AS clients_count
            FROM users u
            LEFT JOIN trainer_requests tr
                ON tr.trainer_id = u.user_id AND tr.status = 'accepted'
            WHERE u.user_role >= 2
            GROUP BY u.user_id, u.username, u.email
            ORDER BY u.username ASC
        """)
        trainers = cursor.fetchall()
        return jsonify({'trainers': trainers}), 200
    except mysql.connector.Error as err:
        return jsonify({'error': str(err)}), 400
    finally:
        cursor.close()
        conn.close()


if __name__ == '__main__':
    init_symspell()
    app.run(host='0.0.0.0', port=5000, debug=True)
