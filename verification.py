from flask import jsonify
import mysql.connector
from datetime import datetime
from utils import db_config

def verify_email_code(email: str, code: str):
    """Проверяет код подтверждения и активирует пользователя после подтверждения email.
    
    Args:
        email: Email пользователя
        code: Введенный код подтверждения
    
    Returns:
        tuple: (success: bool, response: dict, status_code: int)
    """
    conn = None
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        
        # Проверяем данные во временной таблице
        query = """SELECT username, hashed_password, height, bodyweight, age FROM temp_registrations 
                   WHERE email = %s AND code = %s AND expires_at > NOW()"""
        cursor.execute(query, (email, code))
        result = cursor.fetchone()
        
        if not result:
            return False, {'error': 'Неверный или просроченный код подтверждения'}, 400
        
        username, password, height, bodyweight, age = result
        
        # Вставляем пользователя в основную таблицу
        insert_query = """INSERT INTO users (username, hashed_password, email, height, bodyweight, age) 
                          VALUES (%s, %s, %s, %s, %s, %s)"""
        cursor.execute(insert_query, (username, password, email, height, bodyweight, age))
        
        # Удаляем временную запись
        delete_query = "DELETE FROM temp_registrations WHERE email = %s"
        cursor.execute(delete_query, (email,))
        
        conn.commit()
        
        return True, {'message': 'Email успешно подтвержден. Регистрация завершена.'}, 200
        
    except mysql.connector.Error as err:
        return False, {'error': f'Ошибка базы данных: {err}'}, 500
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()