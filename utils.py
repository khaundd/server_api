import mysql.connector
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config import Config
import os

db_config = Config.get_db_config()


def generate_verification_code():
    """Генерирует 6-значный числовой код подтверждения."""
    import random
    return str(random.randint(100000, 999999))

def store_verification_code(email: str, username: str, hashed_password: str, height: float, bodyweight: float, age: int, code: str):
    """Сохраняет данные регистрации и код подтверждения во временной таблице."""
    conn = None
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        
        # Устанавливаем время истечения кода (10 минут)
        expires_at = datetime.now() + timedelta(minutes=10)
        
        # Удаляем предыдущие данные для этого email (если есть)
        cursor.execute("DELETE FROM temp_registrations WHERE email = %s", (email,))
        
        # Вставляем новые данные регистрации
        query = """INSERT INTO temp_registrations (email, username, hashed_password, height, bodyweight, age, code, expires_at) 
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"""
        cursor.execute(query, (email, username, hashed_password, height, bodyweight, age, code, expires_at))
        conn.commit()
        
        print(f"Данные регистрации сохранены для {email}, истекают в {expires_at}")
        return True
        
    except mysql.connector.Error as err:
        print(f"Ошибка базы данных при сохранении данных регистрации: {err}")
        return False
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

def send_verification_email(email: str, code: str) -> bool:
    """Отправляет код подтверждения на указанный email.
    
    Args:
        email: Email получателя
        code: Код подтверждения
    
    Returns:
        bool: True при успешной отправке, False в случае ошибки
    """
    # Настройки SMTP-сервера загружаются из переменных окружения
    smtp_server = os.getenv('SMTP_SERVER')
    smtp_port = int(os.getenv('SMTP_PORT'))
    sender_email = os.getenv('EMAIL_USER')
    sender_password = os.getenv('EMAIL_PASSWORD')

    # Создание сообщения
    message = MIMEMultipart("alternative")
    message["Subject"] = "Код подтверждения регистрации"
    message["From"] = sender_email
    message["To"] = email

    # Текстовое и HTML-представление письма
    text = f"Привет!\nВаш код подтверждения: {code}\nКод действителен в течение 10 минут."
    html = f"""
    <html>
      <body>
        <p>Привет!</p>
        <p>Ваш код подтверждения: <strong>{code}</strong></p>
        <p>Код действителен в течение 10 минут.</p>
      </body>
    </html>
    """

    part1 = MIMEText(text, "plain")
    part2 = MIMEText(html, "html")

    message.attach(part1)
    message.attach(part2)

    # Отправка письма
    try:
        # Используем стандартный SMTP + STARTTLS
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls() # Шифруем соединение
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, email, message.as_string())
        server.quit()
        print(f"Код подтверждения отправлен на {email}")
        return True
    except Exception as e:
        print(f"Ошибка отправки email: {e}")
        return False
