"""
FCM (Firebase Cloud Messaging) utilities.

Отправка push-уведомлений пользователям через Firebase Admin SDK.
"""

import os
import logging

logger = logging.getLogger(__name__)

_firebase_initialized = False


def _init_firebase():
    global _firebase_initialized
    if _firebase_initialized:
        return True
    try:
        import firebase_admin
        from firebase_admin import credentials

        service_account_path = os.getenv('FIREBASE_SERVICE_ACCOUNT_JSON')
        if not service_account_path or not os.path.exists(service_account_path):
            logger.warning(
                "FIREBASE_SERVICE_ACCOUNT_JSON не задан или файл не найден — "
                "FCM-уведомления отключены"
            )
            return False

        cred = credentials.Certificate(service_account_path)
        firebase_admin.initialize_app(cred)
        _firebase_initialized = True
        logger.info("Firebase Admin SDK инициализирован")
        return True
    except Exception as e:
        logger.error(f"Ошибка инициализации Firebase: {e}")
        return False


def send_fcm_notification(fcm_token: str, title: str, body: str, data: dict = None) -> bool:
    """
    Отправляет FCM-уведомление на указанный токен.

    :param fcm_token: FCM-токен устройства получателя
    :param title:     Заголовок уведомления
    :param body:      Текст уведомления
    :param data:      Дополнительные данные (словарь строк), например {"deeplink": "..."}
    :return:          True если успешно, False в противном случае
    """
    if not _init_firebase():
        return False

    try:
        from firebase_admin import messaging

        msg = messaging.Message(
            # Только data — без notification блока.
            # Так onMessageReceived вызывается всегда (и в фоне, и на переднем плане).
            # Сервис AppFirebaseMessagingService сам строит и показывает уведомление.
            data={
                'title': title,
                'body': body,
                **{k: str(v) for k, v in (data or {}).items()}
            },
            token=fcm_token,
            android=messaging.AndroidConfig(
                priority='high',
            )
        )
        response = messaging.send(msg)
        print(f"[FCM] sent: {response}")
        return True
    except Exception as e:
        print(f"[FCM] send error: {e}")
        return False


def get_user_fcm_token(cursor, user_id: int) -> str | None:
    """Возвращает FCM-токен пользователя из БД или None."""
    try:
        cursor.execute(
            "SELECT fcm_token FROM user_fcm_tokens WHERE user_id = %s",
            (user_id,)
        )
        row = cursor.fetchone()
        if not row:
            print(f"[FCM] no token row found for user_id={user_id}")
            return None
        token = row['fcm_token'] if isinstance(row, dict) else row[0]
        print(f"[FCM] token for user_id={user_id}: {'present (' + str(len(token)) + ' chars)' if token else 'EMPTY'}")
        return token if token else None
    except Exception as e:
        print(f"[FCM] get_user_fcm_token error for user_id={user_id}: {e}")
        return None
