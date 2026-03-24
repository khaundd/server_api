import json
import mysql.connector
from mysql.connector import Error
from config import Config

# ─── Настройки подключения ───────────────────────────────────────────────────
DB_CONFIG = Config.get_db_config()

JSON_FILE = "products.json"   # путь к файлу с данными

INSERT_SQL = """
    INSERT INTO products (product_name, proteins, fats, carbs)
    VALUES (%s, %s, %s, %s) as new
    ON DUPLICATE KEY UPDATE
        proteins = new.proteins,
        fats     = new.fats,
        carbs    = new.carbs
"""

# ─── Основная логика ─────────────────────────────────────────────────────────
def main():
    # Читаем JSON
    with open(JSON_FILE, encoding="utf-8") as f:
        products = json.load(f)

    print(f"Загружено продуктов из файла: {len(products)}")

    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        inserted = 0
        updated  = 0
        errors   = 0

        for product in products:
            try:
                cursor.execute(INSERT_SQL, (
                    product["product_name"],
                    product["proteins"],
                    product["fats"],
                    product["carbs"],
                ))
                # rowcount == 1 — вставка, == 2 — обновление (ON DUPLICATE KEY)
                if cursor.rowcount == 1:
                    inserted += 1
                else:
                    updated += 1
            except Error as e:
                print(f"  [ОШИБКА] '{product.get('product_name')}': {e}")
                errors += 1

        conn.commit()
        print(f"\nГотово:")
        print(f"  Вставлено : {inserted}")
        print(f"  Обновлено : {updated}")
        print(f"  Ошибок    : {errors}")

    except Error as e:
        print(f"Ошибка подключения к БД: {e}")
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()
            print("Соединение с БД закрыто.")


if __name__ == "__main__":
    main()