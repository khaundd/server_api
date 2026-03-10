import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    DB_USER = os.getenv('DB_USER')
    DB_PASSWORD = os.getenv('DB_PASSWORD')
    DB_HOST = os.getenv('DB_HOST')
    DB_NAME = os.getenv('DB_NAME')

    @staticmethod
    def get_db_config():
        return {
            'user': Config.DB_USER,
            'password': Config.DB_PASSWORD,
            'host': Config.DB_HOST,
            'database': Config.DB_NAME,
            'raise_on_warnings': True
        }