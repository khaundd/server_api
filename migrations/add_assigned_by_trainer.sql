-- Миграция: добавляет поле assigned_by_trainer_id в таблицы назначений планов
-- MySQL 5.7+ / 8.0
-- Выполнить один раз при деплое

-- Таблица тренировочных планов
ALTER TABLE active_training_plans
    ADD COLUMN assigned_by_trainer_id INT NULL DEFAULT NULL,
    ADD CONSTRAINT fk_atp_trainer
        FOREIGN KEY (assigned_by_trainer_id)
        REFERENCES users(user_id)
        ON DELETE SET NULL;

-- Таблица планов питания
ALTER TABLE user_meal_plan
    ADD COLUMN assigned_by_trainer_id INT NULL DEFAULT NULL,
    ADD CONSTRAINT fk_ump_trainer
        FOREIGN KEY (assigned_by_trainer_id)
        REFERENCES users(user_id)
        ON DELETE SET NULL;
