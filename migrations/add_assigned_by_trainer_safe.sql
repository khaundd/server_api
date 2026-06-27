-- Безопасная версия миграции (идемпотентная) для MySQL
-- Проверяет наличие колонок через INFORMATION_SCHEMA перед добавлением

DROP PROCEDURE IF EXISTS add_assigned_by_trainer_columns;

DELIMITER $$

CREATE PROCEDURE add_assigned_by_trainer_columns()
BEGIN
    -- active_training_plans
    IF NOT EXISTS (
        SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME   = 'active_training_plans'
          AND COLUMN_NAME  = 'assigned_by_trainer_id'
    ) THEN
        ALTER TABLE active_training_plans
            ADD COLUMN assigned_by_trainer_id INT NULL DEFAULT NULL,
            ADD CONSTRAINT fk_atp_trainer
                FOREIGN KEY (assigned_by_trainer_id)
                REFERENCES users(user_id)
                ON DELETE SET NULL;
    END IF;

    -- user_meal_plan
    IF NOT EXISTS (
        SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME   = 'user_meal_plan'
          AND COLUMN_NAME  = 'assigned_by_trainer_id'
    ) THEN
        ALTER TABLE user_meal_plan
            ADD COLUMN assigned_by_trainer_id INT NULL DEFAULT NULL,
            ADD CONSTRAINT fk_ump_trainer
                FOREIGN KEY (assigned_by_trainer_id)
                REFERENCES users(user_id)
                ON DELETE SET NULL;
    END IF;
END$$

DELIMITER ;

CALL add_assigned_by_trainer_columns();

DROP PROCEDURE IF EXISTS add_assigned_by_trainer_columns;
