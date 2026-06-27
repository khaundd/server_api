-- Таблица для хранения отдельных подходов активной тренировки
CREATE TABLE IF NOT EXISTS `training_sets` (
  `id`          INT NOT NULL AUTO_INCREMENT,
  `training_id` INT NOT NULL,
  `exercise_id` INT NOT NULL,
  `set_number`  INT NOT NULL,
  `weight_kg`   DECIMAL(6,2) DEFAULT NULL,
  `reps`        INT DEFAULT NULL,
  `duration_sec` INT DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_ts_training` (`training_id`),
  KEY `fk_ts_exercise` (`exercise_id`),
  CONSTRAINT `fk_ts_training` FOREIGN KEY (`training_id`) REFERENCES `training` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_ts_exercise` FOREIGN KEY (`exercise_id`) REFERENCES `exercises` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
