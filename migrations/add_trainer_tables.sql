-- Trainer-User request/relationship tables
CREATE TABLE IF NOT EXISTS trainer_requests (
    id INT NOT NULL AUTO_INCREMENT,
    trainer_id INT NOT NULL,
    user_id INT NOT NULL,
    status VARCHAR(10) NOT NULL DEFAULT 'pending',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_trainer_user (trainer_id, user_id),
    CONSTRAINT fk_tr_trainer FOREIGN KEY (trainer_id) REFERENCES users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_tr_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS trainer_clients (
    id INT NOT NULL AUTO_INCREMENT,
    trainer_id INT NOT NULL,
    client_id INT NOT NULL,
    assigned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_trainer_client (trainer_id, client_id),
    CONSTRAINT fk_tc_trainer FOREIGN KEY (trainer_id) REFERENCES users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_tc_client FOREIGN KEY (client_id) REFERENCES users(user_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS user_fcm_tokens (
    user_id INT NOT NULL,
    fcm_token VARCHAR(512) NOT NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id),
    CONSTRAINT fk_fcm_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
