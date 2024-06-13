-- Sélectionner la base de données si nécessaire
USE passkeys;

-- Créer la table "users" si elle n'existe pas
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Créer la table "users_passkeys" si elle n'existe pas
/*CREATE TABLE IF NOT EXISTS users_passkeys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(255),
    email VARCHAR(255),
    public_key TEXT,
    credential_id VARCHAR(255),
    challege TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
*/

CREATE TABLE users_passkeys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(255),
    credential_id BINARY(32) PRIMARY KEY,
    public_key BLOB NOT NULL,
    attestation_type VARCHAR(255),
    transport JSON,
    user_present BOOLEAN,
    user_verified BOOLEAN,
    backup_eligible BOOLEAN,
    backup_state BOOLEAN,
    aaguid BINARY(16),
    sign_count INT,
    attachment VARCHAR(255)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

