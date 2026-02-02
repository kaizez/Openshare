-- Create auth database if not exists
CREATE DATABASE IF NOT EXISTS auth_db;
CREATE DATABASE IF NOT EXISTS siem_db;

-- Grant permissions
GRANT ALL PRIVILEGES ON auth_db.* TO 'root'@'%';
GRANT ALL PRIVILEGES ON siem_db.* TO 'root'@'%';
FLUSH PRIVILEGES;
