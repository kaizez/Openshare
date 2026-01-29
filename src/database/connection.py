"""
MySQL database connection management for SIEM system.
"""

import mysql.connector
from mysql.connector import Error
from typing import Optional
import os

# Database configuration
DB_CONFIG = {
    'host': os.getenv('MYSQL_HOST', 'localhost'),
    'port': int(os.getenv('MYSQL_PORT', '3306')),
    'user': os.getenv('MYSQL_USER', 'root'),
    'password': os.getenv('MYSQL_PASSWORD', 'your_secure_password'),
    'database': os.getenv('MYSQL_DATABASE', 'siem_db'),
    'autocommit': False,
    'charset': 'utf8mb4',
    'collation': 'utf8mb4_unicode_ci'
}


def get_db_connection():
    """
    Get a MySQL database connection.
    
    Returns:
        mysql.connector.connection.MySQLConnection: Database connection object
        
    Raises:
        Error: If connection fails
    """
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        if connection.is_connected():
            return connection
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        raise


def init_database():
    """
    Initialize database tables if they don't exist.
    Creates all required tables for SIEM, SOAR, and user management.
    """
    connection = None
    cursor = None
    
    try:
        # Connect without database first to create it if needed
        config_without_db = {k: v for k, v in DB_CONFIG.items() if k != 'database'}
        connection = mysql.connector.connect(**config_without_db)
        cursor = connection.cursor()
        
        # Create database if it doesn't exist
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_CONFIG['database']} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        connection.commit()
        cursor.close()
        connection.close()
        
        # Now connect to the database
        connection = get_db_connection()
        cursor = connection.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP NULL,
                INDEX idx_username (username)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ''')
        
        # Create security_logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_logs (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                log_source VARCHAR(255) NOT NULL,
                event_type VARCHAR(255) NOT NULL,
                description TEXT NOT NULL,
                severity ENUM('Critical', 'High', 'Medium', 'Low', 'Info') NOT NULL DEFAULT 'Info',
                user_id VARCHAR(255),
                ip_address VARCHAR(45),
                file_name VARCHAR(500),
                user_role VARCHAR(100),
                file_size BIGINT,
                result VARCHAR(50),
                INDEX idx_timestamp (timestamp),
                INDEX idx_event_type (event_type),
                INDEX idx_severity (severity),
                INDEX idx_user_id (user_id),
                INDEX idx_ip_address (ip_address)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ''')
        
        # Create quarantined_ips table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS quarantined_ips (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ip_address VARCHAR(45) NOT NULL UNIQUE,
                quarantined_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                released_at TIMESTAMP NULL,
                status ENUM('quarantined', 'released') NOT NULL DEFAULT 'quarantined',
                reason TEXT,
                alerted_by VARCHAR(255),
                action_taken_by VARCHAR(255),
                INDEX idx_ip_address (ip_address),
                INDEX idx_status (status)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ''')
        
        # Create active_sessions table for session management
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS active_sessions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                session_id VARCHAR(255) NOT NULL UNIQUE,
                ip_address VARCHAR(45),
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_activity TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                status ENUM('active', 'terminated') NOT NULL DEFAULT 'active',
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_session_id (session_id),
                INDEX idx_user_id (user_id),
                INDEX idx_status (status)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ''')
        
        # Create quarantined_files table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS quarantined_files (
                id INT AUTO_INCREMENT PRIMARY KEY,
                file_name VARCHAR(500) NOT NULL,
                file_path TEXT,
                quarantined_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                released_at TIMESTAMP NULL,
                status ENUM('quarantined', 'released') NOT NULL DEFAULT 'quarantined',
                reason TEXT,
                user_id VARCHAR(255),
                ip_address VARCHAR(45),
                action_taken_by VARCHAR(255),
                INDEX idx_file_name (file_name(255)),
                INDEX idx_status (status)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ''')
        
        # Create alerts table for tracking SIEM alerts
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                alert_type VARCHAR(255) NOT NULL,
                severity ENUM('Critical', 'High', 'Medium', 'Low') NOT NULL,
                description TEXT NOT NULL,
                user_id VARCHAR(255),
                ip_address VARCHAR(45),
                file_name VARCHAR(500),
                timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                rule_triggered VARCHAR(255),
                status ENUM('new', 'acknowledged', 'resolved') NOT NULL DEFAULT 'new',
                INDEX idx_timestamp (timestamp),
                INDEX idx_severity (severity),
                INDEX idx_status (status)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ''')

        # Create API keys table for service-to-service authentication
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_keys (
                id INT AUTO_INCREMENT PRIMARY KEY,
                key_name VARCHAR(255) NOT NULL,
                api_key VARCHAR(64) NOT NULL UNIQUE,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_used TIMESTAMP NULL,
                is_active BOOLEAN DEFAULT TRUE,
                created_by VARCHAR(255),
                INDEX idx_api_key (api_key),
                INDEX idx_is_active (is_active)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ''')

        # Create honeytokens table for decoy file tracking
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS honeytokens (
                id INT AUTO_INCREMENT PRIMARY KEY,
                file_name VARCHAR(500) NOT NULL,
                file_path TEXT,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                created_by VARCHAR(255),
                is_active BOOLEAN DEFAULT TRUE,
                description TEXT,
                INDEX idx_file_name (file_name(255)),
                INDEX idx_is_active (is_active)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ''')

        # Create file_hashes table for SHA-256 integrity tracking
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_hashes (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                file_name VARCHAR(500) NOT NULL,
                file_path TEXT,
                sha256_hash VARCHAR(64) NOT NULL,
                first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                hash_changed BOOLEAN DEFAULT FALSE,
                previous_hash VARCHAR(64),
                INDEX idx_file_name (file_name(255)),
                INDEX idx_sha256_hash (sha256_hash),
                INDEX idx_hash_changed (hash_changed)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ''')

        # Create geo_cache table for IP geolocation caching
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS geo_cache (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ip_address VARCHAR(45) NOT NULL UNIQUE,
                country VARCHAR(100),
                country_code VARCHAR(10),
                city VARCHAR(255),
                latitude DECIMAL(10, 8),
                longitude DECIMAL(11, 8),
                cached_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_ip_address (ip_address)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ''')

        # Create disabled_accounts table for auto-disabled accounts
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS disabled_accounts (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id VARCHAR(255) NOT NULL,
                disabled_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                reason TEXT NOT NULL,
                disabled_by VARCHAR(255) NOT NULL,
                is_disabled BOOLEAN DEFAULT TRUE,
                re_enabled_at TIMESTAMP NULL,
                re_enabled_by VARCHAR(255),
                INDEX idx_user_id (user_id),
                INDEX idx_is_disabled (is_disabled)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ''')

        # Create blacklisted_networks table for network blocking
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blacklisted_networks (
                id INT AUTO_INCREMENT PRIMARY KEY,
                network_cidr VARCHAR(50) NOT NULL,
                description TEXT,
                added_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                added_by VARCHAR(255),
                is_active BOOLEAN DEFAULT TRUE,
                INDEX idx_network_cidr (network_cidr),
                INDEX idx_is_active (is_active)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ''')

        # Create user_baselines table for behavior tracking (30-day baseline)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_baselines (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                user_id VARCHAR(255) NOT NULL,
                date DATE NOT NULL,
                total_downloads INT DEFAULT 0,
                total_uploads INT DEFAULT 0,
                total_bytes_transferred BIGINT DEFAULT 0,
                login_count INT DEFAULT 0,
                unique_ips_used INT DEFAULT 0,
                avg_file_size BIGINT DEFAULT 0,
                UNIQUE KEY unique_user_date (user_id, date),
                INDEX idx_user_id (user_id),
                INDEX idx_date (date)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ''')

        # Create login_history table for impossible travel detection
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS login_history (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                user_id VARCHAR(255) NOT NULL,
                ip_address VARCHAR(45) NOT NULL,
                login_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                country VARCHAR(100),
                city VARCHAR(255),
                latitude DECIMAL(10, 8),
                longitude DECIMAL(11, 8),
                INDEX idx_user_id (user_id),
                INDEX idx_login_time (login_time)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ''')

        # Create dlp_alerts table for sensitive data detection
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dlp_alerts (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                file_name VARCHAR(500),
                user_id VARCHAR(255),
                ip_address VARCHAR(45),
                pattern_matched VARCHAR(100) NOT NULL,
                matched_count INT DEFAULT 1,
                severity ENUM('Critical', 'High', 'Medium', 'Low') NOT NULL,
                timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                status ENUM('new', 'reviewed', 'false_positive', 'confirmed') DEFAULT 'new',
                INDEX idx_timestamp (timestamp),
                INDEX idx_pattern_matched (pattern_matched),
                INDEX idx_status (status)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ''')
        
        connection.commit()
        print("Database initialized successfully")
        
    except Error as e:
        print(f"Error initializing database: {e}")
        if connection:
            connection.rollback()
        raise
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()
