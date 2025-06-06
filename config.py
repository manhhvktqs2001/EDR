"""
EDR Server Configuration
Cấu hình chính cho EDR Server
"""

import os
import logging
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Server Settings
SERVER_SETTINGS = {
    'host': os.getenv('SERVER_HOST', '0.0.0.0'),
    'port': int(os.getenv('SERVER_PORT', 5000)),
    'debug': os.getenv('SERVER_DEBUG', 'false').lower() == 'true',
    'secret_key': os.getenv('SECRET_KEY', 'edr_secret_key_2024_change_in_production'),
    'jwt_secret': os.getenv('JWT_SECRET_KEY', 'jwt_secret_key_change_in_production')
}

# Database Configuration
DATABASE_CONFIG = {
    'server': os.getenv('DB_SERVER', 'MANH'),
    'database': os.getenv('DB_NAME', 'EDR_System'),
    'driver': os.getenv('DB_DRIVER', 'ODBC Driver 17 for SQL Server'),
    'trusted_connection': True,
    'timeout': int(os.getenv('DB_TIMEOUT', 30)),
    'autocommit': os.getenv('DB_AUTOCOMMIT', 'true').lower() == 'true',
    'pool_size': 20,
    'max_overflow': 30
}

# Logging Configuration
LOGGING_CONFIG = {
    'level': getattr(logging, os.getenv('LOG_LEVEL', 'INFO').upper()),
    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    'file': os.getenv('LOG_FILE', 'logs/server.log'),
    'max_size_mb': int(os.getenv('LOG_MAX_SIZE_MB', 100)),
    'backup_count': int(os.getenv('LOG_BACKUP_COUNT', 5))
}

# Performance Settings
PERFORMANCE_CONFIG = {
    'max_concurrent_agents': int(os.getenv('MAX_CONCURRENT_AGENTS', 1000)),
    'log_batch_size': int(os.getenv('LOG_BATCH_SIZE', 50)),
    'database_timeout': int(os.getenv('DATABASE_TIMEOUT', 30)),
    'socket_timeout': int(os.getenv('SOCKET_TIMEOUT', 60)),
    'ping_interval': int(os.getenv('PING_INTERVAL', 25)),
    'ping_timeout': int(os.getenv('PING_TIMEOUT', 60))
}

# Alert Configuration
ALERT_CONFIG = {
    'max_alerts_per_minute': int(os.getenv('MAX_ALERTS_PER_MINUTE', 100)),
    'alert_retention_days': int(os.getenv('ALERT_RETENTION_DAYS', 30)),
    'notification_timeout': int(os.getenv('NOTIFICATION_TIMEOUT', 15)),
    'auto_resolve_days': 7,
    'escalation_threshold': 5
}

# Rule Engine Configuration
RULE_ENGINE_CONFIG = {
    'refresh_interval': int(os.getenv('RULE_REFRESH_INTERVAL', 60)),
    'max_rules_cache': int(os.getenv('MAX_RULES_CACHE', 1000)),
    'rule_timeout': 30,
    'parallel_processing': True
}

# CORS Configuration
CORS_CONFIG = {
    'origins': os.getenv('CORS_ORIGINS', '*'),
    'methods': os.getenv('CORS_METHODS', 'GET,POST,PUT,DELETE,OPTIONS'),
    'headers': os.getenv('CORS_HEADERS', 'Content-Type,Authorization')
}

# File Upload Configuration
UPLOAD_CONFIG = {
    'max_content_length': int(os.getenv('MAX_CONTENT_LENGTH', 16777216)),  # 16MB
    'upload_folder': os.getenv('UPLOAD_FOLDER', 'uploads'),
    'allowed_extensions': os.getenv('ALLOWED_EXTENSIONS', 'txt,log,csv,json').split(',')
}

# Security Configuration
SECURITY_CONFIG = {
    'enable_rate_limiting': True,
    'rate_limit_per_minute': 100,
    'enable_auth': False,  # Tạm thời tắt để test
    'session_timeout': 3600,
    'max_login_attempts': 5
}

# Agent Configuration
AGENT_CONFIG = {
    'heartbeat_interval': 30,
    'offline_threshold': 300,  # 5 minutes
    'max_log_batch': 100,
    'compression_enabled': True,
    'encryption_enabled': False  # Tạm thời tắt để test
}

# Dashboard Configuration  
DASHBOARD_CONFIG = {
    'refresh_interval': 30,
    'max_chart_points': 100,
    'default_time_range': 24,  # hours
    'enable_real_time': True
}

# Backup Configuration
BACKUP_CONFIG = {
    'enabled': os.getenv('BACKUP_ENABLED', 'true').lower() == 'true',
    'schedule': os.getenv('BACKUP_SCHEDULE', '0 2 * * *'),  # Daily at 2 AM
    'retention_days': int(os.getenv('BACKUP_RETENTION_DAYS', 30)),
    'path': os.getenv('BACKUP_PATH', 'backups')
}

# Email Configuration (cho notifications)
EMAIL_CONFIG = {
    'smtp_server': os.getenv('SMTP_SERVER', 'smtp.gmail.com'),
    'smtp_port': int(os.getenv('SMTP_PORT', 587)),
    'username': os.getenv('SMTP_USERNAME', ''),
    'password': os.getenv('SMTP_PASSWORD', ''),
    'use_tls': os.getenv('SMTP_USE_TLS', 'true').lower() == 'true',
    'from_email': os.getenv('EMAIL_FROM', 'edr-system@company.com')
}

# Webhook Configuration
WEBHOOK_CONFIG = {
    'url': os.getenv('WEBHOOK_URL', ''),
    'secret': os.getenv('WEBHOOK_SECRET', ''),
    'timeout': 30,
    'retry_count': 3
}

# Development Settings
DEV_CONFIG = {
    'mode': os.getenv('DEV_MODE', 'true').lower() == 'true',
    'hot_reload': os.getenv('DEV_HOT_RELOAD', 'true').lower() == 'true',
    'mock_data': os.getenv('DEV_MOCK_DATA', 'false').lower() == 'true',
    'debug_sql': False
}

# Testing Configuration
TEST_CONFIG = {
    'database': os.getenv('TEST_DATABASE', 'EDR_System_Test'),
    'timeout': int(os.getenv('TEST_TIMEOUT', 30)),
    'mock_agents': True
}

def get_database_url():
    """Get database connection URL"""
    config = DATABASE_CONFIG
    if config.get('trusted_connection'):
        return f"mssql+pyodbc://{config['server']}/{config['database']}?driver={config['driver']}&trusted_connection=yes"
    else:
        return f"mssql+pyodbc://{config.get('username', '')}:{config.get('password', '')}@{config['server']}/{config['database']}?driver={config['driver']}"

def validate_config():
    """Validate configuration settings"""
    errors = []
    
    # Check required database settings
    if not DATABASE_CONFIG['server']:
        errors.append("Database server not configured")
    
    if not DATABASE_CONFIG['database']:
        errors.append("Database name not configured")
    
    # Check log directory
    log_dir = os.path.dirname(LOGGING_CONFIG['file'])
    if log_dir and not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir, exist_ok=True)
        except Exception as e:
            errors.append(f"Cannot create log directory: {e}")
    
    # Check upload directory
    upload_dir = UPLOAD_CONFIG['upload_folder']
    if not os.path.exists(upload_dir):
        try:
            os.makedirs(upload_dir, exist_ok=True)
        except Exception as e:
            errors.append(f"Cannot create upload directory: {e}")
    
    # Validate ports
    if not (1 <= SERVER_SETTINGS['port'] <= 65535):
        errors.append("Invalid server port")
    
    return errors

def print_config_summary():
    """Print configuration summary"""
    print("="*60)
    print("🔧 EDR SERVER CONFIGURATION")
    print("="*60)
    print(f"Server: {SERVER_SETTINGS['host']}:{SERVER_SETTINGS['port']}")
    print(f"Database: {DATABASE_CONFIG['server']}/{DATABASE_CONFIG['database']}")
    print(f"Log Level: {logging.getLevelName(LOGGING_CONFIG['level'])}")
    print(f"Log File: {LOGGING_CONFIG['file']}")
    print(f"Debug Mode: {SERVER_SETTINGS['debug']}")
    print(f"Development Mode: {DEV_CONFIG['mode']}")
    print(f"Max Agents: {PERFORMANCE_CONFIG['max_concurrent_agents']}")
    print(f"Rule Engine: Refresh every {RULE_ENGINE_CONFIG['refresh_interval']}s")
    print("="*60)

# Export configuration objects
__all__ = [
    'SERVER_SETTINGS',
    'DATABASE_CONFIG', 
    'LOGGING_CONFIG',
    'PERFORMANCE_CONFIG',
    'ALERT_CONFIG',
    'RULE_ENGINE_CONFIG',
    'CORS_CONFIG',
    'UPLOAD_CONFIG',
    'SECURITY_CONFIG',
    'AGENT_CONFIG',
    'DASHBOARD_CONFIG',
    'get_database_url',
    'validate_config',
    'print_config_summary'
]