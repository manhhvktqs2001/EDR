"""
EDR Server Configuration
Cấu hình toàn bộ server EDR - COMPLETE VERSION
"""

import os
import logging
from pathlib import Path
from typing import Dict, Any

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("Warning: python-dotenv not installed, using environment variables only")

# Base directory
BASE_DIR = Path(__file__).parent.absolute()

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
    'server': os.getenv('DB_SERVER', 'localhost'),
    'database': os.getenv('DB_NAME', 'EDR_System'),
    'driver': os.getenv('DB_DRIVER', 'ODBC Driver 17 for SQL Server'),
    'timeout': int(os.getenv('DB_TIMEOUT', 30)),
    'autocommit': os.getenv('DB_AUTOCOMMIT', 'true').lower() == 'true'
}

# Logging Configuration
LOGGING_CONFIG = {
    'level': getattr(logging, os.getenv('LOG_LEVEL', 'INFO').upper()),
    'format': '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    'file': os.getenv('LOG_FILE', 'logs/server.log'),
    'max_size_mb': int(os.getenv('LOG_MAX_SIZE_MB', 100)),
    'backup_count': int(os.getenv('LOG_BACKUP_COUNT', 5))
}

# SocketIO Configuration
SOCKETIO_CONFIG = {
    'async_mode': 'threading',
    'cors_allowed_origins': os.getenv('CORS_ORIGINS', '*'),
    'ping_timeout': int(os.getenv('PING_TIMEOUT', 60)),
    'ping_interval': int(os.getenv('PING_INTERVAL', 25))
}

# Performance Settings
PERFORMANCE_CONFIG = {
    'max_concurrent_agents': int(os.getenv('MAX_CONCURRENT_AGENTS', 1000)),
    'log_batch_size': int(os.getenv('LOG_BATCH_SIZE', 50)),
    'database_timeout': int(os.getenv('DATABASE_TIMEOUT', 30)),
    'socket_timeout': int(os.getenv('SOCKET_TIMEOUT', 60))
}

# Alert Configuration
ALERT_CONFIG = {
    'max_alerts_per_minute': int(os.getenv('MAX_ALERTS_PER_MINUTE', 100)),
    'alert_retention_days': int(os.getenv('ALERT_RETENTION_DAYS', 30)),
    'notification_timeout': int(os.getenv('NOTIFICATION_TIMEOUT', 15))
}

# Rule Engine Configuration
RULE_ENGINE_CONFIG = {
    'refresh_interval': int(os.getenv('RULE_REFRESH_INTERVAL', 60)),
    'max_rules_cache': int(os.getenv('MAX_RULES_CACHE', 1000))
}

# Security Configuration
SECURITY_CONFIG = {
    'agent_token_expiry': 3600,  # 1 hour
    'max_login_attempts': 5,
    'rate_limit_requests': 100,
    'rate_limit_window': 3600,  # 1 hour
    'require_agent_auth': True
}

# CORS Configuration
CORS_CONFIG = {
    'origins': os.getenv('CORS_ORIGINS', '*').split(','),
    'methods': os.getenv('CORS_METHODS', 'GET,POST,PUT,DELETE,OPTIONS').split(','),
    'headers': os.getenv('CORS_HEADERS', 'Content-Type,Authorization').split(',')
}

# Agent specific configurations
AGENT_CONFIG = {
    'heartbeat_interval': 30,  # seconds
    'log_batch_size': 50,
    'log_send_interval': 60,  # seconds
    'monitoring_enabled': True,
    'default_rules': [1, 2, 3, 4, 5],  # Default rule IDs to assign to new agents
    'max_reconnect_attempts': 5,
    'reconnect_delay': 10  # seconds
}

# Severity levels with priority scores
SEVERITY_LEVELS = {
    'Critical': {'priority': 4, 'color': '#dc3545'},
    'High': {'priority': 3, 'color': '#fd7e14'},
    'Medium': {'priority': 2, 'color': '#ffc107'},
    'Low': {'priority': 1, 'color': '#28a745'},
    'Info': {'priority': 0, 'color': '#17a2b8'}
}

def get_database_connection_string():
    """Get database connection string"""
    return (
        f"DRIVER={{{DATABASE_CONFIG['driver']}}};"
        f"SERVER={DATABASE_CONFIG['server']};"
        f"DATABASE={DATABASE_CONFIG['database']};"
        f"Trusted_Connection=yes;"
        f"Connection Timeout={DATABASE_CONFIG['timeout']};"
    )

def validate_configuration():
    """Validate configuration settings"""
    errors = []
    
    # Check required database settings
    if not DATABASE_CONFIG['server']:
        errors.append("Database server is required")
    
    if not DATABASE_CONFIG['database']:
        errors.append("Database name is required")
    
    # Check required security settings
    if SERVER_SETTINGS['secret_key'] == 'edr_secret_key_2024_change_in_production':
        errors.append("Please change the default secret key in production")
    
    # Create required directories
    required_dirs = [
        'logs',
        'uploads',
        'backups'
    ]
    
    for directory in required_dirs:
        Path(directory).mkdir(parents=True, exist_ok=True)
    
    return errors

def get_config_summary():
    """Get configuration summary for debugging"""
    return {
        'server': {
            'host': SERVER_SETTINGS['host'],
            'port': SERVER_SETTINGS['port'],
            'debug': SERVER_SETTINGS['debug']
        },
        'database': {
            'server': DATABASE_CONFIG['server'],
            'database': DATABASE_CONFIG['database']
        },
        'logging': {
            'level': logging.getLevelName(LOGGING_CONFIG['level']),
            'file': LOGGING_CONFIG['file']
        }
    }

# Export all configurations
__all__ = [
    'SERVER_SETTINGS', 'DATABASE_CONFIG', 'LOGGING_CONFIG', 'SOCKETIO_CONFIG',
    'PERFORMANCE_CONFIG', 'ALERT_CONFIG', 'RULE_ENGINE_CONFIG', 
    'SECURITY_CONFIG', 'CORS_CONFIG', 'AGENT_CONFIG', 'SEVERITY_LEVELS',
    'get_database_connection_string', 'validate_configuration', 'get_config_summary'
]