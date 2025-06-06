"""
Logging configuration và setup cho EDR Server
"""

import os
import sys
import logging
import logging.handlers
from datetime import datetime
from config import LOGGING_CONFIG

def setup_logging():
    """Setup logging configuration"""
    try:
        # Create logs directory if it doesn't exist
        log_dir = os.path.dirname(LOGGING_CONFIG.get('file', 'server.log'))
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Configure root logger
        logger = logging.getLogger()
        logger.setLevel(LOGGING_CONFIG['level'])
        
        # Clear existing handlers
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
        
        # Create formatter
        formatter = logging.Formatter(
            fmt=LOGGING_CONFIG['format'],
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Console handler (stdout)
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(LOGGING_CONFIG['level'])
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        # File handler with rotation
        file_handler = logging.handlers.RotatingFileHandler(
            filename=LOGGING_CONFIG['file'],
            maxBytes=LOGGING_CONFIG.get('max_size_mb', 100) * 1024 * 1024,  # Convert MB to bytes
            backupCount=LOGGING_CONFIG.get('backup_count', 5),
            encoding='utf-8'
        )
        file_handler.setLevel(LOGGING_CONFIG['level'])
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        # Log startup message
        logger.info(f"Logging initialized - Level: {logging.getLevelName(LOGGING_CONFIG['level'])}")
        logger.info(f"Log file: {LOGGING_CONFIG['file']}")
        
        return True
        
    except Exception as e:
        print(f"Failed to setup logging: {e}")
        return False

def get_logger(name):
    """Get logger instance with name"""
    return logging.getLogger(name)

class EDRLogFilter(logging.Filter):
    """Custom log filter for EDR specific logging"""
    
    def filter(self, record):
        # Add custom fields to log record
        record.component = getattr(record, 'component', 'SERVER')
        record.agent_id = getattr(record, 'agent_id', 'N/A')
        return True

def setup_component_logger(component_name, log_file=None):
    """Setup logger for specific component"""
    try:
        logger = logging.getLogger(component_name)
        
        if log_file:
            # Create separate log file for component
            handler = logging.handlers.RotatingFileHandler(
                filename=log_file,
                maxBytes=50 * 1024 * 1024,  # 50MB
                backupCount=3,
                encoding='utf-8'
            )
            
            formatter = logging.Formatter(
                fmt=f'%(asctime)s - {component_name} - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
        
    except Exception as e:
        logging.error(f"Failed to setup component logger for {component_name}: {e}")
        return logging.getLogger(component_name)

# Pre-configured loggers for different components
def get_agent_logger():
    """Get logger for agent operations"""
    return setup_component_logger('AGENT', 'logs/agent_operations.log')

def get_rule_logger():
    """Get logger for rule engine operations"""
    return setup_component_logger('RULE_ENGINE', 'logs/rule_engine.log')

def get_alert_logger():
    """Get logger for alert operations"""
    return setup_component_logger('ALERTS', 'logs/alerts.log')

def get_database_logger():
    """Get logger for database operations"""
    return setup_component_logger('DATABASE', 'logs/database.log')

def get_socketio_logger():
    """Get logger for SocketIO operations"""
    return setup_component_logger('SOCKETIO', 'logs/socketio.log')

def log_performance(func):
    """Decorator to log function performance"""
    import time
    import functools
    
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        logger = logging.getLogger(func.__module__)
        
        try:
            result = func(*args, **kwargs)
            execution_time = (time.time() - start_time) * 1000  # Convert to milliseconds
            
            if execution_time > 1000:  # Log if execution takes more than 1 second
                logger.warning(f"Slow execution: {func.__name__} took {execution_time:.2f}ms")
            else:
                logger.debug(f"Performance: {func.__name__} took {execution_time:.2f}ms")
                
            return result
            
        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            logger.error(f"Error in {func.__name__} after {execution_time:.2f}ms: {e}")
            raise
    
    return wrapper

def log_agent_activity(hostname, activity, details=None):
    """Log agent activity with structured format"""
    logger = get_agent_logger()
    
    log_data = {
        'hostname': hostname,
        'activity': activity,
        'timestamp': datetime.now().isoformat(),
        'details': details or {}
    }
    
    logger.info(f"AGENT_ACTIVITY: {log_data}")

def log_security_event(event_type, severity, description, hostname=None, details=None):
    """Log security events with structured format"""
    logger = get_alert_logger()
    
    log_data = {
        'event_type': event_type,
        'severity': severity,
        'description': description,
        'hostname': hostname,
        'timestamp': datetime.now().isoformat(),
        'details': details or {}
    }
    
    logger.warning(f"SECURITY_EVENT: {log_data}")

def log_database_operation(operation, table, success, details=None):
    """Log database operations"""
    logger = get_database_logger()
    
    log_data = {
        'operation': operation,
        'table': table,
        'success': success,
        'timestamp': datetime.now().isoformat(),
        'details': details or {}
    }
    
    level = logging.INFO if success else logging.ERROR
    logger.log(level, f"DB_OPERATION: {log_data}")

class StructuredLogger:
    """Structured logger class for consistent logging format"""
    
    def __init__(self, component):
        self.component = component
        self.logger = logging.getLogger(component)
    
    def log_event(self, level, event_type, message, **kwargs):
        """Log structured event"""
        log_data = {
            'component': self.component,
            'event_type': event_type,
            'message': message,
            'timestamp': datetime.now().isoformat(),
            **kwargs
        }
        
        self.logger.log(level, f"STRUCTURED_LOG: {log_data}")
    
    def info(self, event_type, message, **kwargs):
        self.log_event(logging.INFO, event_type, message, **kwargs)
    
    def warning(self, event_type, message, **kwargs):
        self.log_event(logging.WARNING, event_type, message, **kwargs)
    
    def error(self, event_type, message, **kwargs):
        self.log_event(logging.ERROR, event_type, message, **kwargs)
    
    def debug(self, event_type, message, **kwargs):
        self.log_event(logging.DEBUG, event_type, message, **kwargs)

# Pre-configured structured loggers
agent_logger = StructuredLogger('AGENT')
rule_logger = StructuredLogger('RULE_ENGINE')
alert_logger = StructuredLogger('ALERTS')
db_logger = StructuredLogger('DATABASE')
socketio_logger = StructuredLogger('SOCKETIO')