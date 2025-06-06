# Database Module for EDR System
"""
Database module providing data access layer for EDR System.
Supports SQL Server with dynamic field mapping and validation.
"""

from .connection import DatabaseConnection
from .agents import AgentDB
from .alerts import AlertDB
from .logs import LogDB
from .rules import RuleDB

__version__ = "2.0.0"
__author__ = "EDR System"

# Database module exports
__all__ = [
    'DatabaseConnection',
    'AgentDB', 
    'AlertDB',
    'LogDB',
    'RuleDB'
]

# Module level configuration
DEFAULT_CONNECTION_TIMEOUT = 30
DEFAULT_QUERY_TIMEOUT = 60
DEFAULT_BATCH_SIZE = 50

def get_database_components():
    """Get all database components initialized"""
    try:
        db_connection = DatabaseConnection()
        db_connection.connect()
        
        return {
            'connection': db_connection,
            'agents': AgentDB(),
            'alerts': AlertDB(), 
            'logs': LogDB(),
            'rules': RuleDB()
        }
    except Exception as e:
        raise Exception(f"Failed to initialize database components: {e}")

def test_database_connection():
    """Test database connectivity"""
    try:
        db = DatabaseConnection()
        if db.connect():
            cursor = db.execute_query("SELECT 1 as test")
            if cursor and cursor.fetchone():
                db.close()
                return True, "Database connection successful"
        return False, "Database connection failed"
    except Exception as e:
        return False, f"Database test error: {e}"