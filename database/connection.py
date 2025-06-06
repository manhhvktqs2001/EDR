"""
Database Connection Manager cho EDR System
Hỗ trợ SQL Server với connection pooling và transaction management
"""

import pyodbc
import logging
import time
import threading
from contextlib import contextmanager
from typing import Dict, List, Any, Optional, Tuple
from config import DATABASE_CONFIG

class DatabaseConnection:
    """Database connection manager với connection pooling"""
    
    def __init__(self):
        self.config = DATABASE_CONFIG
        self.connection = None
        self.connection_string = None
        self.is_connected = False
        self.last_ping = 0
        self.lock = threading.Lock()
        self.logger = logging.getLogger(__name__)
        
    def _build_connection_string(self) -> str:
        """Xây dựng connection string"""
        try:
            server = self.config['server']
            database = self.config['database']
            driver = self.config['driver']
            
            # SQL Server với Windows Authentication
            conn_str = (
                f"DRIVER={{{driver}}};"
                f"SERVER={server};"
                f"DATABASE={database};"
                f"Trusted_Connection=yes;"
                f"Connection Timeout={self.config.get('timeout', 30)};"
                f"Command Timeout={self.config.get('timeout', 30)};"
                f"MARS_Connection=yes;"  # Multiple Active Result Sets
            )
            
            return conn_str
            
        except Exception as e:
            self.logger.error(f"Error building connection string: {e}")
            raise
    
    def connect(self) -> bool:
        """Kết nối đến database"""
        try:
            with self.lock:
                if self.is_connected and self._test_connection():
                    return True
                
                self.connection_string = self._build_connection_string()
                self.connection = pyodbc.connect(
                    self.connection_string,
                    autocommit=self.config.get('autocommit', True),
                    timeout=self.config.get('timeout', 30)
                )
                
                # Test connection
                cursor = self.connection.cursor()
                cursor.execute("SELECT 1")
                cursor.fetchone()
                cursor.close()
                
                self.is_connected = True
                self.last_ping = time.time()
                
                self.logger.info(f"Connected to database: {self.config['server']}/{self.config['database']}")
                return True
                
        except Exception as e:
            self.logger.error(f"Database connection failed: {e}")
            self.is_connected = False
            return False
    
    def _test_connection(self) -> bool:
        """Test connection hiện tại"""
        try:
            if not self.connection:
                return False
            
            # Ping database mỗi 30 giây
            current_time = time.time()
            if current_time - self.last_ping > 30:
                cursor = self.connection.cursor()
                cursor.execute("SELECT 1")
                cursor.fetchone()
                cursor.close()
                self.last_ping = current_time
            
            return True
            
        except Exception:
            self.is_connected = False
            return False
    
    def reconnect(self) -> bool:
        """Reconnect to database"""
        try:
            self.close()
            return self.connect()
        except Exception as e:
            self.logger.error(f"Reconnection failed: {e}")
            return False
    
    def execute_query(self, query: str, params: List = None) -> Optional[pyodbc.Cursor]:
        """Execute SQL query với parameters"""
        try:
            if not self.is_connected or not self._test_connection():
                if not self.reconnect():
                    return None
            
            cursor = self.connection.cursor()
            
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            
            return cursor
            
        except pyodbc.Error as e:
            self.logger.error(f"SQL Error: {e}")
            self.logger.error(f"Query: {query}")
            if params:
                self.logger.error(f"Params: {params}")
            return None
        except Exception as e:
            self.logger.error(f"Database error: {e}")
            return None
    
    def execute_non_query(self, query: str, params: List = None) -> bool:
        """Execute INSERT/UPDATE/DELETE query"""
        try:
            cursor = self.execute_query(query, params)
            if cursor:
                cursor.close()
                return True
            return False
            
        except Exception as e:
            self.logger.error(f"Execute non-query error: {e}")
            return False
    
    def fetch_one(self, query: str, params: List = None) -> Optional[Dict]:
        """Fetch single row as dictionary"""
        try:
            cursor = self.execute_query(query, params)
            if not cursor:
                return None
            
            columns = [column[0] for column in cursor.description]
            row = cursor.fetchone()
            cursor.close()
            
            if row:
                return dict(zip(columns, row))
            return None
            
        except Exception as e:
            self.logger.error(f"Fetch one error: {e}")
            return None
    
    def fetch_all(self, query: str, params: List = None) -> List[Dict]:
        """Fetch all rows as list of dictionaries"""
        try:
            cursor = self.execute_query(query, params)
            if not cursor:
                return []
            
            columns = [column[0] for column in cursor.description]
            rows = cursor.fetchall()
            cursor.close()
            
            return [dict(zip(columns, row)) for row in rows]
            
        except Exception as e:
            self.logger.error(f"Fetch all error: {e}")
            return []
    
    def insert_data(self, table: str, data: Dict) -> bool:
        """Insert data into table"""
        try:
            if not data:
                return False
            
            columns = list(data.keys())
            placeholders = ', '.join(['?' for _ in columns])
            values = [data[col] for col in columns]
            
            query = f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders})"
            
            return self.execute_non_query(query, values)
            
        except Exception as e:
            self.logger.error(f"Insert data error: {e}")
            return False
    
    def update_data(self, table: str, data: Dict, where_clause: str, where_params: List = None) -> bool:
        """Update data in table"""
        try:
            if not data:
                return False
            
            set_clauses = [f"{col} = ?" for col in data.keys()]
            values = list(data.values())
            
            query = f"UPDATE {table} SET {', '.join(set_clauses)} WHERE {where_clause}"
            
            if where_params:
                values.extend(where_params)
            
            return self.execute_non_query(query, values)
            
        except Exception as e:
            self.logger.error(f"Update data error: {e}")
            return False
    
    def delete_data(self, table: str, where_clause: str, where_params: List = None) -> bool:
        """Delete data from table"""
        try:
            query = f"DELETE FROM {table} WHERE {where_clause}"
            return self.execute_non_query(query, where_params)
            
        except Exception as e:
            self.logger.error(f"Delete data error: {e}")
            return False
    
    def get_table_schema(self, table_name: str) -> Dict:
        """Lấy schema của table"""
        try:
            query = """
                SELECT 
                    COLUMN_NAME,
                    DATA_TYPE,
                    IS_NULLABLE,
                    CHARACTER_MAXIMUM_LENGTH,
                    COLUMN_DEFAULT
                FROM INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_NAME = ?
                ORDER BY ORDINAL_POSITION
            """
            
            cursor = self.execute_query(query, [table_name])
            if not cursor:
                return {}
            
            columns = {}
            for row in cursor.fetchall():
                columns[row.COLUMN_NAME] = {
                    'type': row.DATA_TYPE,
                    'nullable': row.IS_NULLABLE == 'YES',
                    'max_length': row.CHARACTER_MAXIMUM_LENGTH,
                    'default': row.COLUMN_DEFAULT
                }
            
            cursor.close()
            
            return {
                'table': table_name,
                'columns': columns
            }
            
        except Exception as e:
            self.logger.error(f"Get table schema error: {e}")
            return {}
    
    def begin_transaction(self):
        """Bắt đầu transaction"""
        try:
            if self.connection:
                self.connection.autocommit = False
        except Exception as e:
            self.logger.error(f"Begin transaction error: {e}")
    
    def commit(self):
        """Commit transaction"""
        try:
            if self.connection:
                self.connection.commit()
                self.connection.autocommit = True
        except Exception as e:
            self.logger.error(f"Commit error: {e}")
            self.rollback()
    
    def rollback(self):
        """Rollback transaction"""
        try:
            if self.connection:
                self.connection.rollback()
                self.connection.autocommit = True
        except Exception as e:
            self.logger.error(f"Rollback error: {e}")
    
    @contextmanager
    def transaction(self):
        """Transaction context manager"""
        try:
            self.begin_transaction()
            yield self
            self.commit()
        except Exception as e:
            self.rollback()
            self.logger.error(f"Transaction error: {e}")
            raise
    
    def execute_stored_procedure(self, proc_name: str, params: List = None) -> List[Dict]:
        """Execute stored procedure"""
        try:
            if params:
                placeholders = ', '.join(['?' for _ in params])
                query = f"EXEC {proc_name} {placeholders}"
            else:
                query = f"EXEC {proc_name}"
            
            return self.fetch_all(query, params)
            
        except Exception as e:
            self.logger.error(f"Execute stored procedure error: {e}")
            return []
    
    def bulk_insert(self, table: str, data_list: List[Dict]) -> Tuple[int, int]:
        """Bulk insert data"""
        success_count = 0
        failed_count = 0
        
        if not data_list:
            return success_count, failed_count
        
        try:
            with self.transaction():
                for data in data_list:
                    if self.insert_data(table, data):
                        success_count += 1
                    else:
                        failed_count += 1
            
            self.logger.info(f"Bulk insert: {success_count} success, {failed_count} failed")
            
        except Exception as e:
            self.logger.error(f"Bulk insert error: {e}")
            failed_count = len(data_list)
            success_count = 0
        
        return success_count, failed_count
    
    def get_connection_info(self) -> Dict:
        """Lấy thông tin connection"""
        return {
            'server': self.config['server'],
            'database': self.config['database'],
            'is_connected': self.is_connected,
            'last_ping': self.last_ping,
            'connection_string': self.connection_string if self.connection_string else None
        }
    
    def close(self):
        """Đóng connection"""
        try:
            with self.lock:
                if self.connection:
                    self.connection.close()
                    self.connection = None
                
                self.is_connected = False
                self.logger.info("Database connection closed")
                
        except Exception as e:
            self.logger.error(f"Close connection error: {e}")

# Connection factory
_db_instance = None
_db_lock = threading.Lock()

def get_database_connection() -> DatabaseConnection:
    """Get singleton database connection"""
    global _db_instance
    
    with _db_lock:
        if _db_instance is None:
            _db_instance = DatabaseConnection()
            _db_instance.connect()
        
        return _db_instance

def test_database_connection() -> Tuple[bool, str]:
    """Test database connection"""
    try:
        db = DatabaseConnection()
        if db.connect():
            # Test basic operations
            result = db.fetch_one("SELECT GETDATE() as CurrentTime, @@VERSION as Version")
            if result:
                db.close()
                return True, f"Connection successful. Server time: {result.get('CurrentTime')}"
            else:
                return False, "Connection failed - no response"
        else:
            return False, "Connection failed - cannot connect"
            
    except Exception as e:
        return False, f"Connection test error: {str(e)}"

def initialize_database() -> bool:
    """Initialize database connection pool"""
    try:
        db = get_database_connection()
        success, message = test_database_connection()
        
        if success:
            logging.info("Database initialized successfully")
            return True
        else:
            logging.error(f"Database initialization failed: {message}")
            return False
            
    except Exception as e:
        logging.error(f"Database initialization error: {e}")
        return False