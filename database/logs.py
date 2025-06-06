from .connection import DatabaseConnection
from datetime import datetime, timedelta
import logging
import json
import hashlib
import os
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger(__name__)

class LogDB:
    def __init__(self):
        self.db = DatabaseConnection()
        self.db.connect()
        
        # Log type to table mapping
        self.log_table_mapping = {
            'process': 'ProcessLogs',
            'file': 'FileLogs', 
            'network': 'NetworkLogs'
        }

    def process_log(self, log_type: str, log_data: Dict) -> bool:
        """Process and store log data dynamically"""
        try:
            if not log_data:
                logging.error("Empty log data received")
                return False
                
            # Get table name from log type
            table_name = self.log_table_mapping.get(log_type.lower())
            if not table_name:
                logging.error(f"Unknown log type: {log_type}")
                return False
            
            # Normalize and validate log data
            normalized_data = self._normalize_log_data(log_type, log_data)
            if not normalized_data:
                logging.error(f"Failed to normalize {log_type} log data")
                return False
                
            # Insert into database
            success = self.db.insert_data(table_name, normalized_data)
            
            if success:
                logging.info(f"Successfully processed {log_type} log for {normalized_data.get('Hostname', 'unknown')}")
            else:
                logging.error(f"Failed to insert {log_type} log into database")
                
            return success
            
        except Exception as e:
            logging.error(f"Error processing {log_type} log: {e}")
            return False

    def _normalize_log_data(self, log_type: str, log_data: Dict) -> Optional[Dict]:
        """Normalize log data based on type and available fields"""
        try:
            # Get table schema
            table_name = self.log_table_mapping.get(log_type.lower())
            schema = self.db.get_table_schema(table_name)
            
            if not schema:
                logging.error(f"No schema found for table {table_name}")
                return None
            
            # Extract available columns from schema
            available_columns = set(schema.get('columns', {}).keys())
            
            # Normalize based on log type
            if log_type.lower() == 'process':
                return self._normalize_process_log(log_data, available_columns)
            elif log_type.lower() == 'file':
                return self._normalize_file_log(log_data, available_columns)
            elif log_type.lower() == 'network':
                return self._normalize_network_log(log_data, available_columns)
            else:
                return self._normalize_generic_log(log_data, available_columns)
                
        except Exception as e:
            logging.error(f"Error normalizing {log_type} log data: {e}")
            return None

    def _normalize_process_log(self, log_data: Dict, available_columns: set) -> Dict:
        """Normalize process log data"""
        normalized = {}
        
        # Field mapping - handle various possible field names
        field_mappings = {
            'Time': ['Time', 'Timestamp', 'DateTime', 'timestamp', 'time'],
            'Hostname': ['Hostname', 'hostname', 'host', 'computer_name', 'ComputerName'],
            'ProcessID': ['ProcessID', 'PID', 'pid', 'process_id', 'Id'],
            'ParentProcessID': ['ParentProcessID', 'PPID', 'ppid', 'parent_pid', 'ParentPID'],
            'ProcessName': ['ProcessName', 'Name', 'name', 'process_name', 'executable'],
            'CommandLine': ['CommandLine', 'command_line', 'cmdline', 'cmd', 'arguments'],
            'ExecutablePath': ['ExecutablePath', 'executable_path', 'exe', 'path', 'full_path'],
            'UserName': ['UserName', 'user_name', 'user', 'username', 'owner'],
            'CPUUsage': ['CPUUsage', 'cpu_usage', 'cpu_percent', 'cpu', 'CpuUsage'],
            'MemoryUsage': ['MemoryUsage', 'memory_usage', 'memory', 'mem', 'rss', 'WorkingSetSize'],
            'Hash': ['Hash', 'hash', 'sha256', 'md5', 'file_hash', 'checksum']
        }
        
        # Map fields dynamically
        for db_field, possible_names in field_mappings.items():
            if db_field in available_columns:
                value = self._extract_field_value(log_data, possible_names)
                if value is not None:
                    normalized[db_field] = self._convert_field_value(db_field, value)
        
        # Set default time if not provided
        if 'Time' in available_columns and 'Time' not in normalized:
            normalized['Time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Ensure required fields have values
        self._ensure_required_fields(normalized, 'process')
        
        return normalized

    def _normalize_file_log(self, log_data: Dict, available_columns: set) -> Dict:
        """Normalize file log data"""
        normalized = {}
        
        field_mappings = {
            'Time': ['Time', 'Timestamp', 'DateTime', 'timestamp', 'time'],
            'Hostname': ['Hostname', 'hostname', 'host', 'computer_name', 'ComputerName'],
            'FileName': ['FileName', 'file_name', 'name', 'filename', 'Name'],
            'FilePath': ['FilePath', 'file_path', 'path', 'full_path', 'Path'],
            'FileSize': ['FileSize', 'file_size', 'size', 'Size', 'length'],
            'FileHash': ['FileHash', 'file_hash', 'hash', 'Hash', 'checksum', 'md5', 'sha256'],
            'EventType': ['EventType', 'event_type', 'action', 'Action', 'operation', 'Operation'],
            'ProcessID': ['ProcessID', 'PID', 'pid', 'process_id', 'Id'],
            'ProcessName': ['ProcessName', 'process_name', 'process', 'executable']
        }
        
        # Map fields dynamically
        for db_field, possible_names in field_mappings.items():
            if db_field in available_columns:
                value = self._extract_field_value(log_data, possible_names)
                if value is not None:
                    normalized[db_field] = self._convert_field_value(db_field, value)
        
        # Auto-generate FileName from FilePath if missing
        if 'FileName' in available_columns and 'FileName' not in normalized and 'FilePath' in normalized:
            normalized['FileName'] = os.path.basename(normalized['FilePath'])
        
        # Set default time if not provided
        if 'Time' in available_columns and 'Time' not in normalized:
            normalized['Time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Ensure required fields have values
        self._ensure_required_fields(normalized, 'file')
        
        return normalized

    def _normalize_network_log(self, log_data: Dict, available_columns: set) -> Dict:
        """Normalize network log data"""
        normalized = {}
        
        field_mappings = {
            'Time': ['Time', 'Timestamp', 'DateTime', 'timestamp', 'time'],
            'Hostname': ['Hostname', 'hostname', 'host', 'computer_name', 'ComputerName'],
            'ProcessID': ['ProcessID', 'PID', 'pid', 'process_id', 'Id'],
            'ProcessName': ['ProcessName', 'process_name', 'process', 'name', 'executable'],
            'Protocol': ['Protocol', 'protocol', 'proto', 'type', 'connection_type'],
            'LocalAddress': ['LocalAddress', 'local_address', 'local_ip', 'src_ip', 'source_ip'],
            'LocalPort': ['LocalPort', 'local_port', 'src_port', 'source_port', 'lport'],
            'RemoteAddress': ['RemoteAddress', 'remote_address', 'remote_ip', 'dst_ip', 'dest_ip', 'destination_ip'],
            'RemotePort': ['RemotePort', 'remote_port', 'dst_port', 'dest_port', 'destination_port', 'rport'],
            'Direction': ['Direction', 'direction', 'flow', 'conn_direction', 'connection_direction']
        }
        
        # Map fields dynamically
        for db_field, possible_names in field_mappings.items():
            if db_field in available_columns:
                value = self._extract_field_value(log_data, possible_names)
                if value is not None:
                    normalized[db_field] = self._convert_field_value(db_field, value)
        
        # Parse address:port format if needed
        self._parse_address_port_fields(log_data, normalized)
        
        # Set default time if not provided
        if 'Time' in available_columns and 'Time' not in normalized:
            normalized['Time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Ensure required fields have values
        self._ensure_required_fields(normalized, 'network')
        
        return normalized

    def _normalize_generic_log(self, log_data: Dict, available_columns: set) -> Dict:
        """Normalize generic log data for unknown types"""
        normalized = {}
        
        # Direct mapping for exact field names
        for field in available_columns:
            if field in log_data:
                normalized[field] = self._convert_field_value(field, log_data[field])
        
        # Ensure Time field if available
        if 'Time' in available_columns and 'Time' not in normalized:
            normalized['Time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        return normalized

    def _extract_field_value(self, log_data: Dict, possible_names: List[str]) -> Any:
        """Extract field value from log data using possible field names"""
        for name in possible_names:
            if name in log_data and log_data[name] is not None:
                return log_data[name]
        return None

    def _convert_field_value(self, field_name: str, value: Any) -> Any:
        """Convert field value to appropriate type"""
        if value is None or value == '':
            return None
            
        field_lower = field_name.lower()
        
        try:
            # Integer fields
            if any(keyword in field_lower for keyword in ['id', 'port', 'size', 'pid']):
                if isinstance(value, str) and value.strip().upper() in ['NULL', 'NONE', '']:
                    return 0
                return int(float(value)) if value else 0
            
            # Float fields
            elif any(keyword in field_lower for keyword in ['usage', 'percent', 'cpu']):
                if isinstance(value, str) and value.strip().upper() in ['NULL', 'NONE', '']:
                    return 0.0
                return float(value) if value else 0.0
            
            # Boolean fields
            elif 'active' in field_lower or 'enabled' in field_lower:
                if isinstance(value, bool):
                    return 1 if value else 0
                if isinstance(value, str):
                    return 1 if value.lower() in ['true', '1', 'yes', 'on'] else 0
                return int(bool(value))
            
            # String fields - clean up
            else:
                str_value = str(value).strip()
                if str_value.upper() in ['NULL', 'NONE']:
                    return ''
                return str_value
                
        except (ValueError, TypeError) as e:
            logging.warning(f"Error converting value '{value}' for field '{field_name}': {e}")
            # Return safe default based on field type
            if any(keyword in field_lower for keyword in ['id', 'port', 'size', 'pid']):
                return 0
            elif any(keyword in field_lower for keyword in ['usage', 'percent', 'cpu']):
                return 0.0
            else:
                return str(value) if value else ''

    def _parse_address_port_fields(self, log_data: Dict, normalized: Dict):
        """Parse address:port format fields"""
        # Check for combined address:port fields
        combined_fields = {
            'local_address': ('LocalAddress', 'LocalPort'),
            'remote_address': ('RemoteAddress', 'RemotePort'),
            'LocalAddress': ('LocalAddress', 'LocalPort'),
            'RemoteAddress': ('RemoteAddress', 'RemotePort')
        }
        
        for combined_field, (addr_field, port_field) in combined_fields.items():
            if combined_field in log_data and ':' in str(log_data[combined_field]):
                try:
                    addr_port = str(log_data[combined_field]).strip()
                    if addr_port and ':' in addr_port:
                        parts = addr_port.rsplit(':', 1)  # Split from right to handle IPv6
                        if len(parts) == 2:
                            address, port = parts
                            if addr_field not in normalized:
                                normalized[addr_field] = address.strip()
                            if port_field not in normalized:
                                normalized[port_field] = int(port.strip())
                except (ValueError, IndexError) as e:
                    logging.warning(f"Error parsing address:port field '{combined_field}': {e}")

    def _ensure_required_fields(self, normalized: Dict, log_type: str):
        """Ensure required fields have default values"""
        defaults = {
            'process': {
                'Hostname': 'unknown',
                'ProcessID': 0,
                'ProcessName': 'unknown'
            },
            'file': {
                'Hostname': 'unknown',
                'FileName': 'unknown',
                'FilePath': 'unknown',
                'EventType': 'unknown'
            },
            'network': {
                'Hostname': 'unknown',
                'ProcessID': 0,
                'ProcessName': 'unknown',
                'Protocol': 'unknown'
            }
        }
        
        log_defaults = defaults.get(log_type, {})
        for field, default_value in log_defaults.items():
            if field not in normalized or normalized[field] is None:
                normalized[field] = default_value

    def insert_process_logs(self, logs: List[Dict]) -> Tuple[int, int]:
        """Insert multiple process logs"""
        return self._insert_logs_batch('process', logs)

    def insert_file_logs(self, logs: List[Dict]) -> Tuple[int, int]:
        """Insert multiple file logs"""
        return self._insert_logs_batch('file', logs)

    def insert_network_logs(self, logs: List[Dict]) -> Tuple[int, int]:
        """Insert multiple network logs"""
        return self._insert_logs_batch('network', logs)

    def _insert_logs_batch(self, log_type: str, logs: List[Dict]) -> Tuple[int, int]:
        """Insert logs in batch with transaction"""
        success_count = 0
        failed_count = 0
        
        if not logs:
            return success_count, failed_count
        
        try:
            self.db.begin_transaction()
            
            for log in logs:
                try:
                    if self.process_log(log_type, log):
                        success_count += 1
                    else:
                        failed_count += 1
                except Exception as e:
                    logging.error(f"Error processing individual {log_type} log: {e}")
                    failed_count += 1
            
            self.db.commit()
            logging.info(f"Batch insert completed - {log_type}: {success_count} success, {failed_count} failed")
            
        except Exception as e:
            logging.error(f"Error in batch insert for {log_type} logs: {e}")
            self.db.rollback()
            failed_count = len(logs)
            success_count = 0
        
        return success_count, failed_count

    def get_logs(self, table_name: str, filters: Dict = None, limit: int = 100) -> List[Dict]:
        """Get logs with dynamic filtering"""
        try:
            # Build base query
            query = f"SELECT TOP {limit} * FROM {table_name}"
            params = []
            
            # Add WHERE clause if filters provided
            if filters:
                where_conditions = []
                for field, value in filters.items():
                    if value is not None:
                        where_conditions.append(f"{field} = ?")
                        params.append(value)
                
                if where_conditions:
                    query += " WHERE " + " AND ".join(where_conditions)
            
            query += " ORDER BY Time DESC"
            
            cursor = self.db.execute_query(query, params)
            if cursor:
                columns = [column[0] for column in cursor.description]
                rows = cursor.fetchall()
                
                results = []
                for row in rows:
                    row_dict = {}
                    for i, value in enumerate(row):
                        col_name = columns[i]
                        # Convert datetime to string for JSON serialization
                        if hasattr(value, 'strftime'):
                            row_dict[col_name] = value.strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            row_dict[col_name] = value
                    results.append(row_dict)
                
                return results
            
            return []
            
        except Exception as e:
            logging.error(f"Error getting logs from {table_name}: {e}")
            return []

    def get_process_logs(self, hostname: str = None, from_time: str = None, to_time: str = None, limit: int = 100) -> List[Dict]:
        """Get process logs with time range filters"""
        try:
            query = f"SELECT TOP {limit} * FROM ProcessLogs"
            params = []
            where_conditions = []
            
            if hostname:
                where_conditions.append("Hostname = ?")
                params.append(hostname)
            
            if from_time:
                where_conditions.append("Time >= ?")
                params.append(from_time)
            
            if to_time:
                where_conditions.append("Time <= ?")
                params.append(to_time)
            
            if where_conditions:
                query += " WHERE " + " AND ".join(where_conditions)
            
            query += " ORDER BY Time DESC"
            
            cursor = self.db.execute_query(query, params)
            if cursor:
                columns = [column[0] for column in cursor.description]
                rows = cursor.fetchall()
                
                results = []
                for row in rows:
                    row_dict = {}
                    for i, value in enumerate(row):
                        col_name = columns[i]
                        if hasattr(value, 'strftime'):
                            row_dict[col_name] = value.strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            row_dict[col_name] = value
                    results.append(row_dict)
                
                return results
            
            return []
            
        except Exception as e:
            logging.error(f"Error getting process logs: {e}")
            return []

    def get_file_logs(self, hostname: str = None, from_time: str = None, to_time: str = None, limit: int = 100) -> List[Dict]:
        """Get file logs with time range filters"""
        try:
            query = f"SELECT TOP {limit} * FROM FileLogs"
            params = []
            where_conditions = []
            
            if hostname:
                where_conditions.append("Hostname = ?")
                params.append(hostname)
            
            if from_time:
                where_conditions.append("Time >= ?")
                params.append(from_time)
            
            if to_time:
                where_conditions.append("Time <= ?")
                params.append(to_time)
            
            if where_conditions:
                query += " WHERE " + " AND ".join(where_conditions)
            
            query += " ORDER BY Time DESC"
            
            cursor = self.db.execute_query(query, params)
            if cursor:
                columns = [column[0] for column in cursor.description]
                rows = cursor.fetchall()
                
                results = []
                for row in rows:
                    row_dict = {}
                    for i, value in enumerate(row):
                        col_name = columns[i]
                        if hasattr(value, 'strftime'):
                            row_dict[col_name] = value.strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            row_dict[col_name] = value
                    results.append(row_dict)
                
                return results
            
            return []
            
        except Exception as e:
            logging.error(f"Error getting file logs: {e}")
            return []

    def get_network_logs(self, hostname: str = None, from_time: str = None, to_time: str = None, limit: int = 100) -> List[Dict]:
        """Get network logs with time range filters"""
        try:
            query = f"SELECT TOP {limit} * FROM NetworkLogs"
            params = []
            where_conditions = []
            
            if hostname:
                where_conditions.append("Hostname = ?")
                params.append(hostname)
            
            if from_time:
                where_conditions.append("Time >= ?")
                params.append(from_time)
            
            if to_time:
                where_conditions.append("Time <= ?")
                params.append(to_time)
            
            if where_conditions:
                query += " WHERE " + " AND ".join(where_conditions)
            
            query += " ORDER BY Time DESC"
            
            cursor = self.db.execute_query(query, params)
            if cursor:
                columns = [column[0] for column in cursor.description]
                rows = cursor.fetchall()
                
                results = []
                for row in rows:
                    row_dict = {}
                    for i, value in enumerate(row):
                        col_name = columns[i]
                        if hasattr(value, 'strftime'):
                            row_dict[col_name] = value.strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            row_dict[col_name] = value
                    results.append(row_dict)
                
                return results
            
            return []
            
        except Exception as e:
            logging.error(f"Error getting network logs: {e}")
            return []

    def get_log_statistics(self, hours: int = 24) -> Dict:
        """Get log statistics for dashboard"""
        try:
            stats = {
                'process_logs': 0,
                'file_logs': 0,
                'network_logs': 0,
                'total_logs': 0,
                'time_range_hours': hours
            }
            
            # Calculate time range
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=hours)
            start_time_str = start_time.strftime('%Y-%m-%d %H:%M:%S')
            
            # Get process logs count
            cursor = self.db.execute_query(
                "SELECT COUNT(*) FROM ProcessLogs WHERE Time >= ?", 
                [start_time_str]
            )
            if cursor:
                stats['process_logs'] = cursor.fetchone()[0]
            
            # Get file logs count
            cursor = self.db.execute_query(
                "SELECT COUNT(*) FROM FileLogs WHERE Time >= ?", 
                [start_time_str]
            )
            if cursor:
                stats['file_logs'] = cursor.fetchone()[0]
            
            # Get network logs count
            cursor = self.db.execute_query(
                "SELECT COUNT(*) FROM NetworkLogs WHERE Time >= ?", 
                [start_time_str]
            )
            if cursor:
                stats['network_logs'] = cursor.fetchone()[0]
            
            stats['total_logs'] = stats['process_logs'] + stats['file_logs'] + stats['network_logs']
            
            return stats
            
        except Exception as e:
            logging.error(f"Error getting log statistics: {e}")
            return {}

    def cleanup_old_logs(self, days: int = 30) -> Dict[str, int]:
        """Clean up old logs from all tables"""
        try:
            cutoff_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
            cleanup_results = {}
            
            for table in ['ProcessLogs', 'FileLogs', 'NetworkLogs']:
                try:
                    query = f"DELETE FROM {table} WHERE Time < ?"
                    cursor = self.db.execute_query(query, [cutoff_date])
                    if cursor:
                        rows_deleted = cursor.rowcount
                        cleanup_results[table] = rows_deleted
                        logging.info(f"Deleted {rows_deleted} old records from {table}")
                    else:
                        cleanup_results[table] = 0
                except Exception as e:
                    logging.error(f"Error cleaning up {table}: {e}")
                    cleanup_results[table] = 0
            
            return cleanup_results
            
        except Exception as e:
            logging.error(f"Error cleaning up old logs: {e}")
            return {}

    def get_top_processes(self, limit: int = 10, hours: int = 24) -> List[Dict]:
        """Get top processes by frequency"""
        try:
            start_time = (datetime.now() - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
            
            query = """
                SELECT TOP (?) ProcessName, COUNT(*) as ProcessCount, 
                       COUNT(DISTINCT Hostname) as HostCount
                FROM ProcessLogs 
                WHERE Time >= ?
                GROUP BY ProcessName 
                ORDER BY ProcessCount DESC
            """
            
            cursor = self.db.execute_query(query, [limit, start_time])
            
            results = []
            if cursor:
                columns = [column[0] for column in cursor.description]
                for row in cursor.fetchall():
                    row_dict = {}
                    for i, value in enumerate(row):
                        row_dict[columns[i]] = value
                    results.append(row_dict)
            
            return results
            
        except Exception as e:
            logging.error(f"Error getting top processes: {e}")
            return []

    def get_file_activity_summary(self, hours: int = 24) -> Dict:
        """Get file activity summary"""
        try:
            start_time = (datetime.now() - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
            
            query = """
                SELECT EventType, COUNT(*) as EventCount
                FROM FileLogs 
                WHERE Time >= ?
                GROUP BY EventType
                ORDER BY EventCount DESC
            """
            
            cursor = self.db.execute_query(query, [start_time])
            
            summary = {}
            if cursor:
                for row in cursor.fetchall():
                    summary[row.EventType] = row.EventCount
            
            return summary
            
        except Exception as e:
            logging.error(f"Error getting file activity summary: {e}")
            return {}

    def get_network_connections_summary(self, hours: int = 24) -> Dict:
        """Get network connections summary"""
        try:
            start_time = (datetime.now() - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
            
            query = """
                SELECT Protocol, Direction, COUNT(*) as ConnectionCount
                FROM NetworkLogs 
                WHERE Time >= ?
                GROUP BY Protocol, Direction
                ORDER BY ConnectionCount DESC
            """
            
            cursor = self.db.execute_query(query, [start_time])
            
            summary = {}
            if cursor:
                for row in cursor.fetchall():
                    key = f"{row.Protocol}_{row.Direction}"
                    summary[key] = row.ConnectionCount
            
            return summary
            
        except Exception as e:
            logging.error(f"Error getting network connections summary: {e}")
            return {}

    def search_logs(self, search_term: str, log_types: List[str] = None, limit: int = 100) -> Dict:
        """Search across multiple log types"""
        try:
            if not search_term:
                return {}
            
            # Default to all log types if none specified
            if not log_types:
                log_types = ['process', 'file', 'network']
            
            results = {}
            
            # Search process logs
            if 'process' in log_types:
                query = f"""
                    SELECT TOP {limit} * FROM ProcessLogs 
                    WHERE ProcessName LIKE ? OR CommandLine LIKE ? OR ExecutablePath LIKE ?
                    ORDER BY Time DESC
                """
                search_pattern = f"%{search_term}%"
                cursor = self.db.execute_query(query, [search_pattern, search_pattern, search_pattern])
                
                if cursor:
                    columns = [column[0] for column in cursor.description]
                    rows = cursor.fetchall()
                    
                    process_results = []
                    for row in rows:
                        row_dict = {}
                        for i, value in enumerate(row):
                            col_name = columns[i]
                            if hasattr(value, 'strftime'):
                                row_dict[col_name] = value.strftime('%Y-%m-%d %H:%M:%S')
                            else:
                                row_dict[col_name] = value
                        process_results.append(row_dict)
                    
                    results['process'] = process_results
            
            # Search file logs
            if 'file' in log_types:
                query = f"""
                    SELECT TOP {limit} * FROM FileLogs 
                    WHERE FileName LIKE ? OR FilePath LIKE ?
                    ORDER BY Time DESC
                """
                search_pattern = f"%{search_term}%"
                cursor = self.db.execute_query(query, [search_pattern, search_pattern])
                
                if cursor:
                    columns = [column[0] for column in cursor.description]
                    rows = cursor.fetchall()
                    
                    file_results = []
                    for row in rows:
                        row_dict = {}
                        for i, value in enumerate(row):
                            col_name = columns[i]
                            if hasattr(value, 'strftime'):
                                row_dict[col_name] = value.strftime('%Y-%m-%d %H:%M:%S')
                            else:
                                row_dict[col_name] = value
                        file_results.append(row_dict)
                    
                    results['file'] = file_results
            
            # Search network logs
            if 'network' in log_types:
                query = f"""
                    SELECT TOP {limit} * FROM NetworkLogs 
                    WHERE ProcessName LIKE ? OR RemoteAddress LIKE ? OR LocalAddress LIKE ?
                    ORDER BY Time DESC
                """
                search_pattern = f"%{search_term}%"
                cursor = self.db.execute_query(query, [search_pattern, search_pattern, search_pattern])
                
                if cursor:
                    columns = [column[0] for column in cursor.description]
                    rows = cursor.fetchall()
                    
                    network_results = []
                    for row in rows:
                        row_dict = {}
                        for i, value in enumerate(row):
                            col_name = columns[i]
                            if hasattr(value, 'strftime'):
                                row_dict[col_name] = value.strftime('%Y-%m-%d %H:%M:%S')
                            else:
                                row_dict[col_name] = value
                        network_results.append(row_dict)
                    
                    results['network'] = network_results
            
            return results
            
        except Exception as e:
            logging.error(f"Error searching logs: {e}")
            return {}

    def get_logs_by_timerange(self, start_time: str, end_time: str, log_types: List[str] = None, limit: int = 1000) -> Dict:
        """Get logs within specific time range"""
        try:
            if not log_types:
                log_types = ['process', 'file', 'network']
            
            results = {}
            
            for log_type in log_types:
                table_name = self.log_table_mapping.get(log_type)
                if not table_name:
                    continue
                
                query = f"""
                    SELECT TOP {limit} * FROM {table_name}
                    WHERE Time >= ? AND Time <= ?
                    ORDER BY Time DESC
                """
                
                cursor = self.db.execute_query(query, [start_time, end_time])
                
                if cursor:
                    columns = [column[0] for column in cursor.description]
                    rows = cursor.fetchall()
                    
                    log_results = []
                    for row in rows:
                        row_dict = {}
                        for i, value in enumerate(row):
                            col_name = columns[i]
                            if hasattr(value, 'strftime'):
                                row_dict[col_name] = value.strftime('%Y-%m-%d %H:%M:%S')
                            else:
                                row_dict[col_name] = value
                        log_results.append(row_dict)
                    
                    results[log_type] = log_results
            
            return results
            
        except Exception as e:
            logging.error(f"Error getting logs by time range: {e}")
            return {}

    def get_agent_log_summary(self, hostname: str, hours: int = 24) -> Dict:
        """Get log summary for specific agent"""
        try:
            start_time = (datetime.now() - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
            
            summary = {
                'hostname': hostname,
                'time_range_hours': hours,
                'process_logs': 0,
                'file_logs': 0,
                'network_logs': 0,
                'total_logs': 0,
                'most_active_processes': [],
                'file_activity_types': {},
                'network_protocols': {}
            }
            
            # Get process logs count and top processes
            cursor = self.db.execute_query(
                "SELECT COUNT(*) FROM ProcessLogs WHERE Hostname = ? AND Time >= ?",
                [hostname, start_time]
            )
            if cursor:
                summary['process_logs'] = cursor.fetchone()[0]
            
            # Get top processes for this agent
            cursor = self.db.execute_query(
                """SELECT ProcessName, COUNT(*) as Count 
                   FROM ProcessLogs 
                   WHERE Hostname = ? AND Time >= ?
                   GROUP BY ProcessName 
                   ORDER BY Count DESC""",
                [hostname, start_time]
            )
            if cursor:
                summary['most_active_processes'] = [
                    {'name': row.ProcessName, 'count': row.Count}
                    for row in cursor.fetchmany(5)
                ]
            
            # Get file logs count and activity types
            cursor = self.db.execute_query(
                "SELECT COUNT(*) FROM FileLogs WHERE Hostname = ? AND Time >= ?",
                [hostname, start_time]
            )
            if cursor:
                summary['file_logs'] = cursor.fetchone()[0]
            
            cursor = self.db.execute_query(
                """SELECT EventType, COUNT(*) as Count 
                   FROM FileLogs 
                   WHERE Hostname = ? AND Time >= ?
                   GROUP BY EventType""",
                [hostname, start_time]
            )
            if cursor:
                for row in cursor.fetchall():
                    summary['file_activity_types'][row.EventType] = row.Count
            
            # Get network logs count and protocols
            cursor = self.db.execute_query(
                "SELECT COUNT(*) FROM NetworkLogs WHERE Hostname = ? AND Time >= ?",
                [hostname, start_time]
            )
            if cursor:
                summary['network_logs'] = cursor.fetchone()[0]
            
            cursor = self.db.execute_query(
                """SELECT Protocol, COUNT(*) as Count 
                   FROM NetworkLogs 
                   WHERE Hostname = ? AND Time >= ?
                   GROUP BY Protocol""",
                [hostname, start_time]
            )
            if cursor:
                for row in cursor.fetchall():
                    summary['network_protocols'][row.Protocol] = row.Count
            
            summary['total_logs'] = summary['process_logs'] + summary['file_logs'] + summary['network_logs']
            
            return summary
            
        except Exception as e:
            logging.error(f"Error getting agent log summary for {hostname}: {e}")
            return {}

    def export_logs(self, export_type: str, filters: Dict = None, limit: int = 10000) -> List[Dict]:
        """Export logs in various formats"""
        try:
            if export_type not in ['process', 'file', 'network', 'all']:
                raise ValueError("Invalid export type")
            
            exported_logs = []
            
            if export_type == 'all':
                log_types = ['process', 'file', 'network']
            else:
                log_types = [export_type]
            
            for log_type in log_types:
                table_name = self.log_table_mapping.get(log_type)
                if not table_name:
                    continue
                
                # Build query with filters
                query = f"SELECT TOP {limit} * FROM {table_name}"
                params = []
                
                if filters:
                    where_conditions = []
                    
                    if 'hostname' in filters:
                        where_conditions.append("Hostname = ?")
                        params.append(filters['hostname'])
                    
                    if 'start_time' in filters:
                        where_conditions.append("Time >= ?")
                        params.append(filters['start_time'])
                    
                    if 'end_time' in filters:
                        where_conditions.append("Time <= ?")
                        params.append(filters['end_time'])
                    
                    if where_conditions:
                        query += " WHERE " + " AND ".join(where_conditions)
                
                query += " ORDER BY Time DESC"
                
                cursor = self.db.execute_query(query, params)
                
                if cursor:
                    columns = [column[0] for column in cursor.description]
                    rows = cursor.fetchall()
                    
                    for row in rows:
                        row_dict = {'log_type': log_type}
                        for i, value in enumerate(row):
                            col_name = columns[i]
                            if hasattr(value, 'strftime'):
                                row_dict[col_name] = value.strftime('%Y-%m-%d %H:%M:%S')
                            else:
                                row_dict[col_name] = value
                        exported_logs.append(row_dict)
            
            return exported_logs
            
        except Exception as e:
            logging.error(f"Error exporting logs: {e}")
            return []