"""
Log Database Operations - IMPROVED VERSION
Xử lý tất cả operations liên quan đến logs với enhanced performance, batch processing và validation
"""

from .connection import DatabaseConnection, DatabaseError
from datetime import datetime, timedelta
import logging
import json
import hashlib
import os
from typing import Dict, List, Any, Optional, Tuple
from pydantic import BaseModel, Field, validator
from concurrent.futures import ThreadPoolExecutor
import threading
from functools import lru_cache

class LogData(BaseModel):
    """Base log data validation model"""
    hostname: str = Field(..., min_length=1, max_length=255)
    time: Optional[datetime] = Field(default_factory=datetime.now)
    
    class Config:
        extra = "allow"  # Allow additional fields

class ProcessLogData(LogData):
    """Process log validation model"""
    process_id: int = Field(..., ge=0)
    process_name: str = Field(..., min_length=1, max_length=255)
    command_line: Optional[str] = Field(None, max_length=2000)
    executable_path: Optional[str] = Field(None, max_length=500)
    parent_process_id: Optional[int] = Field(None, ge=0)
    user_name: Optional[str] = Field(None, max_length=255)
    cpu_usage: Optional[float] = Field(None, ge=0.0, le=100.0)
    memory_usage: Optional[int] = Field(None, ge=0)
    hash: Optional[str] = Field(None, max_length=64)

class FileLogData(LogData):
    """File log validation model"""
    file_name: str = Field(..., min_length=1, max_length=255)
    file_path: str = Field(..., min_length=1, max_length=500)
    file_size: Optional[int] = Field(None, ge=0)
    file_hash: Optional[str] = Field(None, max_length=64)
    event_type: str = Field(..., regex="^(Create|Modify|Delete|Access|Rename)$")
    process_id: Optional[int] = Field(None, ge=0)
    process_name: Optional[str] = Field(None, max_length=255)

class NetworkLogData(LogData):
    """Network log validation model"""
    process_id: int = Field(..., ge=0)
    process_name: str = Field(..., min_length=1, max_length=255)
    protocol: str = Field(..., regex="^(TCP|UDP|ICMP)$")
    local_address: Optional[str] = Field(None, max_length=45)
    local_port: Optional[int] = Field(None, ge=0, le=65535)
    remote_address: str = Field(..., max_length=45)
    remote_port: int = Field(..., ge=0, le=65535)
    direction: str = Field(..., regex="^(Inbound|Outbound)$")

logger = logging.getLogger(__name__)

class LogDB:
    def __init__(self):
        self.db = DatabaseConnection()
        self.db.connect()
        
        # Log type to table and model mapping
        self.log_mapping = {
            'process': {
                'table': 'ProcessLogs',
                'model': ProcessLogData,
                'columns': self._get_process_columns()
            },
            'file': {
                'table': 'FileLogs',
                'model': FileLogData,
                'columns': self._get_file_columns()
            },
            'network': {
                'table': 'NetworkLogs',
                'model': NetworkLogData,
                'columns': self._get_network_columns()
            }
        }
        
        # Performance tracking
        self.stats = {
            'total_logs_processed': 0,
            'failed_logs': 0,
            'batch_operations': 0,
            'avg_processing_time': 0.0
        }
        
        # Thread pool for async operations
        self.executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="LogDB")
        self.lock = threading.RLock()

    def _get_process_columns(self) -> List[str]:
        """Get ProcessLogs table columns"""
        return [
            'Time', 'Hostname', 'ProcessID', 'ParentProcessID', 'ProcessName',
            'CommandLine', 'ExecutablePath', 'UserName', 'CPUUsage', 'MemoryUsage', 'Hash'
        ]

    def _get_file_columns(self) -> List[str]:
        """Get FileLogs table columns"""
        return [
            'Time', 'Hostname', 'FileName', 'FilePath', 'FileSize', 'FileHash',
            'EventType', 'ProcessID', 'ProcessName'
        ]

    def _get_network_columns(self) -> List[str]:
        """Get NetworkLogs table columns"""
        return [
            'Time', 'Hostname', 'ProcessID', 'ProcessName', 'Protocol',
            'LocalAddress', 'LocalPort', 'RemoteAddress', 'RemotePort', 'Direction'
        ]

    def process_log(self, log_type: str, log_data: Dict) -> bool:
        """Process and store single log with validation"""
        try:
            import time
            start_time = time.time()
            
            if not log_data:
                logger.error("Empty log data received")
                return False
                
            # Validate log type
            if log_type.lower() not in self.log_mapping:
                logger.error(f"Unknown log type: {log_type}")
                return False
            
            mapping = self.log_mapping[log_type.lower()]
            
            # Validate and normalize log data
            try:
                validated_data = mapping['model'](**log_data)
                normalized_data = self._normalize_log_to_db(validated_data, mapping['columns'])
            except Exception as e:
                logger.error(f"Validation failed for {log_type} log: {e}")
                with self.lock:
                    self.stats['failed_logs'] += 1
                return False
                
            # Insert into database
            success = self.db.insert_data(mapping['table'], normalized_data)
            
            # Update statistics
            processing_time = time.time() - start_time
            with self.lock:
                self.stats['total_logs_processed'] += 1
                if success:
                    # Update average processing time
                    total_time = self.stats['avg_processing_time'] * (self.stats['total_logs_processed'] - 1)
                    self.stats['avg_processing_time'] = (total_time + processing_time) / self.stats['total_logs_processed']
                else:
                    self.stats['failed_logs'] += 1
            
            if success:
                logger.debug(f"Successfully processed {log_type} log for {normalized_data.get('Hostname')}")
            else:
                logger.error(f"Failed to insert {log_type} log into database")
                
            return success
            
        except Exception as e:
            logger.error(f"Error processing {log_type} log: {e}")
            with self.lock:
                self.stats['failed_logs'] += 1
            return False

    def _normalize_log_to_db(self, validated_data: LogData, columns: List[str]) -> Dict:
        """Convert validated Pydantic model to database format"""
        result = {}
        
        # Convert Pydantic model to dict
        data_dict = validated_data.dict()
        
        # Map fields to database columns
        field_mapping = {
            'hostname': 'Hostname',
            'time': 'Time',
            'process_id': 'ProcessID',
            'parent_process_id': 'ParentProcessID',
            'process_name': 'ProcessName',
            'command_line': 'CommandLine',
            'executable_path': 'ExecutablePath',
            'user_name': 'UserName',
            'cpu_usage': 'CPUUsage',
            'memory_usage': 'MemoryUsage',
            'hash': 'Hash',
            'file_name': 'FileName',
            'file_path': 'FilePath',
            'file_size': 'FileSize',
            'file_hash': 'FileHash',
            'event_type': 'EventType',
            'protocol': 'Protocol',
            'local_address': 'LocalAddress',
            'local_port': 'LocalPort',
            'remote_address': 'RemoteAddress',
            'remote_port': 'RemotePort',
            'direction': 'Direction'
        }
        
        # Map available fields
        for field, db_column in field_mapping.items():
            if db_column in columns and field in data_dict and data_dict[field] is not None:
                result[db_column] = data_dict[field]
        
        # Ensure required fields have defaults
        if 'Time' not in result:
            result['Time'] = datetime.now()
        
        if 'Hostname' not in result:
            result['Hostname'] = 'unknown'
        
        return result

    def bulk_process_logs(self, log_type: str, logs: List[Dict], batch_size: int = 100) -> Tuple[int, int]:
        """Process multiple logs with batching and validation"""
        try:
            import time
            start_time = time.time()
            
            if not logs:
                return 0, 0
                
            if log_type.lower() not in self.log_mapping:
                logger.error(f"Unknown log type: {log_type}")
                return 0, len(logs)
            
            mapping = self.log_mapping[log_type.lower()]
            total_success = 0
            total_failed = 0
            
            # Process in batches
            for i in range(0, len(logs), batch_size):
                batch = logs[i:i + batch_size]
                batch_success, batch_failed = self._process_log_batch(mapping, batch)
                total_success += batch_success
                total_failed += batch_failed
            
            # Update statistics
            processing_time = time.time() - start_time
            with self.lock:
                self.stats['batch_operations'] += 1
                self.stats['total_logs_processed'] += total_success
                self.stats['failed_logs'] += total_failed
            
            logger.info(f"Bulk processed {log_type}: {total_success} success, {total_failed} failed in {processing_time:.2f}s")
            
            return total_success, total_failed
            
        except Exception as e:
            logger.error(f"Error in bulk processing {log_type} logs: {e}")
            return 0, len(logs)

    def _process_log_batch(self, mapping: Dict, batch: List[Dict]) -> Tuple[int, int]:
        """Process a batch of logs with transaction"""
        validated_logs = []
        failed_count = 0
        
        # Validate batch
        for log_data in batch:
            try:
                validated_data = mapping['model'](**log_data)
                normalized_data = self._normalize_log_to_db(validated_data, mapping['columns'])
                validated_logs.append(normalized_data)
            except Exception as e:
                logger.debug(f"Validation failed for log: {e}")
                failed_count += 1
        
        if not validated_logs:
            return 0, failed_count
        
        # Bulk insert with transaction
        try:
            success_count, insert_failed = self.db.bulk_insert(mapping['table'], validated_logs)
            return success_count, failed_count + insert_failed
        except Exception as e:
            logger.error(f"Batch insert failed: {e}")
            return 0, len(batch)

    def get_process_logs(self, hostname: str = None, from_time: str = None, 
                        to_time: str = None, limit: int = 100, 
                        filters: Dict = None) -> List[Dict]:
        """Get process logs with enhanced filtering"""
        try:
            return self._get_logs_with_filters(
                'ProcessLogs', hostname, from_time, to_time, limit, filters
            )
        except Exception as e:
            logger.error(f"Error getting process logs: {e}")
            return []

    def get_file_logs(self, hostname: str = None, from_time: str = None, 
                     to_time: str = None, limit: int = 100,
                     filters: Dict = None) -> List[Dict]:
        """Get file logs with enhanced filtering"""
        try:
            return self._get_logs_with_filters(
                'FileLogs', hostname, from_time, to_time, limit, filters
            )
        except Exception as e:
            logger.error(f"Error getting file logs: {e}")
            return []

    def get_network_logs(self, hostname: str = None, from_time: str = None, 
                        to_time: str = None, limit: int = 100,
                        filters: Dict = None) -> List[Dict]:
        """Get network logs with enhanced filtering"""
        try:
            return self._get_logs_with_filters(
                'NetworkLogs', hostname, from_time, to_time, limit, filters
            )
        except Exception as e:
            logger.error(f"Error getting network logs: {e}")
            return []

    def _get_logs_with_filters(self, table_name: str, hostname: str = None, 
                              from_time: str = None, to_time: str = None, 
                              limit: int = 100, filters: Dict = None) -> List[Dict]:
        """Enhanced log retrieval with comprehensive filtering"""
        try:
            # Build query with filters
            where_conditions = []
            params = []
            
            if hostname:
                where_conditions.append("Hostname = ?")
                params.append(hostname)
            
            if from_time:
                where_conditions.append("Time >= ?")
                params.append(from_time)
            
            if to_time:
                where_conditions.append("Time <= ?")
                params.append(to_time)
            
            # Additional filters
            if filters:
                if 'process_name' in filters:
                    where_conditions.append("ProcessName LIKE ?")
                    params.append(f"%{filters['process_name']}%")
                
                if 'event_type' in filters:
                    where_conditions.append("EventType = ?")
                    params.append(filters['event_type'])
                
                if 'protocol' in filters:
                    where_conditions.append("Protocol = ?")
                    params.append(filters['protocol'])
                
                if 'remote_port' in filters:
                    where_conditions.append("RemotePort = ?")
                    params.append(filters['remote_port'])
                
                if 'file_extension' in filters and table_name == 'FileLogs':
                    where_conditions.append("FileName LIKE ?")
                    params.append(f"%.{filters['file_extension']}")
                
                if 'min_file_size' in filters and table_name == 'FileLogs':
                    where_conditions.append("FileSize >= ?")
                    params.append(filters['min_file_size'])
                
                if 'user_name' in filters and table_name == 'ProcessLogs':
                    where_conditions.append("UserName = ?")
                    params.append(filters['user_name'])
            
            # Build final query
            where_clause = " WHERE " + " AND ".join(where_conditions) if where_conditions else ""
            query = f"SELECT TOP {limit} * FROM {table_name}{where_clause} ORDER BY Time DESC"
            
            return self.db.fetch_all(query, params)
            
        except Exception as e:
            logger.error(f"Error getting logs with filters: {e}")
            return []

    def get_log_statistics(self, hours: int = 24, hostname: str = None) -> Dict:
        """Enhanced log statistics with performance metrics"""
        try:
            stats = {
                'process_logs': 0,
                'file_logs': 0,
                'network_logs': 0,
                'total_logs': 0,
                'time_range_hours': hours,
                'top_processes': [],
                'top_files': [],
                'network_activity': {},
                'performance': {
                    'avg_logs_per_hour': 0,
                    'peak_hour': None,
                    'data_volume_mb': 0
                }
            }
            
            # Calculate time range
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=hours)
            start_time_str = start_time.strftime('%Y-%m-%d %H:%M:%S')
            
            base_where = f"Time >= '{start_time_str}'"
            if hostname:
                base_where += f" AND Hostname = '{hostname}'"
            
            # Get counts for each log type
            for log_type in ['ProcessLogs', 'FileLogs', 'NetworkLogs']:
                try:
                    count_query = f"SELECT COUNT(*) FROM {log_type} WHERE {base_where}"
                    result = self.db.fetch_one(count_query)
                    count = result[list(result.keys())[0]] if result else 0
                    
                    key = log_type.lower().replace('logs', '_logs')
                    stats[key] = count
                    stats['total_logs'] += count
                except Exception as e:
                    logger.error(f"Error counting {log_type}: {e}")
            
            # Performance calculations
            if hours > 0:
                stats['performance']['avg_logs_per_hour'] = stats['total_logs'] / hours
            
            # Get top processes
            try:
                process_query = f"""
                    SELECT TOP 10 ProcessName, COUNT(*) as LogCount
                    FROM ProcessLogs 
                    WHERE {base_where}
                    GROUP BY ProcessName 
                    ORDER BY LogCount DESC
                """
                stats['top_processes'] = self.db.fetch_all(process_query)
            except Exception as e:
                logger.error(f"Error getting top processes: {e}")
            
            # Get top files
            try:
                file_query = f"""
                    SELECT TOP 10 FileName, COUNT(*) as LogCount, 
                           AVG(CAST(FileSize as BIGINT)) as AvgSize
                    FROM FileLogs 
                    WHERE {base_where} AND FileSize IS NOT NULL
                    GROUP BY FileName 
                    ORDER BY LogCount DESC
                """
                stats['top_files'] = self.db.fetch_all(file_query)
            except Exception as e:
                logger.error(f"Error getting top files: {e}")
            
            # Network activity summary
            try:
                network_query = f"""
                    SELECT Protocol, Direction, COUNT(*) as ConnectionCount
                    FROM NetworkLogs 
                    WHERE {base_where}
                    GROUP BY Protocol, Direction
                """
                network_results = self.db.fetch_all(network_query)
                
                for row in network_results:
                    key = f"{row['Protocol']}_{row['Direction']}"
                    stats['network_activity'][key] = row['ConnectionCount']
            except Exception as e:
                logger.error(f"Error getting network activity: {e}")
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting log statistics: {e}")
            return {}

    def search_logs(self, search_term: str, log_types: List[str] = None, 
                   limit: int = 100, hostname: str = None,
                   time_range_hours: int = 24) -> Dict:
        """Enhanced search across multiple log types"""
        try:
            if not search_term:
                return {}
            
            if not log_types:
                log_types = ['process', 'file', 'network']
            
            search_pattern = f"%{search_term}%"
            results = {}
            
            # Time filter
            time_filter = ""
            if time_range_hours > 0:
                start_time = (datetime.now() - timedelta(hours=time_range_hours)).strftime('%Y-%m-%d %H:%M:%S')
                time_filter = f" AND Time >= '{start_time}'"
            
            # Hostname filter
            hostname_filter = f" AND Hostname = '{hostname}'" if hostname else ""
            
            # Search process logs
            if 'process' in log_types:
                query = f"""
                    SELECT TOP {limit} * FROM ProcessLogs 
                    WHERE (ProcessName LIKE ? OR CommandLine LIKE ? OR ExecutablePath LIKE ? OR UserName LIKE ?)
                    {time_filter}{hostname_filter}
                    ORDER BY Time DESC
                """
                results['process'] = self.db.fetch_all(query, [search_pattern] * 4)
            
            # Search file logs
            if 'file' in log_types:
                query = f"""
                    SELECT TOP {limit} * FROM FileLogs 
                    WHERE (FileName LIKE ? OR FilePath LIKE ? OR ProcessName LIKE ?)
                    {time_filter}{hostname_filter}
                    ORDER BY Time DESC
                """
                results['file'] = self.db.fetch_all(query, [search_pattern] * 3)
            
            # Search network logs
            if 'network' in log_types:
                query = f"""
                    SELECT TOP {limit} * FROM NetworkLogs 
                    WHERE (ProcessName LIKE ? OR RemoteAddress LIKE ? OR LocalAddress LIKE ?)
                    {time_filter}{hostname_filter}
                    ORDER BY Time DESC
                """
                results['network'] = self.db.fetch_all(query, [search_pattern] * 3)
            
            # Add summary
            results['summary'] = {
                'search_term': search_term,
                'total_matches': sum(len(logs) for logs in results.values() if isinstance(logs, list)),
                'log_types_searched': log_types,
                'time_range_hours': time_range_hours,
                'hostname': hostname
            }
            
            return results
            
        except Exception as e:
            logger.error(f"Error searching logs: {e}")
            return {}

    def cleanup_old_logs(self, days: int = 30, batch_size: int = 10000) -> Dict[str, int]:
        """Enhanced cleanup with batching and progress tracking"""
        try:
            cutoff_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
            cleanup_results = {}
            
            for table in ['ProcessLogs', 'FileLogs', 'NetworkLogs']:
                try:
                    total_deleted = 0
                    
                    # Count total records to delete
                    count_query = f"SELECT COUNT(*) FROM {table} WHERE Time < ?"
                    count_result = self.db.fetch_one(count_query, [cutoff_date])
                    total_to_delete = count_result[list(count_result.keys())[0]] if count_result else 0
                    
                    if total_to_delete == 0:
                        cleanup_results[table] = 0
                        continue
                    
                    # Delete in batches to avoid locking
                    while True:
                        delete_query = f"""
                            DELETE TOP ({batch_size}) FROM {table} 
                            WHERE Time < ?
                        """
                        
                        cursor = self.db.execute_query(delete_query, [cutoff_date])
                        if cursor:
                            rows_deleted = cursor.rowcount
                            cursor.close()
                            
                            if rows_deleted == 0:
                                break
                                
                            total_deleted += rows_deleted
                            logger.info(f"Deleted {rows_deleted} records from {table} (Total: {total_deleted}/{total_to_delete})")
                        else:
                            break
                    
                    cleanup_results[table] = total_deleted
                    logger.info(f"Cleanup completed for {table}: {total_deleted} records deleted")
                    
                except Exception as e:
                    logger.error(f"Error cleaning up {table}: {e}")
                    cleanup_results[table] = 0
            
            return cleanup_results
            
        except Exception as e:
            logger.error(f"Error cleaning up old logs: {e}")
            return {}

    def get_performance_metrics(self) -> Dict:
        """Get comprehensive performance metrics"""
        try:
            metrics = dict(self.stats)
            
            # Add database performance stats
            db_stats = self.db.get_performance_stats()
            metrics.update(db_stats)
            
            # Calculate additional metrics
            if self.stats['total_logs_processed'] > 0:
                metrics['success_rate'] = (
                    (self.stats['total_logs_processed'] - self.stats['failed_logs']) / 
                    self.stats['total_logs_processed'] * 100
                )
            else:
                metrics['success_rate'] = 0.0
            
            metrics['logs_per_batch'] = (
                self.stats['total_logs_processed'] / max(self.stats['batch_operations'], 1)
            )
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error getting performance metrics: {e}")
            return {}

    def optimize_tables(self) -> Dict[str, bool]:
        """Optimize log tables for better performance"""
        try:
            results = {}
            
            for table in ['ProcessLogs', 'FileLogs', 'NetworkLogs']:
                try:
                    # Update statistics
                    self.db.execute_non_query(f"UPDATE STATISTICS {table}")
                    
                    # Reorganize indexes
                    self.db.execute_non_query(f"ALTER INDEX ALL ON {table} REORGANIZE")
                    
                    results[table] = True
                    logger.info(f"Optimized table {table}")
                    
                except Exception as e:
                    logger.error(f"Error optimizing table {table}: {e}")
                    results[table] = False
            
            return results
            
        except Exception as e:
            logger.error(f"Error optimizing tables: {e}")
            return {}

    def get_log_distribution(self, hours: int = 24) -> Dict:
        """Get log distribution over time for visualization"""
        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=hours)
            
            distribution = {
                'time_range': {
                    'start': start_time.isoformat(),
                    'end': end_time.isoformat(),
                    'hours': hours
                },
                'hourly_distribution': {},
                'by_hostname': {},
                'by_log_type': {
                    'process': 0,
                    'file': 0,
                    'network': 0
                }
            }
            
            # Get hourly distribution
            for table, log_type in [('ProcessLogs', 'process'), ('FileLogs', 'file'), ('NetworkLogs', 'network')]:
                try:
                    query = f"""
                        SELECT 
                            DATEPART(hour, Time) as Hour,
                            COUNT(*) as LogCount,
                            COUNT(DISTINCT Hostname) as HostCount
                        FROM {table}
                        WHERE Time >= ? AND Time <= ?
                        GROUP BY DATEPART(hour, Time)
                        ORDER BY Hour
                    """
                    
                    results = self.db.fetch_all(query, [start_time, end_time])
                    
                    for row in results:
                        hour = row['Hour']
                        count = row['LogCount']
                        
                        if hour not in distribution['hourly_distribution']:
                            distribution['hourly_distribution'][hour] = {}
                        
                        distribution['hourly_distribution'][hour][log_type] = count
                        distribution['by_log_type'][log_type] += count
                        
                except Exception as e:
                    logger.error(f"Error getting distribution for {table}: {e}")
            
            # Get hostname distribution
            try:
                hostname_query = """
                    SELECT Hostname, COUNT(*) as TotalLogs FROM (
                        SELECT Hostname FROM ProcessLogs WHERE Time >= ? AND Time <= ?
                        UNION ALL
                        SELECT Hostname FROM FileLogs WHERE Time >= ? AND Time <= ?
                        UNION ALL
                        SELECT Hostname FROM NetworkLogs WHERE Time >= ? AND Time <= ?
                    ) combined
                    GROUP BY Hostname
                    ORDER BY TotalLogs DESC
                """
                
                hostname_results = self.db.fetch_all(hostname_query, [start_time, end_time] * 3)
                
                for row in hostname_results:
                    distribution['by_hostname'][row['Hostname']] = row['TotalLogs']
                    
            except Exception as e:
                logger.error(f"Error getting hostname distribution: {e}")
            
            return distribution
            
        except Exception as e:
            logger.error(f"Error getting log distribution: {e}")
            return {}

    def export_logs(self, log_type: str, filters: Dict = None, 
                   format_type: str = 'json', limit: int = 10000) -> List[Dict]:
        """Export logs with multiple format support"""
        try:
            if log_type not in ['process', 'file', 'network', 'all']:
                raise ValueError("Invalid log type")
            
            exported_logs = []
            
            if log_type == 'all':
                log_types = ['process', 'file', 'network']
            else:
                log_types = [log_type]
            
            for lt in log_types:
                try:
                    if lt == 'process':
                        logs = self.get_process_logs(limit=limit, filters=filters)
                    elif lt == 'file':
                        logs = self.get_file_logs(limit=limit, filters=filters)
                    elif lt == 'network':
                        logs = self.get_network_logs(limit=limit, filters=filters)
                    
                    for log in logs:
                        log['log_type'] = lt
                        # Convert datetime objects to strings for JSON serialization
                        for key, value in log.items():
                            if hasattr(value, 'strftime'):
                                log[key] = value.strftime('%Y-%m-%d %H:%M:%S')
                        exported_logs.append(log)
                        
                except Exception as e:
                    logger.error(f"Error exporting {lt} logs: {e}")
            
            # Sort by time
            exported_logs.sort(key=lambda x: x.get('Time', ''), reverse=True)
            
            return exported_logs[:limit]
            
        except Exception as e:
            logger.error(f"Error exporting logs: {e}")
            return []

    def get_agent_log_summary(self, hostname: str, hours: int = 24) -> Dict:
        """Enhanced agent log summary with trend analysis"""
        try:
            start_time = (datetime.now() - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
            
            summary = {
                'hostname': hostname,
                'time_range_hours': hours,
                'log_counts': {
                    'process_logs': 0,
                    'file_logs': 0,
                    'network_logs': 0,
                    'total_logs': 0
                },
                'activity_trends': {},
                'top_activities': {
                    'processes': [],
                    'files': [],
                    'connections': []
                },
                'security_indicators': {
                    'suspicious_processes': 0,
                    'executable_downloads': 0,
                    'external_connections': 0
                }
            }
            
            # Get log counts
            for table, key in [('ProcessLogs', 'process_logs'), ('FileLogs', 'file_logs'), ('NetworkLogs', 'network_logs')]:
                try:
                    count_query = f"SELECT COUNT(*) FROM {table} WHERE Hostname = ? AND Time >= ?"
                    result = self.db.fetch_one(count_query, [hostname, start_time])
                    count = result[list(result.keys())[0]] if result else 0
                    summary['log_counts'][key] = count
                    summary['log_counts']['total_logs'] += count
                except Exception as e:
                    logger.error(f"Error counting {table} for {hostname}: {e}")
            
            # Get top processes
            try:
                process_query = """
                    SELECT TOP 5 ProcessName, COUNT(*) as Count
                    FROM ProcessLogs 
                    WHERE Hostname = ? AND Time >= ?
                    GROUP BY ProcessName 
                    ORDER BY Count DESC
                """
                summary['top_activities']['processes'] = self.db.fetch_all(process_query, [hostname, start_time])
            except Exception as e:
                logger.error(f"Error getting top processes for {hostname}: {e}")
            
            # Get top files
            try:
                file_query = """
                    SELECT TOP 5 FileName, EventType, COUNT(*) as Count
                    FROM FileLogs 
                    WHERE Hostname = ? AND Time >= ?
                    GROUP BY FileName, EventType 
                    ORDER BY Count DESC
                """
                summary['top_activities']['files'] = self.db.fetch_all(file_query, [hostname, start_time])
            except Exception as e:
                logger.error(f"Error getting top files for {hostname}: {e}")
            
            # Get top network connections
            try:
                network_query = """
                    SELECT TOP 5 RemoteAddress, COUNT(*) as Count
                    FROM NetworkLogs 
                    WHERE Hostname = ? AND Time >= ?
                    GROUP BY RemoteAddress 
                    ORDER BY Count DESC
                """
                summary['top_activities']['connections'] = self.db.fetch_all(network_query, [hostname, start_time])
            except Exception as e:
                logger.error(f"Error getting top connections for {hostname}: {e}")
            
            # Security indicators
            try:
                # Suspicious processes
                suspicious_query = """
                    SELECT COUNT(*) FROM ProcessLogs 
                    WHERE Hostname = ? AND Time >= ?
                    AND (ProcessName IN ('cmd.exe', 'powershell.exe', 'wmic.exe') 
                         OR CommandLine LIKE '%vssadmin%' 
                         OR CommandLine LIKE '%bcdedit%')
                """
                result = self.db.fetch_one(suspicious_query, [hostname, start_time])
                summary['security_indicators']['suspicious_processes'] = result[list(result.keys())[0]] if result else 0
                
                # Executable downloads
                exec_query = """
                    SELECT COUNT(*) FROM FileLogs 
                    WHERE Hostname = ? AND Time >= ?
                    AND EventType = 'Create'
                    AND (FileName LIKE '%.exe' OR FileName LIKE '%.bat' OR FileName LIKE '%.scr')
                """
                result = self.db.fetch_one(exec_query, [hostname, start_time])
                summary['security_indicators']['executable_downloads'] = result[list(result.keys())[0]] if result else 0
                
                # External connections
                external_query = """
                    SELECT COUNT(*) FROM NetworkLogs 
                    WHERE Hostname = ? AND Time >= ?
                    AND Direction = 'Outbound'
                    AND RemoteAddress NOT LIKE '192.168.%'
                    AND RemoteAddress NOT LIKE '10.%'
                    AND RemoteAddress NOT LIKE '172.16.%'
                """
                result = self.db.fetch_one(external_query, [hostname, start_time])
                summary['security_indicators']['external_connections'] = result[list(result.keys())[0]] if result else 0
                
            except Exception as e:
                logger.error(f"Error calculating security indicators for {hostname}: {e}")
            
            return summary
            
        except Exception as e:
            logger.error(f"Error getting agent log summary for {hostname}: {e}")
            return {}

    def detect_anomalies(self, hostname: str = None, hours: int = 24) -> Dict:
        """Detect anomalous activities in logs"""
        try:
            anomalies = {
                'timestamp': datetime.now().isoformat(),
                'hostname': hostname,
                'time_range_hours': hours,
                'detected_anomalies': [],
                'risk_score': 0
            }
            
            start_time = (datetime.now() - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
            base_filter = f"Time >= '{start_time}'"
            
            if hostname:
                base_filter += f" AND Hostname = '{hostname}'"
            
            risk_score = 0
            
            # Detect unusual process activities
            try:
                unusual_processes_query = f"""
                    SELECT ProcessName, COUNT(*) as Count
                    FROM ProcessLogs 
                    WHERE {base_filter}
                    AND ProcessName IN ('cmd.exe', 'powershell.exe', 'wmic.exe', 'net.exe', 'reg.exe')
                    GROUP BY ProcessName
                    HAVING COUNT(*) > 50
                """
                
                unusual_processes = self.db.fetch_all(unusual_processes_query)
                
                for process in unusual_processes:
                    anomalies['detected_anomalies'].append({
                        'type': 'unusual_process_activity',
                        'description': f"High frequency execution of {process['ProcessName']}: {process['Count']} times",
                        'severity': 'medium',
                        'process_name': process['ProcessName'],
                        'count': process['Count']
                    })
                    risk_score += 10
                    
            except Exception as e:
                logger.error(f"Error detecting unusual processes: {e}")
            
            # Detect file system anomalies
            try:
                file_anomalies_query = f"""
                    SELECT FileName, EventType, COUNT(*) as Count
                    FROM FileLogs 
                    WHERE {base_filter}
                    AND (FileName LIKE '%.exe' OR FileName LIKE '%.bat' OR FileName LIKE '%.scr')
                    AND EventType = 'Create'
                    AND FilePath LIKE '%temp%'
                    GROUP BY FileName, EventType
                    HAVING COUNT(*) > 10
                """
                
                file_anomalies = self.db.fetch_all(file_anomalies_query)
                
                for file_anomaly in file_anomalies:
                    anomalies['detected_anomalies'].append({
                        'type': 'suspicious_file_creation',
                        'description': f"Multiple executable files created in temp: {file_anomaly['FileName']}",
                        'severity': 'high',
                        'file_name': file_anomaly['FileName'],
                        'count': file_anomaly['Count']
                    })
                    risk_score += 20
                    
            except Exception as e:
                logger.error(f"Error detecting file anomalies: {e}")
            
            # Detect network anomalies
            try:
                network_anomalies_query = f"""
                    SELECT RemoteAddress, RemotePort, COUNT(*) as Count
                    FROM NetworkLogs 
                    WHERE {base_filter}
                    AND Direction = 'Outbound'
                    AND RemotePort IN (4444, 5555, 6666, 8080, 1337)
                    GROUP BY RemoteAddress, RemotePort
                """
                
                network_anomalies = self.db.fetch_all(network_anomalies_query)
                
                for net_anomaly in network_anomalies:
                    anomalies['detected_anomalies'].append({
                        'type': 'suspicious_network_connection',
                        'description': f"Connection to suspicious port: {net_anomaly['RemoteAddress']}:{net_anomaly['RemotePort']}",
                        'severity': 'high',
                        'remote_address': net_anomaly['RemoteAddress'],
                        'remote_port': net_anomaly['RemotePort'],
                        'count': net_anomaly['Count']
                    })
                    risk_score += 25
                    
            except Exception as e:
                logger.error(f"Error detecting network anomalies: {e}")
            
            # Calculate final risk score
            anomalies['risk_score'] = min(risk_score, 100)
            
            if risk_score >= 50:
                anomalies['risk_level'] = 'high'
            elif risk_score >= 25:
                anomalies['risk_level'] = 'medium'
            else:
                anomalies['risk_level'] = 'low'
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error detecting anomalies: {e}")
            return {}

    def create_log_partitions(self) -> Dict[str, bool]:
        """Create table partitions for better performance (SQL Server specific)"""
        try:
            results = {}
            
            # This is a simplified partition creation
            # In production, you would want more sophisticated partitioning
            for table in ['ProcessLogs', 'FileLogs', 'NetworkLogs']:
                try:
                    # Check if partition function exists
                    check_query = """
                        SELECT COUNT(*) FROM sys.partition_functions 
                        WHERE name = ?
                    """
                    
                    pf_name = f"pf_{table}_Time"
                    result = self.db.fetch_one(check_query, [pf_name])
                    
                    if result and result[list(result.keys())[0]] == 0:
                        # Create partition function
                        partition_query = f"""
                            CREATE PARTITION FUNCTION {pf_name} (DATETIME)
                            AS RANGE RIGHT FOR VALUES (
                                '{(datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')}',
                                '{(datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')}',
                                '{datetime.now().strftime('%Y-%m-%d')}'
                            )
                        """
                        
                        self.db.execute_non_query(partition_query)
                        logger.info(f"Created partition function for {table}")
                    
                    results[table] = True
                    
                except Exception as e:
                    logger.error(f"Error creating partition for {table}: {e}")
                    results[table] = False
            
            return results
            
        except Exception as e:
            logger.error(f"Error creating log partitions: {e}")
            return {}

    def archive_old_logs(self, days: int = 90, archive_path: str = None) -> Dict:
        """Archive old logs to file system"""
        try:
            if not archive_path:
                archive_path = "logs/archive"
            
            # Create archive directory
            os.makedirs(archive_path, exist_ok=True)
            
            cutoff_date = datetime.now() - timedelta(days=days)
            archive_results = {
                'archived_files': [],
                'total_records': 0,
                'success': True
            }
            
            for table in ['ProcessLogs', 'FileLogs', 'NetworkLogs']:
                try:
                    # Export old logs to JSON file
                    archive_file = os.path.join(archive_path, f"{table}_{cutoff_date.strftime('%Y%m%d')}.json")
                    
                    query = f"""
                        SELECT * FROM {table} 
                        WHERE Time < ?
                        ORDER BY Time
                    """
                    
                    old_logs = self.db.fetch_all(query, [cutoff_date])
                    
                    if old_logs:
                        # Convert datetime objects for JSON serialization
                        for log in old_logs:
                            for key, value in log.items():
                                if hasattr(value, 'strftime'):
                                    log[key] = value.strftime('%Y-%m-%d %H:%M:%S')
                        
                        # Write to file
                        with open(archive_file, 'w', encoding='utf-8') as f:
                            json.dump(old_logs, f, indent=2)
                        
                        archive_results['archived_files'].append({
                            'table': table,
                            'file': archive_file,
                            'records': len(old_logs)
                        })
                        
                        archive_results['total_records'] += len(old_logs)
                        
                        logger.info(f"Archived {len(old_logs)} records from {table} to {archive_file}")
                    
                except Exception as e:
                    logger.error(f"Error archiving {table}: {e}")
                    archive_results['success'] = False
            
            return archive_results
            
        except Exception as e:
            logger.error(f"Error archiving old logs: {e}")
            return {'success': False, 'error': str(e)}

    def __del__(self):
        """Cleanup thread pool on destruction"""
        try:
            if hasattr(self, 'executor'):
                self.executor.shutdown(wait=True)
        except:
            pass