"""
Agent Database Operations - IMPROVED VERSION
Xử lý tất cả operations liên quan đến agents trong database với enhanced performance và error handling
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from .connection import DatabaseConnection, DatabaseError, ConnectionError
from utils.helpers import (
    validate_hostname, validate_ip_address, validate_mac_address,
    normalize_hostname, normalize_mac_address, sanitize_string
)
from pydantic import BaseModel, Field, validator
from functools import lru_cache
import threading
import time

class AgentRegistration(BaseModel):
    """Pydantic model for agent registration validation"""
    hostname: str = Field(..., min_length=1, max_length=255)
    os_type: str = Field(..., regex="^(Windows|Linux|macOS|Unknown)$")
    os_version: str = Field(default="Unknown", max_length=100)
    architecture: str = Field(default="Unknown", max_length=20)
    agent_version: str = Field(default="1.0.0", regex="^\\d+\\.\\d+\\.\\d+(\\.\\d+)?$")
    ip_address: Optional[str] = Field(None, regex="^\\d+\\.\\d+\\.\\d+\\.\\d+$")
    mac_address: Optional[str] = None
    
    @validator('hostname')
    def validate_hostname_format(cls, v):
        if not validate_hostname(v):
            raise ValueError('Invalid hostname format')
        return normalize_hostname(v)
    
    @validator('ip_address')
    def validate_ip_format(cls, v):
        if v and not validate_ip_address(v):
            raise ValueError('Invalid IP address format')
        return v
    
    @validator('mac_address')
    def validate_mac_format(cls, v):
        if v and not validate_mac_address(v):
            raise ValueError('Invalid MAC address format')
        return normalize_mac_address(v) if v else None

class AgentNotFoundError(DatabaseError):
    """Agent not found exception"""
    pass

class AgentAlreadyExistsError(DatabaseError):
    """Agent already exists exception"""
    pass

class AgentDB:
    def __init__(self):
        self.db = DatabaseConnection()
        self.db.connect()
        self.logger = logging.getLogger(__name__)
        self._cache = {}
        self._cache_lock = threading.RLock()
        self._cache_ttl = 300  # 5 minutes
    
    def register_agent(self, agent_data: Dict) -> bool:
        """Đăng ký agent mới hoặc cập nhật agent hiện có với validation"""
        try:
            # Validate input data using Pydantic
            validated_data = AgentRegistration(**agent_data)
            
            # Use UPSERT operation to handle race conditions
            success = self._upsert_agent(validated_data)
            
            if success:
                self.logger.info(f"Agent registered/updated: {validated_data.hostname}")
                
                # Clear cache for this agent
                self._clear_agent_cache(validated_data.hostname)
                
                # Assign global rules for new agents
                if not self._agent_exists_in_cache(validated_data.hostname):
                    self._assign_global_rules(validated_data.hostname, validated_data.os_type)
                
            return success
                
        except ValueError as e:
            self.logger.error(f"Validation error registering agent: {e}")
            raise DatabaseError(f"Invalid agent data: {e}")
        except Exception as e:
            self.logger.error(f"Error registering agent: {e}")
            raise DatabaseError(f"Failed to register agent: {e}")
    
    def _upsert_agent(self, agent_data: AgentRegistration) -> bool:
        """UPSERT agent using MERGE statement to avoid race conditions"""
        try:
            current_time = datetime.now()
            
            merge_query = """
            MERGE Agents AS target
            USING (VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)) AS source 
                (Hostname, OSType, OSVersion, Architecture, AgentVersion, IPAddress, MACAddress, 
                 Status, LastHeartbeat, LastSeen, IsActive)
            ON target.Hostname = source.Hostname
            WHEN MATCHED THEN
                UPDATE SET 
                    OSType = source.OSType,
                    OSVersion = source.OSVersion,
                    Architecture = source.Architecture,
                    AgentVersion = source.AgentVersion,
                    IPAddress = COALESCE(source.IPAddress, target.IPAddress),
                    MACAddress = COALESCE(source.MACAddress, target.MACAddress),
                    Status = 'Online',
                    LastHeartbeat = source.LastHeartbeat,
                    LastSeen = source.LastSeen,
                    IsActive = 1
            WHEN NOT MATCHED THEN
                INSERT (Hostname, OSType, OSVersion, Architecture, AgentVersion, IPAddress, MACAddress,
                       Status, LastHeartbeat, LastSeen, IsActive, FirstSeen)
                VALUES (source.Hostname, source.OSType, source.OSVersion, source.Architecture,
                       source.AgentVersion, source.IPAddress, source.MACAddress, 'Online',
                       source.LastHeartbeat, source.LastSeen, 1, ?);
            """
            
            params = [
                agent_data.hostname,
                agent_data.os_type,
                agent_data.os_version,
                agent_data.architecture,
                agent_data.agent_version,
                agent_data.ip_address,
                agent_data.mac_address,
                'Online',
                current_time,
                current_time,
                1,
                current_time  # FirstSeen for INSERT case
            ]
            
            return self.db.execute_non_query(merge_query, params)
            
        except Exception as e:
            self.logger.error(f"Error in agent upsert: {e}")
            return False
    
    def _assign_global_rules(self, hostname: str, os_type: str):
        """Assign global rules cho agent mới với batch operation"""
        try:
            # Get global rules for OS type
            query = """
                SELECT RuleID FROM Rules 
                WHERE IsGlobal = 1 AND IsActive = 1 
                AND (OSType = ? OR OSType = 'All')
            """
            
            cursor = self.db.execute_query(query, [os_type])
            if not cursor:
                return
            
            rule_ids = [row.RuleID for row in cursor.fetchall()]
            cursor.close()
            
            if rule_ids:
                # Batch insert rule assignments
                self._batch_assign_rules(hostname, rule_ids)
                self.logger.info(f"Assigned {len(rule_ids)} global rules to {hostname}")
            
        except Exception as e:
            self.logger.error(f"Error assigning global rules to {hostname}: {e}")
    
    def _batch_assign_rules(self, hostname: str, rule_ids: List[int]):
        """Batch assign multiple rules to agent"""
        try:
            current_time = datetime.now()
            
            # Build batch insert query
            values_clause = ', '.join(['(?, ?, 1, ?)' for _ in rule_ids])
            query = f"""
                INSERT INTO AgentRules (RuleID, Hostname, IsActive, AppliedAt)
                VALUES {values_clause}
            """
            
            # Flatten parameters
            params = []
            for rule_id in rule_ids:
                params.extend([rule_id, hostname, current_time])
            
            self.db.execute_non_query(query, params)
            
        except Exception as e:
            self.logger.error(f"Error in batch rule assignment: {e}")
            # Fallback to individual inserts
            for rule_id in rule_ids:
                try:
                    self.assign_rule(hostname, rule_id)
                except Exception as inner_e:
                    self.logger.error(f"Failed to assign rule {rule_id} to {hostname}: {inner_e}")
    
    @lru_cache(maxsize=1000)
    def get_agent(self, hostname: str) -> Optional[Dict]:
        """Lấy thông tin agent theo hostname với caching"""
        try:
            # Check cache first
            cache_key = f"agent:{hostname}"
            cached_result = self._get_from_cache(cache_key)
            if cached_result is not None:
                return cached_result
            
            query = "SELECT * FROM Agents WHERE Hostname = ? AND IsActive = 1"
            result = self.db.fetch_one(query, [hostname])
            
            # Cache the result
            if result:
                self._set_cache(cache_key, result)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error getting agent {hostname}: {e}")
            raise AgentNotFoundError(f"Failed to get agent {hostname}: {e}")
    
    def get_all_agents(self, include_inactive: bool = False) -> List[Dict]:
        """Lấy tất cả agents với optional inactive agents"""
        try:
            cache_key = f"all_agents:active_{not include_inactive}"
            cached_result = self._get_from_cache(cache_key)
            if cached_result is not None:
                return cached_result
            
            where_clause = "" if include_inactive else "WHERE IsActive = 1"
            query = f"""
                SELECT * FROM Agents 
                {where_clause}
                ORDER BY LastSeen DESC, Hostname ASC
            """
            
            result = self.db.fetch_all(query)
            
            # Cache for shorter time since this changes frequently
            self._set_cache(cache_key, result, ttl=60)  # 1 minute cache
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error getting all agents: {e}")
            return []
    
    def get_online_agents(self, threshold_minutes: int = 5) -> List[Dict]:
        """Lấy agents đang online với configurable threshold"""
        try:
            threshold = datetime.now() - timedelta(minutes=threshold_minutes)
            
            query = """
                SELECT * FROM Agents 
                WHERE Status = 'Online' 
                AND LastSeen >= ?
                AND IsActive = 1
                ORDER BY LastSeen DESC
            """
            return self.db.fetch_all(query, [threshold])
            
        except Exception as e:
            self.logger.error(f"Error getting online agents: {e}")
            return []
    
    def get_agents_by_os(self, os_type: str) -> List[Dict]:
        """Lấy agents theo OS type với caching"""
        try:
            cache_key = f"agents_by_os:{os_type}"
            cached_result = self._get_from_cache(cache_key)
            if cached_result is not None:
                return cached_result
            
            query = """
                SELECT * FROM Agents 
                WHERE OSType = ? AND IsActive = 1
                ORDER BY LastSeen DESC
            """
            result = self.db.fetch_all(query, [os_type])
            
            self._set_cache(cache_key, result, ttl=120)  # 2 minute cache
            return result
            
        except Exception as e:
            self.logger.error(f"Error getting agents by OS {os_type}: {e}")
            return []
    
    def update_agent_status(self, hostname: str, status: str) -> bool:
        """Cập nhật trạng thái agent với validation"""
        try:
            valid_statuses = ['Online', 'Offline', 'Maintenance', 'Error', 'Updating']
            if status not in valid_statuses:
                raise ValueError(f"Invalid status: {status}. Must be one of: {valid_statuses}")
            
            update_data = {
                'Status': status,
                'LastSeen': datetime.now()
            }
            
            success = self.db.update_data(
                'Agents',
                update_data,
                'Hostname = ? AND IsActive = 1',
                [hostname]
            )
            
            if success:
                self._clear_agent_cache(hostname)
                self.logger.debug(f"Agent {hostname} status updated to {status}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error updating agent status {hostname}: {e}")
            return False
    
    def update_heartbeat(self, hostname: str, system_info: Dict = None) -> bool:
        """Cập nhật heartbeat của agent với optional system info"""
        try:
            current_time = datetime.now()
            update_data = {
                'LastHeartbeat': current_time,
                'LastSeen': current_time,
                'Status': 'Online'
            }
            
            # Update system info if provided
            if system_info:
                if 'cpu_usage' in system_info:
                    update_data['CPUUsage'] = system_info['cpu_usage']
                if 'memory_usage' in system_info:
                    update_data['MemoryUsage'] = system_info['memory_usage']
                if 'disk_usage' in system_info:
                    update_data['DiskUsage'] = system_info['disk_usage']
            
            success = self.db.update_data(
                'Agents',
                update_data,
                'Hostname = ? AND IsActive = 1',
                [hostname]
            )
            
            if success:
                self._clear_agent_cache(hostname)
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error updating heartbeat {hostname}: {e}")
            return False
    
    def cleanup_offline_agents(self, minutes_threshold: int = 5) -> int:
        """Batch cleanup agents offline nếu không heartbeat trong threshold"""
        try:
            threshold = datetime.now() - timedelta(minutes=minutes_threshold)
            
            query = """
                UPDATE Agents 
                SET Status = 'Offline'
                WHERE LastHeartbeat < ? 
                AND Status = 'Online'
                AND IsActive = 1
            """
            
            cursor = self.db.execute_query(query, [threshold])
            if cursor:
                affected_rows = cursor.rowcount
                cursor.close()
                
                if affected_rows > 0:
                    self.logger.info(f"Marked {affected_rows} agents as offline")
                    self._clear_cache_pattern("agent:")  # Clear agent caches
                
                return affected_rows
            
            return 0
            
        except Exception as e:
            self.logger.error(f"Error cleaning up offline agents: {e}")
            return 0
    
    def assign_rule(self, hostname: str, rule_id: int) -> bool:
        """Assign rule cho agent với conflict handling"""
        try:
            # Use UPSERT to handle conflicts
            upsert_query = """
            MERGE AgentRules AS target
            USING (VALUES (?, ?, 1, ?)) AS source (Hostname, RuleID, IsActive, AppliedAt)
            ON target.Hostname = source.Hostname AND target.RuleID = source.RuleID
            WHEN MATCHED THEN
                UPDATE SET IsActive = 1, AppliedAt = source.AppliedAt
            WHEN NOT MATCHED THEN
                INSERT (Hostname, RuleID, IsActive, AppliedAt)
                VALUES (source.Hostname, source.RuleID, source.IsActive, source.AppliedAt);
            """
            
            current_time = datetime.now()
            success = self.db.execute_non_query(upsert_query, [hostname, rule_id, current_time])
            
            if success:
                self._clear_agent_rules_cache(hostname)
                self.logger.debug(f"Rule {rule_id} assigned to {hostname}")
            
            return success
                
        except Exception as e:
            self.logger.error(f"Error assigning rule {rule_id} to {hostname}: {e}")
            return False
    
    def unassign_rule(self, hostname: str, rule_id: int) -> bool:
        """Unassign rule từ agent"""
        try:
            success = self.db.update_data(
                'AgentRules',
                {'IsActive': 0},
                'Hostname = ? AND RuleID = ?',
                [hostname, rule_id]
            )
            
            if success:
                self._clear_agent_rules_cache(hostname)
                self.logger.debug(f"Rule {rule_id} unassigned from {hostname}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error unassigning rule {rule_id} from {hostname}: {e}")
            return False
    
    def bulk_assign_rules(self, hostname: str, rule_ids: List[int]) -> Tuple[int, int]:
        """Bulk assign multiple rules to agent"""
        try:
            success_count = 0
            failed_count = 0
            
            with self.db.transaction():
                for rule_id in rule_ids:
                    if self.assign_rule(hostname, rule_id):
                        success_count += 1
                    else:
                        failed_count += 1
            
            self.logger.info(f"Bulk assign to {hostname}: {success_count} success, {failed_count} failed")
            return success_count, failed_count
            
        except Exception as e:
            self.logger.error(f"Error in bulk rule assignment to {hostname}: {e}")
            return 0, len(rule_ids)
    
    def get_agent_rules(self, hostname: str) -> List[int]:
        """Lấy danh sách rule IDs được assign cho agent với caching"""
        try:
            cache_key = f"agent_rules:{hostname}"
            cached_result = self._get_from_cache(cache_key)
            if cached_result is not None:
                return cached_result
            
            query = """
                SELECT RuleID FROM AgentRules 
                WHERE Hostname = ? AND IsActive = 1
            """
            
            cursor = self.db.execute_query(query, [hostname])
            if cursor:
                rule_ids = [row.RuleID for row in cursor.fetchall()]
                cursor.close()
                
                self._set_cache(cache_key, rule_ids)
                return rule_ids
            
            return []
            
        except Exception as e:
            self.logger.error(f"Error getting rules for agent {hostname}: {e}")
            return []
    
    def get_agent_detailed_rules(self, hostname: str) -> List[Dict]:
        """Lấy thông tin chi tiết rules của agent"""
        try:
            query = """
                SELECT r.*, ar.AppliedAt, ar.IsActive as RuleAssigned
                FROM Rules r
                INNER JOIN AgentRules ar ON r.RuleID = ar.RuleID
                WHERE ar.Hostname = ? AND ar.IsActive = 1
                ORDER BY r.Severity DESC, r.RuleName ASC
            """
            
            return self.db.fetch_all(query, [hostname])
            
        except Exception as e:
            self.logger.error(f"Error getting detailed rules for agent {hostname}: {e}")
            return []
    
    def delete_agent(self, hostname: str, hard_delete: bool = False) -> bool:
        """Xóa agent (soft delete mặc định, hard delete optional)"""
        try:
            if hard_delete:
                # Hard delete - remove completely
                with self.db.transaction():
                    # Delete rule assignments first
                    self.db.execute_non_query(
                        "DELETE FROM AgentRules WHERE Hostname = ?",
                        [hostname]
                    )
                    
                    # Delete agent
                    success = self.db.execute_non_query(
                        "DELETE FROM Agents WHERE Hostname = ?",
                        [hostname]
                    )
            else:
                # Soft delete - set IsActive = 0
                update_data = {
                    'IsActive': 0,
                    'Status': 'Deleted',
                    'LastSeen': datetime.now()
                }
                
                success = self.db.update_data(
                    'Agents',
                    update_data,
                    'Hostname = ?',
                    [hostname]
                )
                
                if success:
                    # Deactivate all rule assignments
                    self.db.update_data(
                        'AgentRules',
                        {'IsActive': 0},
                        'Hostname = ?',
                        [hostname]
                    )
            
            if success:
                self._clear_agent_cache(hostname)
                self._clear_agent_rules_cache(hostname)
                delete_type = "hard" if hard_delete else "soft"
                self.logger.info(f"Agent {hostname} {delete_type} deleted")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error deleting agent {hostname}: {e}")
            return False
    
    def get_agents_statistics(self) -> Dict:
        """Lấy thống kê agents với enhanced metrics"""
        try:
            stats = {
                'total_agents': 0,
                'online_agents': 0,
                'offline_agents': 0,
                'by_os_type': {},
                'by_status': {},
                'by_version': {},
                'recent_registrations': 0,
                'inactive_agents': 0,
                'performance_metrics': {}
            }
            
            # Get all agents with status info
            query = """
                SELECT 
                    OSType, Status, AgentVersion, FirstSeen, IsActive,
                    CASE 
                        WHEN LastSeen >= DATEADD(minute, -5, GETDATE()) THEN 'Online'
                        ELSE 'Offline'
                    END as RealTimeStatus
                FROM Agents
            """
            
            agents = self.db.fetch_all(query)
            
            recent_threshold = datetime.now() - timedelta(hours=24)
            
            for agent in agents:
                is_active = agent.get('IsActive', True)
                
                if is_active:
                    stats['total_agents'] += 1
                    
                    # Real-time status based on last seen
                    realtime_status = agent.get('RealTimeStatus', 'Offline')
                    if realtime_status == 'Online':
                        stats['online_agents'] += 1
                    else:
                        stats['offline_agents'] += 1
                    
                    # By OS Type
                    os_type = agent.get('OSType', 'Unknown')
                    stats['by_os_type'][os_type] = stats['by_os_type'].get(os_type, 0) + 1
                    
                    # By Status
                    status = agent.get('Status', 'Unknown')
                    stats['by_status'][status] = stats['by_status'].get(status, 0) + 1
                    
                    # By Version
                    version = agent.get('AgentVersion', 'Unknown')
                    stats['by_version'][version] = stats['by_version'].get(version, 0) + 1
                    
                    # Recent registrations
                    first_seen = agent.get('FirstSeen')
                    if first_seen:
                        try:
                            if isinstance(first_seen, str):
                                first_seen_dt = datetime.strptime(first_seen, '%Y-%m-%d %H:%M:%S')
                            else:
                                first_seen_dt = first_seen
                                
                            if first_seen_dt >= recent_threshold:
                                stats['recent_registrations'] += 1
                        except:
                            pass
                else:
                    stats['inactive_agents'] += 1
            
            # Performance metrics
            stats['performance_metrics'] = {
                'uptime_percentage': (stats['online_agents'] / max(stats['total_agents'], 1)) * 100,
                'agent_distribution_score': len(stats['by_os_type']),
                'version_diversity': len(stats['by_version'])
            }
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error getting agents statistics: {e}")
            return {}
    
    def search_agents(self, search_term: str, filters: Dict = None) -> List[Dict]:
        """Enhanced agent search với advanced filtering"""
        try:
            search_pattern = f"%{search_term}%"
            where_conditions = ["IsActive = 1"]
            params = []
            
            # Base search
            if search_term:
                where_conditions.append("""(
                    Hostname LIKE ? OR 
                    IPAddress LIKE ? OR 
                    OSType LIKE ? OR 
                    OSVersion LIKE ? OR
                    AgentVersion LIKE ?
                )""")
                params.extend([search_pattern] * 5)
            
            # Additional filters
            if filters:
                if 'status' in filters:
                    where_conditions.append("Status = ?")
                    params.append(filters['status'])
                
                if 'os_type' in filters:
                    where_conditions.append("OSType = ?")
                    params.append(filters['os_type'])
                
                if 'online_only' in filters and filters['online_only']:
                    where_conditions.append("LastSeen >= DATEADD(minute, -5, GETDATE())")
                
                if 'version' in filters:
                    where_conditions.append("AgentVersion = ?")
                    params.append(filters['version'])
            
            query = f"""
                SELECT * FROM Agents 
                WHERE {' AND '.join(where_conditions)}
                ORDER BY LastSeen DESC
            """
            
            return self.db.fetch_all(query, params)
            
        except Exception as e:
            self.logger.error(f"Error searching agents: {e}")
            return []
    
    def get_agent_activity_summary(self, hostname: str, hours: int = 24) -> Dict:
        """Enhanced activity summary với performance metrics"""
        try:
            agent = self.get_agent(hostname)
            if not agent:
                raise AgentNotFoundError(f"Agent {hostname} not found")
            
            start_time = datetime.now() - timedelta(hours=hours)
            
            summary = {
                'hostname': hostname,
                'status': agent.get('Status'),
                'last_seen': agent.get('LastSeen'),
                'os_type': agent.get('OSType'),
                'agent_version': agent.get('AgentVersion'),
                'period_hours': hours,
                'connection_stability': self._calculate_connection_stability(hostname, hours),
                'rule_compliance': self._calculate_rule_compliance(hostname),
                'activity_level': 'normal'  # Will be calculated based on logs
            }
            
            # Get log counts (if LogDB is available)
            try:
                from .logs import LogDB
                log_db = LogDB()
                
                log_counts = {
                    'process_logs': len(log_db.get_process_logs(hostname, 
                                                              start_time.strftime('%Y-%m-%d %H:%M:%S'), 
                                                              limit=1000)),
                    'file_logs': len(log_db.get_file_logs(hostname, 
                                                        start_time.strftime('%Y-%m-%d %H:%M:%S'), 
                                                        limit=1000)),
                    'network_logs': len(log_db.get_network_logs(hostname, 
                                                              start_time.strftime('%Y-%m-%d %H:%M:%S'), 
                                                              limit=1000))
                }
                
                total_logs = sum(log_counts.values())
                log_counts['total_logs'] = total_logs
                
                # Determine activity level
                if total_logs > 500:
                    summary['activity_level'] = 'high'
                elif total_logs > 100:
                    summary['activity_level'] = 'normal'
                else:
                    summary['activity_level'] = 'low'
                
                summary['log_counts'] = log_counts
                
            except ImportError:
                summary['log_counts'] = {'total_logs': 0, 'error': 'LogDB not available'}
            
            # Get alert counts (if AlertDB is available)
            try:
                from .alerts import AlertDB
                alert_db = AlertDB()
                
                alerts = alert_db.get_alerts({
                    'hostname': hostname,
                    'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S')
                }, 1000)
                
                alert_counts = {
                    'total_alerts': len(alerts),
                    'critical_alerts': len([a for a in alerts if a.get('Severity') == 'Critical']),
                    'high_alerts': len([a for a in alerts if a.get('Severity') == 'High']),
                    'resolved_alerts': len([a for a in alerts if a.get('Status') == 'Resolved'])
                }
                
                summary['alert_counts'] = alert_counts
                
            except ImportError:
                summary['alert_counts'] = {'total_alerts': 0, 'error': 'AlertDB not available'}
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Error getting activity summary for {hostname}: {e}")
            return {}
    
    def _calculate_connection_stability(self, hostname: str, hours: int) -> float:
        """Calculate connection stability score"""
        try:
            # This would require connection history tracking
            # For now, return a simple score based on current status
            agent = self.get_agent(hostname)
            if not agent:
                return 0.0
            
            if agent.get('Status') == 'Online':
                return 95.0
            elif agent.get('Status') == 'Offline':
                return 60.0
            else:
                return 80.0
                
        except Exception:
            return 50.0
    
    def _calculate_rule_compliance(self, hostname: str) -> float:
        """Calculate rule compliance score"""
        try:
            total_rules = len(self.get_agent_rules(hostname))
            if total_rules == 0:
                return 0.0
            
            # Simple compliance score based on number of active rules
            if total_rules >= 10:
                return 100.0
            elif total_rules >= 5:
                return 80.0
            else:
                return 60.0
                
        except Exception:
            return 50.0
    
    def bulk_update_agents(self, updates: List[Dict]) -> Dict:
        """Enhanced bulk update với transaction và error handling"""
        try:
            success_count = 0
            failed_count = 0
            errors = []
            
            with self.db.transaction():
                for update in updates:
                    try:
                        hostname = update.get('hostname')
                        if not hostname:
                            failed_count += 1
                            errors.append("Missing hostname in update")
                            continue
                        
                        # Validate hostname exists
                        if not self.get_agent(hostname):
                            failed_count += 1
                            errors.append(f"Agent {hostname} not found")
                            continue
                        
                        update_data = {k: v for k, v in update.items() if k != 'hostname'}
                        
                        if self.db.update_data('Agents', update_data, 'Hostname = ?', [hostname]):
                            success_count += 1
                            self._clear_agent_cache(hostname)
                        else:
                            failed_count += 1
                            errors.append(f"Failed to update {hostname}")
                            
                    except Exception as e:
                        failed_count += 1
                        errors.append(f"Error updating {update.get('hostname', 'unknown')}: {str(e)}")
            
            self.logger.info(f"Bulk update: {success_count} success, {failed_count} failed")
            
            return {
                'success_count': success_count,
                'failed_count': failed_count,
                'total': len(updates),
                'errors': errors[:10]  # Limit error list
            }
            
        except Exception as e:
            self.logger.error(f"Error in bulk update agents: {e}")
            return {
                'success_count': 0, 
                'failed_count': len(updates), 
                'total': len(updates),
                'errors': [str(e)]
            }
    
    # Cache management methods
    def _get_from_cache(self, key: str) -> Any:
        """Get item from cache with TTL check"""
        with self._cache_lock:
            if key in self._cache:
                value, timestamp = self._cache[key]
                if time.time() - timestamp < self._cache_ttl:
                    return value
                else:
                    del self._cache[key]
            return None
    
    def _set_cache(self, key: str, value: Any, ttl: int = None) -> None:
        """Set item in cache with TTL"""
        with self._cache_lock:
            if ttl is None:
                ttl = self._cache_ttl
            self._cache[key] = (value, time.time())
            
            # Simple cache cleanup
            if len(self._cache) > 1000:
                self._cleanup_cache()
    
    def _clear_agent_cache(self, hostname: str) -> None:
        """Clear all cache entries for specific agent"""
        with self._cache_lock:
            keys_to_remove = [
                f"agent:{hostname}",
                f"agent_rules:{hostname}"
            ]
            
            for key in keys_to_remove:
                self._cache.pop(key, None)
    
    def _clear_agent_rules_cache(self, hostname: str) -> None:
        """Clear agent rules cache"""
        with self._cache_lock:
            self._cache.pop(f"agent_rules:{hostname}", None)
    
    def _clear_cache_pattern(self, pattern: str) -> None:
        """Clear cache entries matching pattern"""
        with self._cache_lock:
            keys_to_remove = [key for key in self._cache.keys() if pattern in key]
            for key in keys_to_remove:
                del self._cache[key]
    
    def _cleanup_cache(self) -> None:
        """Clean up expired cache entries"""
        current_time = time.time()
        with self._cache_lock:
            expired_keys = [
                key for key, (value, timestamp) in self._cache.items()
                if current_time - timestamp >= self._cache_ttl
            ]
            for key in expired_keys:
                del self._cache[key]
    
    def _agent_exists_in_cache(self, hostname: str) -> bool:
        """Check if agent exists in cache"""
        return self._get_from_cache(f"agent:{hostname}") is not None
    
    def get_cache_stats(self) -> Dict:
        """Get cache statistics"""
        with self._cache_lock:
            current_time = time.time()
            expired_count = sum(
                1 for _, (_, timestamp) in self._cache.items()
                if current_time - timestamp >= self._cache_ttl
            )
            
            return {
                'total_entries': len(self._cache),
                'expired_entries': expired_count,
                'active_entries': len(self._cache) - expired_count,
                'cache_ttl': self._cache_ttl
            }