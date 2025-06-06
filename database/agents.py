"""
Agent Database Operations
Xử lý tất cả operations liên quan đến agents trong database
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from .connection import DatabaseConnection
from utils.helpers import (
    validate_hostname, validate_ip_address, validate_mac_address,
    normalize_hostname, normalize_mac_address, sanitize_string
)

class AgentDB:
    def __init__(self):
        self.db = DatabaseConnection()
        self.db.connect()
        self.logger = logging.getLogger(__name__)
    
    def register_agent(self, agent_data: Dict) -> bool:
        """Đăng ký agent mới hoặc cập nhật agent hiện có"""
        try:
            # Validate và normalize dữ liệu
            hostname = agent_data.get('hostname', '').strip()
            if not hostname or not validate_hostname(hostname):
                self.logger.error(f"Invalid hostname: {hostname}")
                return False
            
            hostname = normalize_hostname(hostname)
            
            # Kiểm tra agent đã tồn tại chưa
            existing_agent = self.get_agent(hostname)
            
            if existing_agent:
                # Cập nhật agent hiện có
                return self._update_existing_agent(hostname, agent_data)
            else:
                # Tạo agent mới
                return self._create_new_agent(hostname, agent_data)
                
        except Exception as e:
            self.logger.error(f"Error registering agent: {e}")
            return False
    
    def _create_new_agent(self, hostname: str, agent_data: Dict) -> bool:
        """Tạo agent mới"""
        try:
            # Chuẩn bị dữ liệu
            normalized_data = self._normalize_agent_data(hostname, agent_data)
            
            # Insert vào database
            success = self.db.insert_data('Agents', normalized_data)
            
            if success:
                self.logger.info(f"New agent registered: {hostname}")
                
                # Assign global rules cho agent mới
                self._assign_global_rules(hostname, normalized_data.get('OSType', 'Unknown'))
                
            return success
            
        except Exception as e:
            self.logger.error(f"Error creating new agent {hostname}: {e}")
            return False
    
    def _update_existing_agent(self, hostname: str, agent_data: Dict) -> bool:
        """Cập nhật agent hiện có"""
        try:
            # Chuẩn bị dữ liệu update
            update_data = {
                'Status': 'Online',
                'LastSeen': datetime.now(),
                'LastHeartbeat': datetime.now(),
                'IsActive': 1
            }
            
            # Cập nhật thông tin nếu có
            if 'ip_address' in agent_data:
                ip = agent_data['ip_address']
                if validate_ip_address(ip):
                    update_data['IPAddress'] = ip
            
            if 'mac_address' in agent_data:
                mac = agent_data['mac_address']
                if validate_mac_address(mac):
                    update_data['MACAddress'] = normalize_mac_address(mac)
            
            if 'agent_version' in agent_data:
                update_data['AgentVersion'] = sanitize_string(agent_data['agent_version'])
            
            if 'os_version' in agent_data:
                update_data['OSVersion'] = sanitize_string(agent_data['os_version'])
            
            if 'architecture' in agent_data:
                update_data['Architecture'] = sanitize_string(agent_data['architecture'])
            
            # Update database
            success = self.db.update_data(
                'Agents',
                update_data,
                'Hostname = ?',
                [hostname]
            )
            
            if success:
                self.logger.info(f"Agent updated: {hostname}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error updating existing agent {hostname}: {e}")
            return False
    
    def _normalize_agent_data(self, hostname: str, agent_data: Dict) -> Dict:
        """Normalize dữ liệu agent"""
        normalized = {
            'Hostname': hostname,
            'Status': 'Online',
            'OSType': sanitize_string(agent_data.get('os_type', 'Unknown')),
            'OSVersion': sanitize_string(agent_data.get('os_version', 'Unknown')),
            'Architecture': sanitize_string(agent_data.get('architecture', 'Unknown')),
            'AgentVersion': sanitize_string(agent_data.get('agent_version', '1.0.0')),
            'LastHeartbeat': datetime.now(),
            'LastSeen': datetime.now(),
            'IsActive': 1,
            'FirstSeen': datetime.now()
        }
        
        # IP Address
        ip = agent_data.get('ip_address', '')
        if validate_ip_address(ip):
            normalized['IPAddress'] = ip
        
        # MAC Address
        mac = agent_data.get('mac_address', '')
        if validate_mac_address(mac):
            normalized['MACAddress'] = normalize_mac_address(mac)
        
        return normalized
    
    def _assign_global_rules(self, hostname: str, os_type: str):
        """Assign global rules cho agent mới"""
        try:
            # Lấy global rules
            query = """
                SELECT RuleID FROM Rules 
                WHERE IsGlobal = 1 AND IsActive = 1 
                AND (OSType = ? OR OSType = 'All')
            """
            
            cursor = self.db.execute_query(query, [os_type])
            if not cursor:
                return
            
            # Assign từng rule
            for row in cursor.fetchall():
                rule_id = row.RuleID
                self.assign_rule(hostname, rule_id)
            
            cursor.close()
            self.logger.info(f"Global rules assigned to {hostname}")
            
        except Exception as e:
            self.logger.error(f"Error assigning global rules to {hostname}: {e}")
    
    def get_agent(self, hostname: str) -> Optional[Dict]:
        """Lấy thông tin agent theo hostname"""
        try:
            query = "SELECT * FROM Agents WHERE Hostname = ?"
            return self.db.fetch_one(query, [hostname])
            
        except Exception as e:
            self.logger.error(f"Error getting agent {hostname}: {e}")
            return None
    
    def get_all_agents(self) -> List[Dict]:
        """Lấy tất cả agents"""
        try:
            query = """
                SELECT * FROM Agents 
                ORDER BY LastSeen DESC, Hostname ASC
            """
            return self.db.fetch_all(query)
            
        except Exception as e:
            self.logger.error(f"Error getting all agents: {e}")
            return []
    
    def get_online_agents(self) -> List[Dict]:
        """Lấy agents đang online"""
        try:
            # Agents online trong 5 phút qua
            threshold = datetime.now() - timedelta(minutes=5)
            
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
        """Lấy agents theo OS type"""
        try:
            query = """
                SELECT * FROM Agents 
                WHERE OSType = ? AND IsActive = 1
                ORDER BY LastSeen DESC
            """
            return self.db.fetch_all(query, [os_type])
            
        except Exception as e:
            self.logger.error(f"Error getting agents by OS {os_type}: {e}")
            return []
    
    def update_agent_status(self, hostname: str, status: str) -> bool:
        """Cập nhật trạng thái agent"""
        try:
            update_data = {
                'Status': status,
                'LastSeen': datetime.now()
            }
            
            return self.db.update_data(
                'Agents',
                update_data,
                'Hostname = ?',
                [hostname]
            )
            
        except Exception as e:
            self.logger.error(f"Error updating agent status {hostname}: {e}")
            return False
    
    def update_heartbeat(self, hostname: str) -> bool:
        """Cập nhật heartbeat của agent"""
        try:
            update_data = {
                'LastHeartbeat': datetime.now(),
                'LastSeen': datetime.now(),
                'Status': 'Online'
            }
            
            return self.db.update_data(
                'Agents',
                update_data,
                'Hostname = ?',
                [hostname]
            )
            
        except Exception as e:
            self.logger.error(f"Error updating heartbeat {hostname}: {e}")
            return False
    
    def cleanup_offline_agents(self, minutes_threshold: int = 5) -> int:
        """Đánh dấu agents offline nếu không heartbeat trong threshold"""
        try:
            threshold = datetime.now() - timedelta(minutes=minutes_threshold)
            
            query = """
                UPDATE Agents 
                SET Status = 'Offline'
                WHERE LastHeartbeat < ? 
                AND Status = 'Online'
            """
            
            cursor = self.db.execute_query(query, [threshold])
            if cursor:
                affected_rows = cursor.rowcount
                cursor.close()
                
                if affected_rows > 0:
                    self.logger.info(f"Marked {affected_rows} agents as offline")
                
                return affected_rows
            
            return 0
            
        except Exception as e:
            self.logger.error(f"Error cleaning up offline agents: {e}")
            return 0
    
    def assign_rule(self, hostname: str, rule_id: int) -> bool:
        """Assign rule cho agent"""
        try:
            # Kiểm tra đã assign chưa
            existing = self.db.fetch_one(
                "SELECT * FROM AgentRules WHERE Hostname = ? AND RuleID = ?",
                [hostname, rule_id]
            )
            
            if existing:
                # Update IsActive nếu đã tồn tại
                return self.db.update_data(
                    'AgentRules',
                    {'IsActive': 1, 'AppliedAt': datetime.now()},
                    'Hostname = ? AND RuleID = ?',
                    [hostname, rule_id]
                )
            else:
                # Insert mới
                rule_assignment = {
                    'RuleID': rule_id,
                    'Hostname': hostname,
                    'IsActive': 1,
                    'AppliedAt': datetime.now()
                }
                
                return self.db.insert_data('AgentRules', rule_assignment)
                
        except Exception as e:
            self.logger.error(f"Error assigning rule {rule_id} to {hostname}: {e}")
            return False
    
    def unassign_rule(self, hostname: str, rule_id: int) -> bool:
        """Unassign rule từ agent"""
        try:
            return self.db.update_data(
                'AgentRules',
                {'IsActive': 0},
                'Hostname = ? AND RuleID = ?',
                [hostname, rule_id]
            )
            
        except Exception as e:
            self.logger.error(f"Error unassigning rule {rule_id} from {hostname}: {e}")
            return False
    
    def get_agent_rules(self, hostname: str) -> List[int]:
        """Lấy danh sách rule IDs được assign cho agent"""
        try:
            query = """
                SELECT RuleID FROM AgentRules 
                WHERE Hostname = ? AND IsActive = 1
            """
            
            cursor = self.db.execute_query(query, [hostname])
            if cursor:
                rule_ids = [row.RuleID for row in cursor.fetchall()]
                cursor.close()
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
    
    def delete_agent(self, hostname: str) -> bool:
        """Xóa agent (set IsActive = 0)"""
        try:
            # Không xóa hẳn, chỉ deactivate
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
                # Deactivate tất cả rule assignments
                self.db.update_data(
                    'AgentRules',
                    {'IsActive': 0},
                    'Hostname = ?',
                    [hostname]
                )
                
                self.logger.info(f"Agent {hostname} deleted")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error deleting agent {hostname}: {e}")
            return False
    
    def get_agents_statistics(self) -> Dict:
        """Lấy thống kê agents"""
        try:
            stats = {
                'total_agents': 0,
                'online_agents': 0,
                'offline_agents': 0,
                'by_os_type': {},
                'by_status': {},
                'recent_registrations': 0
            }
            
            # Total agents
            total_result = self.db.fetch_one(
                "SELECT COUNT(*) as total FROM Agents WHERE IsActive = 1"
            )
            if total_result:
                stats['total_agents'] = total_result['total']
            
            # Online agents (last 5 minutes)
            threshold = datetime.now() - timedelta(minutes=5)
            online_result = self.db.fetch_one(
                "SELECT COUNT(*) as online FROM Agents WHERE LastSeen >= ? AND IsActive = 1",
                [threshold]
            )
            if online_result:
                stats['online_agents'] = online_result['online']
            
            stats['offline_agents'] = stats['total_agents'] - stats['online_agents']
            
            # By OS Type
            os_stats = self.db.fetch_all(
                "SELECT OSType, COUNT(*) as count FROM Agents WHERE IsActive = 1 GROUP BY OSType"
            )
            for row in os_stats:
                stats['by_os_type'][row['OSType']] = row['count']
            
            # By Status
            status_stats = self.db.fetch_all(
                "SELECT Status, COUNT(*) as count FROM Agents WHERE IsActive = 1 GROUP BY Status"
            )
            for row in status_stats:
                stats['by_status'][row['Status']] = row['count']
            
            # Recent registrations (last 24 hours)
            recent_threshold = datetime.now() - timedelta(hours=24)
            recent_result = self.db.fetch_one(
                "SELECT COUNT(*) as recent FROM Agents WHERE FirstSeen >= ? AND IsActive = 1",
                [recent_threshold]
            )
            if recent_result:
                stats['recent_registrations'] = recent_result['recent']
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error getting agents statistics: {e}")
            return {}
    
    def search_agents(self, search_term: str) -> List[Dict]:
        """Tìm kiếm agents"""
        try:
            search_pattern = f"%{search_term}%"
            
            query = """
                SELECT * FROM Agents 
                WHERE IsActive = 1 
                AND (
                    Hostname LIKE ? OR 
                    IPAddress LIKE ? OR 
                    OSType LIKE ? OR 
                    OSVersion LIKE ?
                )
                ORDER BY LastSeen DESC
            """
            
            return self.db.fetch_all(query, [search_pattern] * 4)
            
        except Exception as e:
            self.logger.error(f"Error searching agents: {e}")
            return []
    
    def get_agent_activity_summary(self, hostname: str, hours: int = 24) -> Dict:
        """Lấy tóm tắt hoạt động của agent"""
        try:
            # Basic agent info
            agent = self.get_agent(hostname)
            if not agent:
                return {}
            
            start_time = datetime.now() - timedelta(hours=hours)
            
            summary = {
                'hostname': hostname,
                'status': agent.get('Status'),
                'last_seen': agent.get('LastSeen'),
                'os_type': agent.get('OSType'),
                'agent_version': agent.get('AgentVersion'),
                'period_hours': hours,
                'log_counts': {
                    'process_logs': 0,
                    'file_logs': 0,
                    'network_logs': 0,
                    'total_logs': 0
                },
                'alert_counts': {
                    'total_alerts': 0,
                    'critical_alerts': 0,
                    'high_alerts': 0,
                    'resolved_alerts': 0
                },
                'rule_counts': {
                    'total_rules': len(self.get_agent_rules(hostname)),
                    'active_rules': len(self.get_agent_rules(hostname))
                }
            }
            
            # Count logs (cần import LogDB)
            try:
                from .logs import LogDB
                log_db = LogDB()
                
                process_logs = log_db.get_process_logs(
                    hostname, 
                    start_time.strftime('%Y-%m-%d %H:%M:%S'),
                    limit=10000
                )
                file_logs = log_db.get_file_logs(
                    hostname,
                    start_time.strftime('%Y-%m-%d %H:%M:%S'), 
                    limit=10000
                )
                network_logs = log_db.get_network_logs(
                    hostname,
                    start_time.strftime('%Y-%m-%d %H:%M:%S'),
                    limit=10000
                )
                
                summary['log_counts'] = {
                    'process_logs': len(process_logs),
                    'file_logs': len(file_logs),
                    'network_logs': len(network_logs),
                    'total_logs': len(process_logs) + len(file_logs) + len(network_logs)
                }
                
            except ImportError:
                pass
            
            # Count alerts (cần import AlertDB)
            try:
                from .alerts import AlertDB
                alert_db = AlertDB()
                
                alerts = alert_db.get_alerts({
                    'hostname': hostname,
                    'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S')
                }, 1000)
                
                critical_count = len([a for a in alerts if a.get('Severity') == 'Critical'])
                high_count = len([a for a in alerts if a.get('Severity') == 'High'])
                resolved_count = len([a for a in alerts if a.get('Status') == 'Resolved'])
                
                summary['alert_counts'] = {
                    'total_alerts': len(alerts),
                    'critical_alerts': critical_count,
                    'high_alerts': high_count,
                    'resolved_alerts': resolved_count
                }
                
            except ImportError:
                pass
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Error getting activity summary for {hostname}: {e}")
            return {}
    
    def bulk_update_agents(self, updates: List[Dict]) -> Dict:
        """Bulk update nhiều agents"""
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
                            errors.append("Missing hostname")
                            continue
                        
                        update_data = {k: v for k, v in update.items() if k != 'hostname'}
                        
                        if self.db.update_data('Agents', update_data, 'Hostname = ?', [hostname]):
                            success_count += 1
                        else:
                            failed_count += 1
                            errors.append(f"Failed to update {hostname}")
                            
                    except Exception as e:
                        failed_count += 1
                        errors.append(f"Error updating {update.get('hostname', 'unknown')}: {str(e)}")
            
            return {
                'success_count': success_count,
                'failed_count': failed_count,
                'errors': errors
            }
            
        except Exception as e:
            self.logger.error(f"Error in bulk update agents: {e}")
            return {'success_count': 0, 'failed_count': len(updates), 'errors': [str(e)]}
    
    def _update_agent(self, hostname: str, updates: Dict) -> bool:
        """Internal method để update agent"""
        try:
            return self.db.update_data(
                'Agents',
                updates,
                'Hostname = ?',
                [hostname]
            )
        except Exception as e:
            self.logger.error(f"Error updating agent {hostname}: {e}")
            return False