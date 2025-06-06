"""
Rule Database Operations
Xử lý tất cả operations liên quan đến rules trong database
"""

import logging
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from .connection import DatabaseConnection
from utils.helpers import sanitize_string

class RuleDB:
    def __init__(self):
        self.db = DatabaseConnection()
        self.db.connect()
        self.logger = logging.getLogger(__name__)
    
    def get_all_rules(self) -> List[Dict]:
        """Lấy tất cả rules"""
        try:
            query = """
                SELECT * FROM Rules 
                WHERE IsActive = 1
                ORDER BY Severity DESC, RuleName ASC
            """
            return self.db.fetch_all(query)
            
        except Exception as e:
            self.logger.error(f"Error getting all rules: {e}")
            return []
    
    def get_rule_by_id(self, rule_id: int) -> Optional[Dict]:
        """Lấy rule theo ID với conditions"""
        try:
            # Lấy rule chính
            rule = self.db.fetch_one("SELECT * FROM Rules WHERE RuleID = ?", [rule_id])
            if not rule:
                return None
            
            # Lấy conditions
            rule['ProcessConditions'] = self.get_process_conditions(rule_id)
            rule['FileConditions'] = self.get_file_conditions(rule_id)
            rule['NetworkConditions'] = self.get_network_conditions(rule_id)
            
            return rule
            
        except Exception as e:
            self.logger.error(f"Error getting rule {rule_id}: {e}")
            return None
    
    def get_process_conditions(self, rule_id: int) -> List[Dict]:
        """Lấy process conditions của rule"""
        try:
            query = "SELECT * FROM ProcessRuleConditions WHERE RuleID = ?"
            return self.db.fetch_all(query, [rule_id])
            
        except Exception as e:
            self.logger.error(f"Error getting process conditions for rule {rule_id}: {e}")
            return []
    
    def get_file_conditions(self, rule_id: int) -> List[Dict]:
        """Lấy file conditions của rule"""
        try:
            query = "SELECT * FROM FileRuleConditions WHERE RuleID = ?"
            return self.db.fetch_all(query, [rule_id])
            
        except Exception as e:
            self.logger.error(f"Error getting file conditions for rule {rule_id}: {e}")
            return []
    
    def get_network_conditions(self, rule_id: int) -> List[Dict]:
        """Lấy network conditions của rule"""
        try:
            query = "SELECT * FROM NetworkRuleConditions WHERE RuleID = ?"
            return self.db.fetch_all(query, [rule_id])
            
        except Exception as e:
            self.logger.error(f"Error getting network conditions for rule {rule_id}: {e}")
            return []
    
    def get_rules_by_type(self, rule_type: str) -> List[Dict]:
        """Lấy rules theo type"""
        try:
            query = """
                SELECT * FROM Rules 
                WHERE RuleType = ? AND IsActive = 1
                ORDER BY Severity DESC, RuleName ASC
            """
            return self.db.fetch_all(query, [rule_type])
            
        except Exception as e:
            self.logger.error(f"Error getting rules by type {rule_type}: {e}")
            return []
    
    def get_rules_by_severity(self, severity: str) -> List[Dict]:
        """Lấy rules theo severity"""
        try:
            query = """
                SELECT * FROM Rules 
                WHERE Severity = ? AND IsActive = 1
                ORDER BY RuleName ASC
            """
            return self.db.fetch_all(query, [severity])
            
        except Exception as e:
            self.logger.error(f"Error getting rules by severity {severity}: {e}")
            return []
    
    def get_global_rules(self, os_type: str = None) -> List[Dict]:
        """Lấy global rules (áp dụng cho tất cả agents)"""
        try:
            query = """
                SELECT * FROM Rules 
                WHERE IsGlobal = 1 AND IsActive = 1
            """
            params = []
            
            if os_type:
                query += " AND (OSType = ? OR OSType = 'All')"
                params.append(os_type)
            
            query += " ORDER BY Severity DESC, RuleName ASC"
            
            return self.db.fetch_all(query, params)
            
        except Exception as e:
            self.logger.error(f"Error getting global rules: {e}")
            return []
    
    def get_agent_applicable_rules(self, hostname: str, os_type: str) -> List[Dict]:
        """Lấy rules có thể áp dụng cho agent"""
        try:
            query = """
                SELECT * FROM Rules 
                WHERE IsActive = 1 
                AND (OSType = ? OR OSType = 'All')
                ORDER BY Severity DESC, RuleName ASC
            """
            return self.db.fetch_all(query, [os_type])
            
        except Exception as e:
            self.logger.error(f"Error getting applicable rules for {hostname}: {e}")
            return []
    
    def create_rule(self, rule_data: Dict) -> bool:
        """Tạo rule mới"""
        try:
            # Validate dữ liệu
            required_fields = ['rule_name', 'rule_type', 'severity', 'description']
            for field in required_fields:
                if field not in rule_data:
                    self.logger.error(f"Missing required field: {field}")
                    return False
            
            # Chuẩn bị dữ liệu rule
            normalized_data = {
                'RuleName': sanitize_string(rule_data['rule_name']),
                'RuleType': sanitize_string(rule_data['rule_type']),
                'Description': sanitize_string(rule_data['description']),
                'Severity': sanitize_string(rule_data['severity']),
                'Action': sanitize_string(rule_data.get('action', 'Alert')),
                'IsGlobal': rule_data.get('is_global', 0),
                'OSType': sanitize_string(rule_data.get('os_type', 'All')),
                'IsActive': 1,
                'CreatedAt': datetime.now(),
                'UpdatedAt': datetime.now()
            }
            
            # Insert rule
            success = self.db.insert_data('Rules', normalized_data)
            
            if success:
                self.logger.info(f"Rule created: {rule_data['rule_name']}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error creating rule: {e}")
            return False
    
    def create_cross_platform_rule(self, rule_data: Dict) -> bool:
        """Tạo rule cho nhiều platform"""
        try:
            # Tạo rule chính
            if not self.create_rule(rule_data):
                return False
            
            # Lấy rule ID vừa tạo
            rule_id = self._get_last_rule_id()
            if not rule_id:
                return False
            
            # Thêm conditions cho Windows
            if 'WindowsConditions' in rule_data:
                self._add_conditions(rule_id, rule_data['WindowsConditions'], rule_data['rule_type'])
            
            # Thêm conditions cho Linux
            if 'LinuxConditions' in rule_data:
                self._add_conditions(rule_id, rule_data['LinuxConditions'], rule_data['rule_type'])
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error creating cross-platform rule: {e}")
            return False
    
    def _get_last_rule_id(self) -> Optional[int]:
        """Lấy rule ID vừa tạo"""
        try:
            result = self.db.fetch_one("SELECT MAX(RuleID) as LastID FROM Rules")
            return result['LastID'] if result else None
            
        except Exception as e:
            self.logger.error(f"Error getting last rule ID: {e}")
            return None
    
    def _add_conditions(self, rule_id: int, conditions: List[Dict], rule_type: str):
        """Thêm conditions cho rule"""
        try:
            table_map = {
                'Process': 'ProcessRuleConditions',
                'File': 'FileRuleConditions', 
                'Network': 'NetworkRuleConditions'
            }
            
            table_name = table_map.get(rule_type)
            if not table_name:
                return
            
            for condition in conditions:
                condition_data = {'RuleID': rule_id, **condition}
                self.db.insert_data(table_name, condition_data)
                
        except Exception as e:
            self.logger.error(f"Error adding conditions: {e}")
    
    def update_rule(self, rule_id: int, rule_data: Dict) -> bool:
        """Cập nhật rule"""
        try:
            update_data = {
                'UpdatedAt': datetime.now()
            }
            
            # Cập nhật các field cho phép
            allowed_fields = ['RuleName', 'Description', 'Severity', 'Action', 'IsGlobal', 'OSType', 'IsActive']
            for field in allowed_fields:
                if field.lower() in rule_data:
                    update_data[field] = sanitize_string(str(rule_data[field.lower()]))
            
            success = self.db.update_data(
                'Rules',
                update_data,
                'RuleID = ?',
                [rule_id]
            )
            
            if success:
                self.logger.info(f"Rule {rule_id} updated")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error updating rule {rule_id}: {e}")
            return False
    
    def delete_rule(self, rule_id: int) -> bool:
        """Xóa rule (set IsActive = 0)"""
        try:
            update_data = {
                'IsActive': 0,
                'UpdatedAt': datetime.now()
            }
            
            success = self.db.update_data(
                'Rules',
                update_data,
                'RuleID = ?',
                [rule_id]
            )
            
            if success:
                # Deactivate tất cả assignments
                self.db.update_data(
                    'AgentRules',
                    {'IsActive': 0},
                    'RuleID = ?',
                    [rule_id]
                )
                
                self.logger.info(f"Rule {rule_id} deleted")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error deleting rule {rule_id}: {e}")
            return False
    
    def check_rule_violation(self, rule_id: int, log_data: Dict) -> Optional[Dict]:
        """Kiểm tra log có vi phạm rule không"""
        try:
            rule = self.get_rule_by_id(rule_id)
            if not rule or not rule['IsActive']:
                return None
            
            rule_type = rule['RuleType']
            
            # Kiểm tra theo type
            if rule_type == 'Process':
                return self._check_process_violation(rule, log_data)
            elif rule_type == 'File':
                return self._check_file_violation(rule, log_data)
            elif rule_type == 'Network':
                return self._check_network_violation(rule, log_data)
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error checking rule violation {rule_id}: {e}")
            return None
    
    def _check_process_violation(self, rule: Dict, log_data: Dict) -> Optional[Dict]:
        """Kiểm tra process rule violation"""
        try:
            conditions = rule['ProcessConditions']
            if not conditions:
                return None
            
            process_name = log_data.get('ProcessName', '').lower()
            process_path = log_data.get('ExecutablePath', '').lower()
            command_line = log_data.get('CommandLine', '').lower()
            
            for condition in conditions:
                condition_process = condition.get('ProcessName', '').lower()
                condition_path = condition.get('ProcessPath', '').lower()
                
                # Check process name match
                if condition_process and condition_process in process_name:
                    return {
                        'rule_id': rule['RuleID'],
                        'rule_name': rule['RuleName'],
                        'violation_type': 'ProcessName',
                        'description': f"Suspicious process detected: {log_data.get('ProcessName')}",
                        'severity': rule['Severity'],
                        'action': rule['Action'],
                        'detection_data': log_data
                    }
                
                # Check process path match
                if condition_path and condition_path in process_path:
                    return {
                        'rule_id': rule['RuleID'],
                        'rule_name': rule['RuleName'],
                        'violation_type': 'ProcessPath',
                        'description': f"Suspicious process path detected: {log_data.get('ExecutablePath')}",
                        'severity': rule['Severity'],
                        'action': rule['Action'],
                        'detection_data': log_data
                    }
                
                # Check for suspicious command patterns
                suspicious_commands = [
                    'vssadmin delete shadows',
                    'wevtutil cl',
                    'bcdedit /set',
                    'schtasks /create',
                    'reg delete'
                ]
                
                for suspicious_cmd in suspicious_commands:
                    if suspicious_cmd.lower() in command_line:
                        return {
                            'rule_id': rule['RuleID'],
                            'rule_name': rule['RuleName'],
                            'violation_type': 'SuspiciousCommand',
                            'description': f"Suspicious command detected: {suspicious_cmd}",
                            'severity': rule['Severity'],
                            'action': rule['Action'],
                            'detection_data': log_data
                        }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error checking process violation: {e}")
            return None
    
    def _check_file_violation(self, rule: Dict, log_data: Dict) -> Optional[Dict]:
        """Kiểm tra file rule violation"""
        try:
            conditions = rule['FileConditions']
            if not conditions:
                return None
            
            file_name = log_data.get('FileName', '').lower()
            file_path = log_data.get('FilePath', '').lower()
            event_type = log_data.get('EventType', '').lower()
            
            for condition in conditions:
                condition_name = condition.get('FileName', '').lower()
                condition_path = condition.get('FilePath', '').lower()
                
                # Check file name pattern
                if condition_name:
                    if '*' in condition_name:
                        # Wildcard pattern
                        pattern = condition_name.replace('*', '')
                        if pattern in file_name:
                            return {
                                'rule_id': rule['RuleID'],
                                'rule_name': rule['RuleName'],
                                'violation_type': 'FileName',
                                'description': f"Suspicious file activity: {log_data.get('FileName')}",
                                'severity': rule['Severity'],
                                'action': rule['Action'],
                                'detection_data': log_data
                            }
                    elif condition_name in file_name:
                        return {
                            'rule_id': rule['RuleID'],
                            'rule_name': rule['RuleName'],
                            'violation_type': 'FileName',
                            'description': f"Suspicious file activity: {log_data.get('FileName')}",
                            'severity': rule['Severity'],
                            'action': rule['Action'],
                            'detection_data': log_data
                        }
                
                # Check file path pattern
                if condition_path and condition_path in file_path:
                    return {
                        'rule_id': rule['RuleID'],
                        'rule_name': rule['RuleName'],
                        'violation_type': 'FilePath',
                        'description': f"Suspicious file path activity: {log_data.get('FilePath')}",
                        'severity': rule['Severity'],
                        'action': rule['Action'],
                        'detection_data': log_data
                    }
            
            # Check for suspicious file extensions
            suspicious_extensions = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.com']
            for ext in suspicious_extensions:
                if file_name.endswith(ext) and 'temp' in file_path:
                    return {
                        'rule_id': rule['RuleID'],
                        'rule_name': rule['RuleName'],
                        'violation_type': 'SuspiciousFileLocation',
                        'description': f"Executable file in temporary location: {log_data.get('FileName')}",
                        'severity': rule['Severity'],
                        'action': rule['Action'],
                        'detection_data': log_data
                    }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error checking file violation: {e}")
            return None
    
    def _check_network_violation(self, rule: Dict, log_data: Dict) -> Optional[Dict]:
        """Kiểm tra network rule violation"""
        try:
            conditions = rule['NetworkConditions']
            if not conditions:
                return None
            
            remote_address = log_data.get('RemoteAddress', '')
            remote_port = log_data.get('RemotePort', 0)
            protocol = log_data.get('Protocol', '').lower()
            direction = log_data.get('Direction', '').lower()
            
            for condition in conditions:
                condition_ip = condition.get('IPAddress', '')
                condition_port = condition.get('Port', 0)
                condition_protocol = condition.get('Protocol', '').lower()
                
                # Check IP address pattern
                if condition_ip:
                    if '*' in condition_ip:
                        # Wildcard pattern
                        pattern = condition_ip.replace('*', '')
                        if pattern in remote_address:
                            return {
                                'rule_id': rule['RuleID'],
                                'rule_name': rule['RuleName'],
                                'violation_type': 'SuspiciousIP',
                                'description': f"Connection to suspicious IP: {remote_address}",
                                'severity': rule['Severity'],
                                'action': rule['Action'],
                                'detection_data': log_data
                            }
                    elif condition_ip in remote_address:
                        return {
                            'rule_id': rule['RuleID'],
                            'rule_name': rule['RuleName'],
                            'violation_type': 'SuspiciousIP',
                            'description': f"Connection to flagged IP: {remote_address}",
                            'severity': rule['Severity'],
                            'action': rule['Action'],
                            'detection_data': log_data
                        }
                
                # Check port
                if condition_port and condition_port == remote_port:
                    return {
                        'rule_id': rule['RuleID'],
                        'rule_name': rule['RuleName'],
                        'violation_type': 'SuspiciousPort',
                        'description': f"Connection to suspicious port: {remote_port}",
                        'severity': rule['Severity'],
                        'action': rule['Action'],
                        'detection_data': log_data
                    }
                
                # Check protocol
                if condition_protocol and condition_protocol == protocol:
                    # Additional checks for suspicious protocol usage
                    pass
            
            # Check for suspicious ports
            suspicious_ports = [4444, 5555, 1337, 31337, 8080, 3389]
            if remote_port in suspicious_ports:
                return {
                    'rule_id': rule['RuleID'],
                    'rule_name': rule['RuleName'],
                    'violation_type': 'SuspiciousPort',
                    'description': f"Connection to commonly used malicious port: {remote_port}",
                    'severity': rule['Severity'],
                    'action': rule['Action'],
                    'detection_data': log_data
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error checking network violation: {e}")
            return None
    
    def get_rules_statistics(self) -> Dict:
        """Lấy thống kê rules"""
        try:
            stats = {
                'total_rules': 0,
                'active_rules': 0,
                'by_type': {},
                'by_severity': {},
                'by_os': {},
                'global_rules': 0
            }
            
            # Total rules
            total_result = self.db.fetch_one("SELECT COUNT(*) as total FROM Rules")
            if total_result:
                stats['total_rules'] = total_result['total']
            
            # Active rules
            active_result = self.db.fetch_one("SELECT COUNT(*) as active FROM Rules WHERE IsActive = 1")
            if active_result:
                stats['active_rules'] = active_result['active']
            
            # By type
            type_stats = self.db.fetch_all(
                "SELECT RuleType, COUNT(*) as count FROM Rules WHERE IsActive = 1 GROUP BY RuleType"
            )
            for row in type_stats:
                stats['by_type'][row['RuleType']] = row['count']
            
            # By severity
            severity_stats = self.db.fetch_all(
                "SELECT Severity, COUNT(*) as count FROM Rules WHERE IsActive = 1 GROUP BY Severity"
            )
            for row in severity_stats:
                stats['by_severity'][row['Severity']] = row['count']
            
            # By OS
            os_stats = self.db.fetch_all(
                "SELECT OSType, COUNT(*) as count FROM Rules WHERE IsActive = 1 GROUP BY OSType"
            )
            for row in os_stats:
                stats['by_os'][row['OSType']] = row['count']
            
            # Global rules
            global_result = self.db.fetch_one(
                "SELECT COUNT(*) as global_count FROM Rules WHERE IsActive = 1 AND IsGlobal = 1"
            )
            if global_result:
                stats['global_rules'] = global_result['global_count']
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error getting rules statistics: {e}")
            return {}
    
    def search_rules(self, search_term: str) -> List[Dict]:
        """Tìm kiếm rules"""
        try:
            search_pattern = f"%{search_term}%"
            
            query = """
                SELECT * FROM Rules 
                WHERE IsActive = 1 
                AND (
                    RuleName LIKE ? OR 
                    Description LIKE ? OR 
                    RuleType LIKE ? OR
                    Severity LIKE ?
                )
                ORDER BY Severity DESC, RuleName ASC
            """
            
            return self.db.fetch_all(query, [search_pattern] * 4)
            
        except Exception as e:
            self.logger.error(f"Error searching rules: {e}")
            return []
    
    def get_rule_usage_statistics(self, rule_id: int) -> Dict:
        """Lấy thống kê sử dụng của rule"""
        try:
            stats = {
                'rule_id': rule_id,
                'assigned_agents': 0,
                'total_violations': 0,
                'recent_violations': 0,
                'last_violation': None
            }
            
            # Assigned agents
            assigned_result = self.db.fetch_one(
                "SELECT COUNT(*) as assigned FROM AgentRules WHERE RuleID = ? AND IsActive = 1",
                [rule_id]
            )
            if assigned_result:
                stats['assigned_agents'] = assigned_result['assigned']
            
            # Total violations (alerts)
            total_violations = self.db.fetch_one(
                "SELECT COUNT(*) as total FROM Alerts WHERE RuleID = ?",
                [rule_id]
            )
            if total_violations:
                stats['total_violations'] = total_violations['total']
            
            # Recent violations (last 7 days)
            recent_threshold = datetime.now() - timedelta(days=7)
            recent_violations = self.db.fetch_one(
                "SELECT COUNT(*) as recent FROM Alerts WHERE RuleID = ? AND Time >= ?",
                [rule_id, recent_threshold]
            )
            if recent_violations:
                stats['recent_violations'] = recent_violations['recent']
            
            # Last violation
            last_violation = self.db.fetch_one(
                "SELECT TOP 1 Time FROM Alerts WHERE RuleID = ? ORDER BY Time DESC",
                [rule_id]
            )
            if last_violation:
                stats['last_violation'] = last_violation['Time']
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error getting rule usage statistics for {rule_id}: {e}")
            return {}
    
    def bulk_update_rules(self, updates: List[Dict]) -> Dict:
        """Bulk update nhiều rules"""
        try:
            success_count = 0
            failed_count = 0
            errors = []
            
            with self.db.transaction():
                for update in updates:
                    try:
                        rule_id = update.get('rule_id')
                        if not rule_id:
                            failed_count += 1
                            errors.append("Missing rule_id")
                            continue
                        
                        update_data = {k: v for k, v in update.items() if k != 'rule_id'}
                        
                        if self.update_rule(rule_id, update_data):
                            success_count += 1
                        else:
                            failed_count += 1
                            errors.append(f"Failed to update rule {rule_id}")
                            
                    except Exception as e:
                        failed_count += 1
                        errors.append(f"Error updating rule {update.get('rule_id', 'unknown')}: {str(e)}")
            
            return {
                'success_count': success_count,
                'failed_count': failed_count,
                'errors': errors
            }
            
        except Exception as e:
            self.logger.error(f"Error in bulk update rules: {e}")
            return {'success_count': 0, 'failed_count': len(updates), 'errors': [str(e)]}
    
    def clone_rule(self, rule_id: int, new_name: str) -> bool:
        """Clone rule hiện có"""
        try:
            # Lấy rule gốc
            original_rule = self.get_rule_by_id(rule_id)
            if not original_rule:
                return False
            
            # Tạo rule mới
            new_rule_data = {
                'rule_name': new_name,
                'rule_type': original_rule['RuleType'],
                'description': f"Cloned from: {original_rule['Description']}",
                'severity': original_rule['Severity'],
                'action': original_rule['Action'],
                'is_global': original_rule['IsGlobal'],
                'os_type': original_rule['OSType']
            }
            
            if not self.create_rule(new_rule_data):
                return False
            
            # Lấy ID của rule mới
            new_rule_id = self._get_last_rule_id()
            if not new_rule_id:
                return False
            
            # Clone conditions
            self._clone_conditions(rule_id, new_rule_id, original_rule['RuleType'])
            
            self.logger.info(f"Rule {rule_id} cloned to {new_rule_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error cloning rule {rule_id}: {e}")
            return False
    
    def _clone_conditions(self, source_rule_id: int, target_rule_id: int, rule_type: str):
        """Clone conditions từ rule này sang rule khác"""
        try:
            if rule_type == 'Process':
                conditions = self.get_process_conditions(source_rule_id)
                for condition in conditions:
                    condition_data = {
                        'RuleID': target_rule_id,
                        'ProcessName': condition.get('ProcessName'),
                        'ProcessPath': condition.get('ProcessPath')
                    }
                    self.db.insert_data('ProcessRuleConditions', condition_data)
            
            elif rule_type == 'File':
                conditions = self.get_file_conditions(source_rule_id)
                for condition in conditions:
                    condition_data = {
                        'RuleID': target_rule_id,
                        'FileName': condition.get('FileName'),
                        'FilePath': condition.get('FilePath')
                    }
                    self.db.insert_data('FileRuleConditions', condition_data)
            
            elif rule_type == 'Network':
                conditions = self.get_network_conditions(source_rule_id)
                for condition in conditions:
                    condition_data = {
                        'RuleID': target_rule_id,
                        'IPAddress': condition.get('IPAddress'),
                        'Port': condition.get('Port'),
                        'Protocol': condition.get('Protocol')
                    }
                    self.db.insert_data('NetworkRuleConditions', condition_data)
                    
        except Exception as e:
            self.logger.error(f"Error cloning conditions: {e}")
    
    def import_rules(self, rules_data: List[Dict]) -> Dict:
        """Import nhiều rules từ data"""
        try:
            success_count = 0
            failed_count = 0
            errors = []
            
            with self.db.transaction():
                for rule_data in rules_data:
                    try:
                        if self.create_rule(rule_data):
                            success_count += 1
                        else:
                            failed_count += 1
                            errors.append(f"Failed to create rule: {rule_data.get('rule_name', 'unknown')}")
                    except Exception as e:
                        failed_count += 1
                        errors.append(f"Error creating rule: {str(e)}")
            
            return {
                'success_count': success_count,
                'failed_count': failed_count,
                'total': len(rules_data),
                'errors': errors
            }
            
        except Exception as e:
            self.logger.error(f"Error importing rules: {e}")
            return {
                'success_count': 0,
                'failed_count': len(rules_data),
                'total': len(rules_data),
                'errors': [str(e)]
            }
    
    def export_rules(self, rule_ids: List[int] = None) -> List[Dict]:
        """Export rules data"""
        try:
            if rule_ids:
                # Export specific rules
                rules = []
                for rule_id in rule_ids:
                    rule = self.get_rule_by_id(rule_id)
                    if rule:
                        rules.append(rule)
            else:
                # Export all rules
                rules = self.get_all_rules()
            
            # Clean up for export
            export_data = []
            for rule in rules:
                export_rule = {
                    'rule_name': rule['RuleName'],
                    'rule_type': rule['RuleType'],
                    'description': rule['Description'],
                    'severity': rule['Severity'],
                    'action': rule['Action'],
                    'is_global': rule['IsGlobal'],
                    'os_type': rule['OSType'],
                    'conditions': {
                        'process': rule.get('ProcessConditions', []),
                        'file': rule.get('FileConditions', []),
                        'network': rule.get('NetworkConditions', [])
                    }
                }
                export_data.append(export_rule)
            
            return export_data
            
        except Exception as e:
            self.logger.error(f"Error exporting rules: {e}")
            return []
    
    def validate_rule_data(self, rule_data: Dict) -> Dict:
        """Validate rule data"""
        errors = []
        warnings = []
        
        # Required fields
        required_fields = ['rule_name', 'rule_type', 'severity', 'description']
        for field in required_fields:
            if field not in rule_data or not rule_data[field]:
                errors.append(f"Missing required field: {field}")
        
        # Valid rule types
        valid_types = ['Process', 'File', 'Network']
        if rule_data.get('rule_type') not in valid_types:
            errors.append(f"Invalid rule type. Must be one of: {valid_types}")
        
        # Valid severities
        valid_severities = ['Critical', 'High', 'Medium', 'Low']
        if rule_data.get('severity') not in valid_severities:
            errors.append(f"Invalid severity. Must be one of: {valid_severities}")
        
        # Valid actions
        valid_actions = ['Alert', 'AlertAndBlock', 'Block']
        if rule_data.get('action') and rule_data['action'] not in valid_actions:
            warnings.append(f"Unknown action: {rule_data['action']}. Valid actions: {valid_actions}")
        
        # Valid OS types
        valid_os_types = ['Windows', 'Linux', 'All']
        if rule_data.get('os_type') and rule_data['os_type'] not in valid_os_types:
            warnings.append(f"Unknown OS type: {rule_data['os_type']}. Valid types: {valid_os_types}")
        
        # Rule name uniqueness
        if rule_data.get('rule_name'):
            existing_rule = self.db.fetch_one(
                "SELECT RuleID FROM Rules WHERE RuleName = ? AND IsActive = 1",
                [rule_data['rule_name']]
            )
            if existing_rule:
                errors.append(f"Rule name already exists: {rule_data['rule_name']}")
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'warnings': warnings
        }