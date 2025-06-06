"""
Rule Engine Core
Xử lý logic kiểm tra rules và tạo alerts
"""

import logging
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
from database.rules import RuleDB
from database.agents import AgentDB
from utils.helpers import sanitize_string, safe_int
from utils.logger import rule_logger

class RuleEngine:
    """Core rule engine để kiểm tra violations"""
    
    def __init__(self):
        self.rule_db = RuleDB()
        self.agent_db = AgentDB()
        self.logger = logging.getLogger(__name__)
        
        # Cache cho rules
        self.rules_cache = {}
        self.agent_rules_cache = {}
        self.last_refresh = 0
        self.refresh_interval = 300  # 5 minutes
        self.lock = threading.Lock()
        
        # Performance tracking
        self.check_count = 0
        self.violation_count = 0
        self.last_stats_time = time.time()
        
        # Initialize
        self.is_initialized = False
        self._initialize()
    
    def _initialize(self):
        """Initialize rule engine"""
        try:
            # Load rules vào cache
            self.refresh_rules()
            self.is_initialized = True
            
            rule_logger.info('engine_initialized', 'Rule engine initialized successfully',
                           total_rules=len(self.rules_cache))
            
        except Exception as e:
            self.logger.error(f"Failed to initialize rule engine: {e}")
            self.is_initialized = False
    
    def refresh_rules(self) -> bool:
        """Refresh rules cache từ database"""
        try:
            with self.lock:
                start_time = time.time()
                
                # Load all active rules
                rules = self.rule_db.get_all_rules()
                
                # Rebuild cache
                new_rules_cache = {}
                for rule in rules:
                    rule_id = rule['RuleID']
                    # Load detailed rule with conditions
                    detailed_rule = self.rule_db.get_rule_by_id(rule_id)
                    if detailed_rule:
                        new_rules_cache[rule_id] = detailed_rule
                
                self.rules_cache = new_rules_cache
                self.last_refresh = time.time()
                
                # Clear agent rules cache để force reload
                self.agent_rules_cache.clear()
                
                load_time = time.time() - start_time
                
                rule_logger.info('rules_refreshed', f'Rules cache refreshed in {load_time:.2f}s',
                               total_rules=len(self.rules_cache), load_time=load_time)
                
                return True
                
        except Exception as e:
            self.logger.error(f"Error refreshing rules: {e}")
            return False
    
    def _should_refresh_rules(self) -> bool:
        """Kiểm tra có cần refresh rules không"""
        return (time.time() - self.last_refresh) > self.refresh_interval
    
    def get_agent_rules(self, hostname: str) -> List[Dict]:
        """Lấy rules áp dụng cho agent"""
        try:
            # Check cache first
            if hostname in self.agent_rules_cache:
                cached_rules, cache_time = self.agent_rules_cache[hostname]
                if (time.time() - cache_time) < 300:  # 5 minutes cache
                    return cached_rules
            
            # Get agent info
            agent = self.agent_db.get_agent(hostname)
            if not agent:
                return []
            
            os_type = agent.get('OSType', 'Unknown')
            
            # Get assigned rule IDs
            assigned_rule_ids = self.agent_db.get_agent_rules(hostname)
            
            # Get global rules for OS type
            global_rules = self.rule_db.get_global_rules(os_type)
            global_rule_ids = [rule['RuleID'] for rule in global_rules]
            
            # Combine assigned and global rules
            all_rule_ids = list(set(assigned_rule_ids + global_rule_ids))
            
            # Get detailed rules from cache
            agent_rules = []
            for rule_id in all_rule_ids:
                if rule_id in self.rules_cache:
                    rule = self.rules_cache[rule_id]
                    # Check OS compatibility
                    rule_os = rule.get('OSType', 'All')
                    if rule_os == 'All' or rule_os == os_type:
                        agent_rules.append(rule)
            
            # Cache result
            self.agent_rules_cache[hostname] = (agent_rules, time.time())
            
            return agent_rules
            
        except Exception as e:
            self.logger.error(f"Error getting agent rules for {hostname}: {e}")
            return []
    
    def check_rules(self, log_type: str, log_data: Dict, hostname: str) -> Tuple[bool, Optional[str], Optional[str], Optional[str], Optional[int], Optional[str]]:
        """
        Kiểm tra log có vi phạm rules không
        
        Returns:
            (violated, description, detection_data, severity, rule_id, action)
        """
        try:
            # Refresh rules nếu cần
            if self._should_refresh_rules():
                self.refresh_rules()
            
            # Update performance counter
            self.check_count += 1
            
            # Get rules cho agent
            agent_rules = self.get_agent_rules(hostname)
            if not agent_rules:
                return False, None, None, None, None, None
            
            # Check từng rule
            for rule in agent_rules:
                try:
                    # Skip nếu rule type không match
                    rule_type = rule.get('RuleType', '').lower()
                    if not self._rule_type_matches(rule_type, log_type):
                        continue
                    
                    # Kiểm tra violation
                    violation = self._check_rule_violation(rule, log_data, log_type)
                    if violation:
                        self.violation_count += 1
                        
                        rule_logger.warning('rule_violation', f'Rule violation detected: {rule["RuleName"]}',
                                          hostname=hostname, rule_id=rule['RuleID'], 
                                          log_type=log_type, severity=rule['Severity'])
                        
                        return (
                            True,
                            violation['description'],
                            violation['detection_data'],
                            rule['Severity'],
                            rule['RuleID'],
                            rule['Action']
                        )
                        
                except Exception as e:
                    self.logger.error(f"Error checking rule {rule.get('RuleID')}: {e}")
                    continue
            
            return False, None, None, None, None, None
            
        except Exception as e:
            self.logger.error(f"Error in check_rules: {e}")
            return False, None, None, None, None, None
    
    def _rule_type_matches(self, rule_type: str, log_type: str) -> bool:
        """Kiểm tra rule type có match với log type"""
        log_type = log_type.lower().replace('_logs', '')
        
        type_mapping = {
            'process': ['process'],
            'file': ['file'],
            'network': ['network']
        }
        
        return rule_type in type_mapping.get(log_type, [])
    
    def _check_rule_violation(self, rule: Dict, log_data: Dict, log_type: str) -> Optional[Dict]:
        """Kiểm tra một rule cụ thể"""
        try:
            rule_type = rule['RuleType'].lower()
            
            if rule_type == 'process':
                return self._check_process_rule(rule, log_data)
            elif rule_type == 'file':
                return self._check_file_rule(rule, log_data)
            elif rule_type == 'network':
                return self._check_network_rule(rule, log_data)
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error checking rule violation: {e}")
            return None
    
    def _check_process_rule(self, rule: Dict, log_data: Dict) -> Optional[Dict]:
        """Kiểm tra process rule"""
        try:
            conditions = rule.get('ProcessConditions', [])
            
            process_name = log_data.get('ProcessName', '').lower()
            process_path = log_data.get('ExecutablePath', '').lower()
            command_line = log_data.get('CommandLine', '').lower()
            user_name = log_data.get('UserName', '').lower()
            
            # Check conditions
            for condition in conditions:
                condition_process = condition.get('ProcessName', '').lower()
                condition_path = condition.get('ProcessPath', '').lower()
                
                # Process name match
                if condition_process and self._pattern_match(condition_process, process_name):
                    return {
                        'description': f"Suspicious process detected: {log_data.get('ProcessName')}",
                        'detection_data': self._build_detection_data(log_data, 'ProcessName', condition_process),
                        'violation_type': 'ProcessName'
                    }
                
                # Process path match
                if condition_path and self._pattern_match(condition_path, process_path):
                    return {
                        'description': f"Suspicious process path: {log_data.get('ExecutablePath')}",
                        'detection_data': self._build_detection_data(log_data, 'ProcessPath', condition_path),
                        'violation_type': 'ProcessPath'
                    }
            
            # Check for suspicious command patterns
            suspicious_patterns = [
                'vssadmin delete shadows',
                'wevtutil cl',
                'bcdedit /set',
                'schtasks /create',
                'reg delete',
                'net user',
                'net localgroup',
                'powershell -encodedcommand',
                'powershell -enc',
                'invoke-expression',
                'downloadstring',
                'certutil -urlcache',
                'bitsadmin /transfer'
            ]
            
            for pattern in suspicious_patterns:
                if pattern.lower() in command_line:
                    return {
                        'description': f"Suspicious command pattern detected: {pattern}",
                        'detection_data': self._build_detection_data(log_data, 'CommandLine', pattern),
                        'violation_type': 'SuspiciousCommand'
                    }
            
            # Check for suspicious process + user combinations
            if user_name == 'system' and process_name in ['cmd.exe', 'powershell.exe']:
                return {
                    'description': f"System account running suspicious process: {process_name}",
                    'detection_data': self._build_detection_data(log_data, 'SystemProcess', process_name),
                    'violation_type': 'SuspiciousSystemProcess'
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error checking process rule: {e}")
            return None
    
    def _check_file_rule(self, rule: Dict, log_data: Dict) -> Optional[Dict]:
        """Kiểm tra file rule"""
        try:
            conditions = rule.get('FileConditions', [])
            
            file_name = log_data.get('FileName', '').lower()
            file_path = log_data.get('FilePath', '').lower()
            event_type = log_data.get('EventType', '').lower()
            file_size = safe_int(log_data.get('FileSize', 0))
            
            # Check conditions
            for condition in conditions:
                condition_name = condition.get('FileName', '').lower()
                condition_path = condition.get('FilePath', '').lower()
                
                # File name match
                if condition_name and self._pattern_match(condition_name, file_name):
                    return {
                        'description': f"Suspicious file activity: {log_data.get('FileName')}",
                        'detection_data': self._build_detection_data(log_data, 'FileName', condition_name),
                        'violation_type': 'FileName'
                    }
                
                # File path match
                if condition_path and self._pattern_match(condition_path, file_path):
                    return {
                        'description': f"Suspicious file location: {log_data.get('FilePath')}",
                        'detection_data': self._build_detection_data(log_data, 'FilePath', condition_path),
                        'violation_type': 'FilePath'
                    }
            
            # Check for suspicious file patterns
            
            # Ransomware file extensions
            ransomware_extensions = [
                '.encrypted', '.locked', '.crypto', '.crypt', '.enc',
                '.xtbl', '.vault', '.micro', '.xxx', '.zzz'
            ]
            
            for ext in ransomware_extensions:
                if file_name.endswith(ext):
                    return {
                        'description': f"Potential ransomware file extension: {ext}",
                        'detection_data': self._build_detection_data(log_data, 'RansomwareExtension', ext),
                        'violation_type': 'RansomwareFile'
                    }
            
            # Executable files in temp locations
            executable_extensions = ['.exe', '.scr', '.bat', '.cmd', '.com', '.pif']
            temp_locations = ['temp', 'tmp', 'appdata\\local\\temp', 'windows\\temp']
            
            if any(file_name.endswith(ext) for ext in executable_extensions):
                if any(temp_loc in file_path for temp_loc in temp_locations):
                    return {
                        'description': f"Executable file in temporary location: {file_name}",
                        'detection_data': self._build_detection_data(log_data, 'TempExecutable', file_path),
                        'violation_type': 'SuspiciousFileLocation'
                    }
            
            # Large file operations
            if file_size > 100 * 1024 * 1024:  # 100MB
                if event_type in ['create', 'modify']:
                    return {
                        'description': f"Large file operation: {file_size / (1024*1024):.1f}MB",
                        'detection_data': self._build_detection_data(log_data, 'LargeFile', str(file_size)),
                        'violation_type': 'LargeFileOperation'
                    }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error checking file rule: {e}")
            return None
    
    def _check_network_rule(self, rule: Dict, log_data: Dict) -> Optional[Dict]:
        """Kiểm tra network rule"""
        try:
            conditions = rule.get('NetworkConditions', [])
            
            remote_address = log_data.get('RemoteAddress', '')
            remote_port = safe_int(log_data.get('RemotePort', 0))
            local_port = safe_int(log_data.get('LocalPort', 0))
            protocol = log_data.get('Protocol', '').lower()
            direction = log_data.get('Direction', '').lower()
            process_name = log_data.get('ProcessName', '').lower()
            
            # Check conditions
            for condition in conditions:
                condition_ip = condition.get('IPAddress', '')
                condition_port = safe_int(condition.get('Port', 0))
                condition_protocol = condition.get('Protocol', '').lower()
                
                # IP address match
                if condition_ip and self._ip_pattern_match(condition_ip, remote_address):
                    return {
                        'description': f"Connection to flagged IP: {remote_address}",
                        'detection_data': self._build_detection_data(log_data, 'IPAddress', condition_ip),
                        'violation_type': 'SuspiciousIP'
                    }
                
                # Port match
                if condition_port and condition_port == remote_port:
                    return {
                        'description': f"Connection to suspicious port: {remote_port}",
                        'detection_data': self._build_detection_data(log_data, 'Port', str(condition_port)),
                        'violation_type': 'SuspiciousPort'
                    }
                
                # Protocol match với additional checks
                if condition_protocol and condition_protocol == protocol:
                    return {
                        'description': f"Suspicious {protocol.upper()} connection detected",
                        'detection_data': self._build_detection_data(log_data, 'Protocol', condition_protocol),
                        'violation_type': 'SuspiciousProtocol'
                    }
            
            # Check for commonly used malicious ports
            suspicious_ports = [
                4444, 5555, 6666, 7777, 8888, 9999,  # Common backdoor ports
                1337, 31337,  # Leet speak ports
                3389,  # RDP
                5900, 5901,  # VNC
                6667, 6668, 6669,  # IRC
                1234, 12345,  # Common trojan ports
                4000, 5000, 8000, 9000  # Common web backdoors
            ]
            
            if remote_port in suspicious_ports:
                return {
                    'description': f"Connection to commonly abused port: {remote_port}",
                    'detection_data': self._build_detection_data(log_data, 'MaliciousPort', str(remote_port)),
                    'violation_type': 'MaliciousPort'
                }
            
            # Check for suspicious process network activity
            suspicious_network_processes = [
                'cmd.exe', 'powershell.exe', 'wmic.exe', 'certutil.exe',
                'regsvr32.exe', 'rundll32.exe', 'mshta.exe'
            ]
            
            if process_name in suspicious_network_processes and direction == 'outbound':
                return {
                    'description': f"Suspicious outbound connection from {process_name}",
                    'detection_data': self._build_detection_data(log_data, 'SuspiciousProcessNetwork', process_name),
                    'violation_type': 'SuspiciousProcessNetwork'
                }
            
            # Check for private IP ranges (might indicate lateral movement)
            private_ranges = ['10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.',
                            '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.',
                            '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '192.168.']
            
            if any(remote_address.startswith(prefix) for prefix in private_ranges):
                if remote_port in [22, 23, 135, 139, 445, 1433, 3389, 5432, 5985, 5986]:
                    return {
                        'description': f"Potential lateral movement: {remote_address}:{remote_port}",
                        'detection_data': self._build_detection_data(log_data, 'LateralMovement', f"{remote_address}:{remote_port}"),
                        'violation_type': 'LateralMovement'
                    }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error checking network rule: {e}")
            return None
    
    def _pattern_match(self, pattern: str, text: str) -> bool:
        """Check if pattern matches text (supports wildcards)"""
        try:
            if not pattern or not text:
                return False
            
            pattern = pattern.lower()
            text = text.lower()
            
            # Exact match
            if pattern == text:
                return True
            
            # Wildcard support
            if '*' in pattern:
                # Simple wildcard matching
                if pattern.startswith('*') and pattern.endswith('*'):
                    # *pattern*
                    return pattern[1:-1] in text
                elif pattern.startswith('*'):
                    # *pattern
                    return text.endswith(pattern[1:])
                elif pattern.endswith('*'):
                    # pattern*
                    return text.startswith(pattern[:-1])
                else:
                    # pattern*something or more complex
                    import fnmatch
                    return fnmatch.fnmatch(text, pattern)
            
            # Substring match
            return pattern in text
            
        except Exception as e:
            self.logger.error(f"Error in pattern matching: {e}")
            return False
    
    def _ip_pattern_match(self, pattern: str, ip: str) -> bool:
        """Check if IP matches pattern (supports CIDR and wildcards)"""
        try:
            if not pattern or not ip:
                return False
            
            # Exact match
            if pattern == ip:
                return True
            
            # Wildcard pattern
            if '*' in pattern:
                pattern_parts = pattern.split('.')
                ip_parts = ip.split('.')
                
                if len(pattern_parts) != len(ip_parts):
                    return False
                
                for p_part, ip_part in zip(pattern_parts, ip_parts):
                    if p_part != '*' and p_part != ip_part:
                        return False
                
                return True
            
            # CIDR notation support (basic)
            if '/' in pattern:
                try:
                    import ipaddress
                    network = ipaddress.IPv4Network(pattern, strict=False)
                    return ipaddress.IPv4Address(ip) in network
                except:
                    pass
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error in IP pattern matching: {e}")
            return False
    
    def _build_detection_data(self, log_data: Dict, match_type: str, matched_value: str) -> str:
        """Build detection data JSON string"""
        try:
            import json
            
            detection_data = {
                'match_type': match_type,
                'matched_value': matched_value,
                'timestamp': datetime.now().isoformat(),
                'original_log': log_data
            }
            
            return json.dumps(detection_data)
            
        except Exception as e:
            self.logger.error(f"Error building detection data: {e}")
            return "{}"
    
    def get_rules_summary(self) -> Dict:
        """Lấy tóm tắt rules hiện tại"""
        try:
            # Refresh if needed
            if self._should_refresh_rules():
                self.refresh_rules()
            
            summary = {
                'total_rules': len(self.rules_cache),
                'by_type': {},
                'by_severity': {},
                'by_os': {},
                'cache_stats': {
                    'last_refresh': self.last_refresh,
                    'refresh_interval': self.refresh_interval,
                    'cached_agent_rules': len(self.agent_rules_cache)
                },
                'performance_stats': self._get_performance_stats()
            }
            
            # Count by categories
            for rule in self.rules_cache.values():
                # By type
                rule_type = rule.get('RuleType', 'Unknown')
                summary['by_type'][rule_type] = summary['by_type'].get(rule_type, 0) + 1
                
                # By severity
                severity = rule.get('Severity', 'Unknown')
                summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
                
                # By OS
                os_type = rule.get('OSType', 'All')
                summary['by_os'][os_type] = summary['by_os'].get(os_type, 0) + 1
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Error getting rules summary: {e}")
            return {}
    
    def _get_performance_stats(self) -> Dict:
        """Lấy performance statistics"""
        try:
            current_time = time.time()
            elapsed_time = current_time - self.last_stats_time
            
            if elapsed_time > 0:
                checks_per_second = self.check_count / elapsed_time
                violations_per_second = self.violation_count / elapsed_time
                violation_rate = (self.violation_count / max(self.check_count, 1)) * 100
            else:
                checks_per_second = 0
                violations_per_second = 0
                violation_rate = 0
            
            return {
                'total_checks': self.check_count,
                'total_violations': self.violation_count,
                'checks_per_second': round(checks_per_second, 2),
                'violations_per_second': round(violations_per_second, 2),
                'violation_rate_percent': round(violation_rate, 2),
                'uptime_seconds': int(elapsed_time)
            }
            
        except Exception as e:
            self.logger.error(f"Error getting performance stats: {e}")
            return {}
    
    def reset_performance_stats(self):
        """Reset performance counters"""
        try:
            self.check_count = 0
            self.violation_count = 0
            self.last_stats_time = time.time()
            
            rule_logger.info('stats_reset', 'Performance statistics reset')
            
        except Exception as e:
            self.logger.error(f"Error resetting performance stats: {e}")
    
    def validate_rule_against_log(self, rule_id: int, log_data: Dict, log_type: str) -> Dict:
        """Test một rule cụ thể với log data"""
        try:
            if rule_id not in self.rules_cache:
                return {'valid': False, 'error': 'Rule not found in cache'}
            
            rule = self.rules_cache[rule_id]
            
            # Check if rule type matches log type
            if not self._rule_type_matches(rule['RuleType'].lower(), log_type):
                return {
                    'valid': False, 
                    'error': f"Rule type {rule['RuleType']} does not match log type {log_type}"
                }
            
            # Test the rule
            violation = self._check_rule_violation(rule, log_data, log_type)
            
            return {
                'valid': True,
                'rule_triggered': violation is not None,
                'violation_details': violation,
                'rule_info': {
                    'id': rule_id,
                    'name': rule['RuleName'],
                    'type': rule['RuleType'],
                    'severity': rule['Severity']
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error validating rule {rule_id}: {e}")
            return {'valid': False, 'error': str(e)}
    
    def get_rule_effectiveness(self, days: int = 7) -> Dict:
        """Phân tích hiệu quả của rules"""
        try:
            # Lấy statistics từ database
            from database.alerts import AlertDB
            alert_db = AlertDB()
            
            start_time = datetime.now() - timedelta(days=days)
            
            # Get all alerts in period
            alerts = alert_db.get_alerts({
                'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S')
            }, 10000)
            
            effectiveness = {
                'period_days': days,
                'total_alerts': len(alerts),
                'rules_triggered': {},
                'most_effective_rules': [],
                'least_effective_rules': [],
                'rules_with_no_alerts': []
            }
            
            # Count alerts per rule
            rule_alert_counts = {}
            for alert in alerts:
                rule_id = alert.get('RuleID')
                if rule_id:
                    rule_alert_counts[rule_id] = rule_alert_counts.get(rule_id, 0) + 1
            
            # Build effectiveness data
            for rule_id, rule in self.rules_cache.items():
                alert_count = rule_alert_counts.get(rule_id, 0)
                effectiveness['rules_triggered'][rule_id] = {
                    'rule_name': rule['RuleName'],
                    'rule_type': rule['RuleType'],
                    'severity': rule['Severity'],
                    'alert_count': alert_count,
                    'effectiveness_score': self._calculate_effectiveness_score(rule, alert_count)
                }
            
            # Sort by effectiveness
            sorted_rules = sorted(
                effectiveness['rules_triggered'].items(),
                key=lambda x: x[1]['alert_count'],
                reverse=True
            )
            
            effectiveness['most_effective_rules'] = [
                {'rule_id': rid, **data} for rid, data in sorted_rules[:10]
            ]
            
            effectiveness['least_effective_rules'] = [
                {'rule_id': rid, **data} for rid, data in sorted_rules[-10:]
                if data['alert_count'] > 0
            ]
            
            effectiveness['rules_with_no_alerts'] = [
                {'rule_id': rid, **data} for rid, data in sorted_rules
                if data['alert_count'] == 0
            ]
            
            return effectiveness
            
        except Exception as e:
            self.logger.error(f"Error getting rule effectiveness: {e}")
            return {}
    
    def _calculate_effectiveness_score(self, rule: Dict, alert_count: int) -> float:
        """Calculate effectiveness score for a rule"""
        try:
            # Base score from alert count
            base_score = min(alert_count * 10, 100)
            
            # Severity multiplier
            severity_multipliers = {
                'Critical': 1.5,
                'High': 1.2,
                'Medium': 1.0,
                'Low': 0.8
            }
            
            severity = rule.get('Severity', 'Medium')
            multiplier = severity_multipliers.get(severity, 1.0)
            
            return min(base_score * multiplier, 100)
            
        except Exception as e:
            self.logger.error(f"Error calculating effectiveness score: {e}")
            return 0.0
    
    def optimize_rules(self) -> Dict:
        """Suggest rule optimizations"""
        try:
            optimization_suggestions = {
                'rules_to_disable': [],
                'rules_to_tune': [],
                'missing_coverage': [],
                'performance_impact': []
            }
            
            effectiveness = self.get_rule_effectiveness(30)  # 30 days
            
            # Rules with no alerts - candidates for disabling
            for rule_data in effectiveness.get('rules_with_no_alerts', []):
                optimization_suggestions['rules_to_disable'].append({
                    'rule_id': rule_data['rule_id'],
                    'rule_name': rule_data['rule_name'],
                    'reason': 'No alerts generated in 30 days'
                })
            
            # Rules with too many alerts - might need tuning
            for rule_data in effectiveness.get('most_effective_rules', [])[:5]:
                if rule_data['alert_count'] > 100:  # More than 100 alerts in 30 days
                    optimization_suggestions['rules_to_tune'].append({
                        'rule_id': rule_data['rule_id'],
                        'rule_name': rule_data['rule_name'],
                        'alert_count': rule_data['alert_count'],
                        'reason': 'Generating excessive alerts - may need refinement'
                    })
            
            return optimization_suggestions
            
        except Exception as e:
            self.logger.error(f"Error optimizing rules: {e}")
            return {}
    
    def cleanup(self):
        """Cleanup resources"""
        try:
            with self.lock:
                self.rules_cache.clear()
                self.agent_rules_cache.clear()
            
            rule_logger.info('engine_cleanup', 'Rule engine cleaned up')
            
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")