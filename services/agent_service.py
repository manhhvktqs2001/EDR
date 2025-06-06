"""
Agent Service - Xử lý logic business cho agents
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from database.agents import AgentDB
from database.rules import RuleDB
from utils.helpers import validate_hostname, calculate_time_ago, safe_int
from utils.logger import agent_logger

class AgentService:
    def __init__(self):
        self.agent_db = AgentDB()
        self.rule_db = RuleDB()
        self.logger = logging.getLogger(__name__)
    
    def get_agent_dashboard_data(self, hostname: str = None) -> Dict:
        """Lấy dữ liệu dashboard cho agents"""
        try:
            if hostname:
                # Dữ liệu cho agent cụ thể
                agent = self.agent_db.get_agent(hostname)
                if not agent:
                    return {'error': 'Agent not found'}
                
                return self._get_single_agent_dashboard(agent)
            else:
                # Dữ liệu tổng quan tất cả agents
                return self._get_all_agents_dashboard()
                
        except Exception as e:
            self.logger.error(f"Error getting agent dashboard data: {e}")
            return {'error': str(e)}
    
    def _get_single_agent_dashboard(self, agent: Dict) -> Dict:
        """Lấy dashboard data cho một agent"""
        try:
            hostname = agent['Hostname']
            
            # Thông tin cơ bản
            basic_info = {
                'hostname': hostname,
                'os_type': agent.get('OSType', 'Unknown'),
                'os_version': agent.get('OSVersion', 'Unknown'),
                'architecture': agent.get('Architecture', 'Unknown'),
                'agent_version': agent.get('AgentVersion', 'Unknown'),
                'ip_address': agent.get('IPAddress', 'Unknown'),
                'status': agent.get('Status', 'Offline'),
                'first_seen': agent.get('FirstSeen'),
                'last_seen': agent.get('LastSeen'),
                'is_active': agent.get('IsActive', False)
            }
            
            # Tính toán thời gian
            if agent.get('LastSeen'):
                basic_info['last_seen_ago'] = calculate_time_ago(agent['LastSeen'])
                basic_info['is_online'] = self._is_agent_online(agent['LastSeen'])
            
            # Lấy rules được assign
            assigned_rules = self._get_agent_rules_summary(hostname)
            
            # Lấy alerts gần đây
            recent_alerts = self._get_agent_recent_alerts(hostname)
            
            # Lấy activity logs
            activity_summary = self._get_agent_activity_summary(hostname)
            
            return {
                'basic_info': basic_info,
                'rules': assigned_rules,
                'recent_alerts': recent_alerts,
                'activity': activity_summary,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error getting single agent dashboard: {e}")
            return {'error': str(e)}
    
    def _get_all_agents_dashboard(self) -> Dict:
        """Lấy dashboard data cho tất cả agents"""
        try:
            agents = self.agent_db.get_all_agents()
            
            # Thống kê tổng quan
            summary = {
                'total_agents': len(agents),
                'online_agents': 0,
                'offline_agents': 0,
                'by_os_type': {},
                'by_status': {},
                'recently_registered': 0
            }
            
            agent_list = []
            recent_threshold = datetime.now() - timedelta(hours=24)
            
            for agent in agents:
                # Thống kê cơ bản
                status = agent.get('Status', 'Offline')
                os_type = agent.get('OSType', 'Unknown')
                
                if self._is_agent_online(agent.get('LastSeen')):
                    summary['online_agents'] += 1
                else:
                    summary['offline_agents'] += 1
                
                summary['by_status'][status] = summary['by_status'].get(status, 0) + 1
                summary['by_os_type'][os_type] = summary['by_os_type'].get(os_type, 0) + 1
                
                # Agents đăng ký gần đây
                if agent.get('FirstSeen'):
                    try:
                        first_seen = datetime.strptime(agent['FirstSeen'], '%Y-%m-%d %H:%M:%S')
                        if first_seen >= recent_threshold:
                            summary['recently_registered'] += 1
                    except:
                        pass
                
                # Thông tin agent cho list
                agent_info = {
                    'hostname': agent['Hostname'],
                    'os_type': os_type,
                    'status': status,
                    'last_seen': agent.get('LastSeen'),
                    'last_seen_ago': calculate_time_ago(agent.get('LastSeen')),
                    'is_online': self._is_agent_online(agent.get('LastSeen')),
                    'ip_address': agent.get('IPAddress', 'Unknown')
                }
                agent_list.append(agent_info)
            
            # Sắp xếp agents theo last_seen
            agent_list.sort(key=lambda x: x.get('last_seen', ''), reverse=True)
            
            return {
                'summary': summary,
                'agents': agent_list,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error getting all agents dashboard: {e}")
            return {'error': str(e)}
    
    def _is_agent_online(self, last_seen: str, threshold_minutes: int = 5) -> bool:
        """Kiểm tra agent có online không dựa trên last_seen"""
        if not last_seen:
            return False
        
        try:
            if isinstance(last_seen, str):
                last_seen_dt = datetime.strptime(last_seen, '%Y-%m-%d %H:%M:%S')
            else:
                last_seen_dt = last_seen
            
            threshold = datetime.now() - timedelta(minutes=threshold_minutes)
            return last_seen_dt >= threshold
            
        except:
            return False
    
    def _get_agent_rules_summary(self, hostname: str) -> Dict:
        """Lấy tóm tắt rules của agent"""
        try:
            # Lấy rule IDs được assign
            rule_ids = self.agent_db.get_agent_rules(hostname)
            
            # Lấy thông tin chi tiết rules
            rules_detail = []
            by_type = {}
            by_severity = {}
            active_count = 0
            
            for rule_id in rule_ids:
                rule = self.rule_db.get_rule_by_id(rule_id)
                if rule:
                    rule_type = rule.get('RuleType', 'Unknown')
                    severity = rule.get('Severity', 'Unknown')
                    is_active = rule.get('IsActive', False)
                    
                    rules_detail.append({
                        'rule_id': rule_id,
                        'name': rule.get('RuleName', 'Unknown'),
                        'type': rule_type,
                        'severity': severity,
                        'is_active': is_active,
                        'description': rule.get('Description', '')
                    })
                    
                    by_type[rule_type] = by_type.get(rule_type, 0) + 1
                    by_severity[severity] = by_severity.get(severity, 0) + 1
                    
                    if is_active:
                        active_count += 1
            
            return {
                'total_rules': len(rule_ids),
                'active_rules': active_count,
                'inactive_rules': len(rule_ids) - active_count,
                'by_type': by_type,
                'by_severity': by_severity,
                'rules': rules_detail
            }
            
        except Exception as e:
            self.logger.error(f"Error getting agent rules summary: {e}")
            return {'total_rules': 0, 'active_rules': 0, 'rules': []}
    
    def _get_agent_recent_alerts(self, hostname: str, hours: int = 24) -> Dict:
        """Lấy alerts gần đây của agent"""
        try:
            from database.alerts import AlertDB
            
            alert_db = AlertDB()
            alerts = alert_db.get_recent_alerts(hostname, hours, 20)
            
            # Thống kê alerts
            by_severity = {}
            by_status = {}
            recent_count = 0
            
            for alert in alerts:
                severity = alert.get('Severity', 'Unknown')
                status = alert.get('Status', 'Unknown')
                
                by_severity[severity] = by_severity.get(severity, 0) + 1
                by_status[status] = by_status.get(status, 0) + 1
                
                # Alerts trong 1 giờ qua
                alert_time = alert.get('Time')
                if alert_time:
                    try:
                        alert_dt = datetime.strptime(alert_time, '%Y-%m-%d %H:%M:%S')
                        if datetime.now() - alert_dt < timedelta(hours=1):
                            recent_count += 1
                    except:
                        pass
            
            return {
                'total_alerts': len(alerts),
                'recent_count': recent_count,
                'by_severity': by_severity,
                'by_status': by_status,
                'alerts': alerts[:10]  # Top 10 most recent
            }
            
        except Exception as e:
            self.logger.error(f"Error getting agent recent alerts: {e}")
            return {'total_alerts': 0, 'alerts': []}
    
    def _get_agent_activity_summary(self, hostname: str) -> Dict:
        """Lấy tóm tắt hoạt động của agent"""
        try:
            from database.logs import LogDB
            
            log_db = LogDB()
            
            # Lấy logs gần đây
            process_logs = log_db.get_process_logs(hostname, limit=100)
            file_logs = log_db.get_file_logs(hostname, limit=100)
            network_logs = log_db.get_network_logs(hostname, limit=100)
            
            # Tính thống kê
            activity = {
                'process_events': len(process_logs),
                'file_events': len(file_logs),
                'network_events': len(network_logs),
                'total_events': len(process_logs) + len(file_logs) + len(network_logs),
                'last_activity': None,
                'top_processes': [],
                'top_files': [],
                'top_connections': []
            }
            
            # Tìm last activity
            all_logs = []
            for log in process_logs + file_logs + network_logs:
                if log.get('Time'):
                    all_logs.append(log['Time'])
            
            if all_logs:
                activity['last_activity'] = max(all_logs)
                activity['last_activity_ago'] = calculate_time_ago(activity['last_activity'])
            
            # Top processes
            process_counts = {}
            for log in process_logs:
                proc_name = log.get('ProcessName', 'Unknown')
                process_counts[proc_name] = process_counts.get(proc_name, 0) + 1
            
            activity['top_processes'] = [
                {'name': name, 'count': count}
                for name, count in sorted(process_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            ]
            
            # Top files
            file_counts = {}
            for log in file_logs:
                file_name = log.get('FileName', 'Unknown')
                file_counts[file_name] = file_counts.get(file_name, 0) + 1
            
            activity['top_files'] = [
                {'name': name, 'count': count}
                for name, count in sorted(file_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            ]
            
            # Top connections
            connection_counts = {}
            for log in network_logs:
                remote_addr = log.get('RemoteAddress', 'Unknown')
                if remote_addr and remote_addr != 'Unknown':
                    connection_counts[remote_addr] = connection_counts.get(remote_addr, 0) + 1
            
            activity['top_connections'] = [
                {'address': addr, 'count': count}
                for addr, count in sorted(connection_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            ]
            
            return activity
            
        except Exception as e:
            self.logger.error(f"Error getting agent activity summary: {e}")
            return {'total_events': 0, 'top_processes': [], 'top_files': [], 'top_connections': []}
    
    def assign_rules_to_agent(self, hostname: str, rule_ids: List[int]) -> Tuple[bool, str]:
        """Assign rules cho agent"""
        try:
            # Kiểm tra agent tồn tại
            agent = self.agent_db.get_agent(hostname)
            if not agent:
                return False, f"Agent {hostname} not found"
            
            success_count = 0
            failed_rules = []
            
            for rule_id in rule_ids:
                try:
                    # Kiểm tra rule tồn tại
                    rule = self.rule_db.get_rule_by_id(rule_id)
                    if not rule:
                        failed_rules.append(f"Rule {rule_id} not found")
                        continue
                    
                    # Assign rule
                    if self.agent_db.assign_rule(hostname, rule_id):
                        success_count += 1
                    else:
                        failed_rules.append(f"Failed to assign rule {rule_id}")
                        
                except Exception as e:
                    failed_rules.append(f"Error assigning rule {rule_id}: {str(e)}")
            
            # Log activity
            agent_logger.info('rules_assigned', 
                            f'Assigned {success_count}/{len(rule_ids)} rules to {hostname}',
                            hostname=hostname, success_count=success_count, 
                            total_rules=len(rule_ids))
            
            if failed_rules:
                message = f"Assigned {success_count}/{len(rule_ids)} rules. Failures: {'; '.join(failed_rules)}"
                return success_count > 0, message
            else:
                return True, f"Successfully assigned {success_count} rules to {hostname}"
                
        except Exception as e:
            self.logger.error(f"Error assigning rules to agent {hostname}: {e}")
            return False, str(e)
    
    def get_applicable_rules_for_agent(self, hostname: str) -> Dict:
        """Lấy các rules có thể áp dụng cho agent"""
        try:
            agent = self.agent_db.get_agent(hostname)
            if not agent:
                return {'error': f"Agent {hostname} not found"}
            
            os_type = agent.get('OSType', 'Unknown')
            
            # Lấy rules có thể áp dụng
            applicable_rules = self.rule_db.get_agent_applicable_rules(hostname, os_type)
            
            # Lấy rules đã được assign
            assigned_rule_ids = self.agent_db.get_agent_rules(hostname)
            
            # Phân loại rules
            available_rules = []
            assigned_rules = []
            
            for rule in applicable_rules:
                rule_info = {
                    'rule_id': rule['RuleID'],
                    'name': rule.get('RuleName'),
                    'type': rule.get('RuleType'),
                    'severity': rule.get('Severity'),
                    'description': rule.get('Description'),
                    'is_global': rule.get('IsGlobal'),
                    'os_type': rule.get('OSType')
                }
                
                if rule['RuleID'] in assigned_rule_ids:
                    assigned_rules.append(rule_info)
                else:
                    available_rules.append(rule_info)
            
            return {
                'agent_info': {
                    'hostname': hostname,
                    'os_type': os_type
                },
                'available_rules': available_rules,
                'assigned_rules': assigned_rules,
                'summary': {
                    'total_available': len(available_rules),
                    'total_assigned': len(assigned_rules),
                    'can_assign_more': len(available_rules) > 0
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error getting applicable rules for agent {hostname}: {e}")
            return {'error': str(e)}
    
    def update_agent_configuration(self, hostname: str, config_updates: Dict) -> Tuple[bool, str]:
        """Cập nhật cấu hình agent"""
        try:
            # Kiểm tra agent tồn tại
            agent = self.agent_db.get_agent(hostname)
            if not agent:
                return False, f"Agent {hostname} not found"
            
            # Validate config updates
            valid_fields = ['Status', 'IsActive', 'AgentVersion', 'IPAddress', 'MACAddress']
            filtered_updates = {}
            
            for field, value in config_updates.items():
                if field in valid_fields:
                    filtered_updates[field] = value
            
            if not filtered_updates:
                return False, "No valid configuration fields to update"
            
            # Cập nhật agent
            success = self.agent_db._update_agent(hostname, filtered_updates)
            
            if success:
                agent_logger.info('config_updated', f'Configuration updated for {hostname}',
                                hostname=hostname, updates=filtered_updates)
                return True, f"Configuration updated successfully for {hostname}"
            else:
                return False, "Failed to update agent configuration"
                
        except Exception as e:
            self.logger.error(f"Error updating agent configuration: {e}")
            return False, str(e)
    
    def get_agent_performance_metrics(self, hostname: str, hours: int = 24) -> Dict:
        """Lấy metrics hiệu suất của agent"""
        try:
            from database.logs import LogDB
            
            agent = self.agent_db.get_agent(hostname)
            if not agent:
                return {'error': f"Agent {hostname} not found"}
            
            log_db = LogDB()
            
            # Lấy logs trong khoảng thời gian
            process_logs = log_db.get_process_logs(hostname, limit=1000)
            file_logs = log_db.get_file_logs(hostname, limit=1000)
            network_logs = log_db.get_network_logs(hostname, limit=1000)
            
            # Tính toán metrics
            metrics = {
                'log_volumes': {
                    'process_logs': len(process_logs),
                    'file_logs': len(file_logs),
                    'network_logs': len(network_logs),
                    'total_logs': len(process_logs) + len(file_logs) + len(network_logs)
                },
                'system_activity': {
                    'unique_processes': len(set(log.get('ProcessName', '') for log in process_logs)),
                    'unique_files': len(set(log.get('FileName', '') for log in file_logs)),
                    'unique_connections': len(set(log.get('RemoteAddress', '') for log in network_logs if log.get('RemoteAddress')))
                },
                'performance_indicators': {
                    'avg_cpu_usage': 0,
                    'avg_memory_usage': 0,
                    'high_activity_periods': 0
                },
                'agent_health': {
                    'last_heartbeat': agent.get('LastHeartbeat'),
                    'connection_stability': 'stable',  # Would calculate based on connection history
                    'data_quality_score': 95  # Would calculate based on log completeness
                }
            }
            
            # Tính average CPU và Memory từ process logs
            cpu_values = [safe_int(log.get('CPUUsage', 0)) for log in process_logs if log.get('CPUUsage')]
            memory_values = [safe_int(log.get('MemoryUsage', 0)) for log in process_logs if log.get('MemoryUsage')]
            
            if cpu_values:
                metrics['performance_indicators']['avg_cpu_usage'] = sum(cpu_values) / len(cpu_values)
            
            if memory_values:
                metrics['performance_indicators']['avg_memory_usage'] = sum(memory_values) / len(memory_values)
            
            # Detect high activity periods (hours with more than 100 events)
            hourly_activity = {}
            for log in process_logs + file_logs + network_logs:
                if log.get('Time'):
                    try:
                        hour = datetime.strptime(log['Time'], '%Y-%m-%d %H:%M:%S').strftime('%Y-%m-%d %H')
                        hourly_activity[hour] = hourly_activity.get(hour, 0) + 1
                    except:
                        continue
            
            metrics['performance_indicators']['high_activity_periods'] = len([
                count for count in hourly_activity.values() if count > 100
            ])
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"Error getting agent performance metrics: {e}")
            return {'error': str(e)}
    
    def generate_agent_report(self, hostname: str, report_type: str = 'summary') -> Dict:
        """Tạo báo cáo chi tiết cho agent"""
        try:
            agent = self.agent_db.get_agent(hostname)
            if not agent:
                return {'error': f"Agent {hostname} not found"}
            
            report = {
                'agent_info': {
                    'hostname': hostname,
                    'os_type': agent.get('OSType'),
                    'os_version': agent.get('OSVersion'),
                    'agent_version': agent.get('AgentVersion'),
                    'status': agent.get('Status'),
                    'ip_address': agent.get('IPAddress'),
                    'first_seen': agent.get('FirstSeen'),
                    'last_seen': agent.get('LastSeen')
                },
                'report_type': report_type,
                'generated_at': datetime.now().isoformat(),
                'period': '24 hours'
            }
            
            if report_type == 'summary':
                # Báo cáo tóm tắt
                report['summary'] = {
                    'rules': self._get_agent_rules_summary(hostname),
                    'alerts': self._get_agent_recent_alerts(hostname, 24),
                    'activity': self._get_agent_activity_summary(hostname)
                }
                
            elif report_type == 'detailed':
                # Báo cáo chi tiết
                report['detailed'] = {
                    'rules': self._get_agent_rules_summary(hostname),
                    'alerts': self._get_agent_recent_alerts(hostname, 168),  # 7 days
                    'activity': self._get_agent_activity_summary(hostname),
                    'performance': self.get_agent_performance_metrics(hostname, 24),
                    'security_events': self._get_agent_security_events(hostname),
                    'compliance_status': self._get_agent_compliance_status(hostname)
                }
                
            elif report_type == 'security':
                # Báo cáo bảo mật
                report['security'] = {
                    'threat_level': self._calculate_agent_threat_level(hostname),
                    'security_alerts': self._get_agent_recent_alerts(hostname, 168),
                    'suspicious_activities': self._get_suspicious_activities(hostname),
                    'security_score': self._calculate_security_score(hostname),
                    'recommendations': self._get_security_recommendations(hostname)
                }
            
            return report
            
        except Exception as e:
            self.logger.error(f"Error generating agent report: {e}")
            return {'error': str(e)}
    
    def _get_agent_security_events(self, hostname: str) -> Dict:
        """Lấy security events của agent"""
        try:
            from database.alerts import AlertDB
            
            alert_db = AlertDB()
            
            # Lấy security alerts
            security_alerts = alert_db.get_alerts({
                'hostname': hostname,
                'start_time': (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')
            }, 100)
            
            # Phân loại theo mức độ nghiêm trọng
            by_severity = {}
            timeline = []
            
            for alert in security_alerts:
                severity = alert.get('Severity', 'Unknown')
                by_severity[severity] = by_severity.get(severity, 0) + 1
                
                timeline.append({
                    'time': alert.get('Time'),
                    'type': alert.get('AlertType'),
                    'severity': severity,
                    'description': alert.get('Description', '')[:100] + '...'
                })
            
            return {
                'total_events': len(security_alerts),
                'by_severity': by_severity,
                'timeline': sorted(timeline, key=lambda x: x.get('time', ''), reverse=True)[:20]
            }
            
        except Exception as e:
            self.logger.error(f"Error getting agent security events: {e}")
            return {'total_events': 0, 'timeline': []}
    
    def _get_agent_compliance_status(self, hostname: str) -> Dict:
        """Lấy trạng thái tuân thủ của agent"""
        try:
            agent = self.agent_db.get_agent(hostname)
            rules_summary = self._get_agent_rules_summary(hostname)
            
            # Tính compliance score
            compliance_factors = {
                'agent_updated': 1 if agent.get('AgentVersion', '').startswith('2.') else 0,
                'rules_active': 1 if rules_summary.get('active_rules', 0) > 0 else 0,
                'monitoring_enabled': 1 if agent.get('Status') == 'Online' else 0,
                'recent_activity': 1 if agent.get('LastSeen') else 0
            }
            
            compliance_score = (sum(compliance_factors.values()) / len(compliance_factors)) * 100
            
            return {
                'compliance_score': round(compliance_score, 1),
                'status': 'compliant' if compliance_score >= 80 else 'non_compliant',
                'factors': compliance_factors,
                'recommendations': self._get_compliance_recommendations(compliance_factors)
            }
            
        except Exception as e:
            self.logger.error(f"Error getting agent compliance status: {e}")
            return {'compliance_score': 0, 'status': 'unknown'}
    
    def _calculate_agent_threat_level(self, hostname: str) -> str:
        """Tính toán mức độ đe dọa của agent"""
        try:
            from database.alerts import AlertDB
            
            alert_db = AlertDB()
            
            # Lấy alerts gần đây
            recent_alerts = alert_db.get_alerts({
                'hostname': hostname,
                'start_time': (datetime.now() - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
            }, 50)
            
            # Tính threat score
            threat_score = 0
            
            for alert in recent_alerts:
                severity = alert.get('Severity', 'Low')
                if severity == 'Critical':
                    threat_score += 10
                elif severity == 'High':
                    threat_score += 5
                elif severity == 'Medium':
                    threat_score += 2
                elif severity == 'Low':
                    threat_score += 1
            
            # Xác định threat level
            if threat_score >= 50:
                return 'Critical'
            elif threat_score >= 25:
                return 'High'
            elif threat_score >= 10:
                return 'Medium'
            else:
                return 'Low'
                
        except Exception as e:
            self.logger.error(f"Error calculating agent threat level: {e}")
            return 'Unknown'
    
    def _get_suspicious_activities(self, hostname: str) -> List[Dict]:
        """Lấy các hoạt động đáng ngờ"""
        try:
            from database.logs import LogDB
            
            log_db = LogDB()
            suspicious_activities = []
            
            # Lấy process logs
            process_logs = log_db.get_process_logs(hostname, limit=200)
            
            for log in process_logs:
                process_name = log.get('ProcessName', '').lower()
                command_line = log.get('CommandLine', '').lower()
                
                # Kiểm tra suspicious patterns
                if any(suspicious in process_name for suspicious in ['cmd.exe', 'powershell.exe', 'wmic.exe']):
                    suspicious_activities.append({
                        'type': 'suspicious_process',
                        'time': log.get('Time'),
                        'process': log.get('ProcessName'),
                        'details': f"Suspicious process execution: {log.get('ProcessName')}"
                    })
                
                if any(pattern in command_line for pattern in ['shadowcopy delete', 'vssadmin', 'bcdedit']):
                    suspicious_activities.append({
                        'type': 'suspicious_command',
                        'time': log.get('Time'),
                        'command': command_line[:100],
                        'details': "Potentially malicious command detected"
                    })
            
            return suspicious_activities[:10]  # Top 10
            
        except Exception as e:
            self.logger.error(f"Error getting suspicious activities: {e}")
            return []
    
    def _calculate_security_score(self, hostname: str) -> int:
        """Tính security score cho agent"""
        try:
            agent = self.agent_db.get_agent(hostname)
            rules_summary = self._get_agent_rules_summary(hostname)
            threat_level = self._calculate_agent_threat_level(hostname)
            
            score = 100  # Start with perfect score
            
            # Deduct points based on factors
            if agent.get('Status') != 'Online':
                score -= 20
            
            if rules_summary.get('active_rules', 0) == 0:
                score -= 30
            
            if threat_level == 'Critical':
                score -= 40
            elif threat_level == 'High':
                score -= 25
            elif threat_level == 'Medium':
                score -= 10
            
            return max(0, score)  # Ensure score doesn't go below 0
            
        except Exception as e:
            self.logger.error(f"Error calculating security score: {e}")
            return 50  # Default middle score
    
    def _get_security_recommendations(self, hostname: str) -> List[str]:
        """Lấy khuyến nghị bảo mật cho agent"""
        try:
            recommendations = []
            
            agent = self.agent_db.get_agent(hostname)
            rules_summary = self._get_agent_rules_summary(hostname)
            threat_level = self._calculate_agent_threat_level(hostname)
            
            if agent.get('Status') != 'Online':
                recommendations.append("Ensure agent connectivity and resolve connection issues")
            
            if rules_summary.get('active_rules', 0) < 5:
                recommendations.append("Assign more security rules to improve monitoring coverage")
            
            if threat_level in ['Critical', 'High']:
                recommendations.append("Investigate recent security alerts and take appropriate actions")
            
            if not agent.get('AgentVersion', '').startswith('2.'):
                recommendations.append("Update agent to the latest version for improved security")
            
            # Default recommendations
            if not recommendations:
                recommendations.extend([
                    "Maintain regular security rule updates",
                    "Monitor system activity for anomalies",
                    "Ensure endpoint protection is always enabled"
                ])
            
            return recommendations
            
        except Exception as e:
            self.logger.error(f"Error getting security recommendations: {e}")
            return ["Unable to generate recommendations"]
    
    def _get_compliance_recommendations(self, compliance_factors: Dict) -> List[str]:
        """Lấy khuyến nghị tuân thủ"""
        recommendations = []
        
        if not compliance_factors.get('agent_updated'):
            recommendations.append("Update agent to the latest version")
        
        if not compliance_factors.get('rules_active'):
            recommendations.append("Activate security monitoring rules")
        
        if not compliance_factors.get('monitoring_enabled'):
            recommendations.append("Enable continuous monitoring")
        
        if not compliance_factors.get('recent_activity'):
            recommendations.append("Verify agent connectivity and functionality")
        
        return recommendations if recommendations else ["System is compliant"]