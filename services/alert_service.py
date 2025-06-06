"""
Alert Service - Xử lý logic business cho alerts
"""

import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from database.alerts import AlertDB
from database.agents import AgentDB
from database.rules import RuleDB
from utils.helpers import (
    generate_unique_id, calculate_time_ago, safe_int,
    get_severity_color, get_severity_priority, filter_sensitive_data
)
from utils.logger import alert_logger, log_security_event

class AlertService:
    def __init__(self):
        self.alert_db = AlertDB()
        self.agent_db = AgentDB()
        self.rule_db = RuleDB()
        self.logger = logging.getLogger(__name__)
    
    def create_alert_from_violation(self, violation_data: Dict, hostname: str) -> Tuple[bool, Optional[str]]:
        """Tạo alert từ rule violation"""
        try:
            # Validate dữ liệu
            required_fields = ['rule_id', 'severity', 'description']
            for field in required_fields:
                if field not in violation_data:
                    return False, f"Missing required field: {field}"
            
            rule_id = violation_data['rule_id']
            
            # Lấy thông tin rule
            rule = self.rule_db.get_rule_by_id(rule_id)
            if not rule:
                return False, f"Rule {rule_id} not found"
            
            # Tạo alert data
            alert_data = {
                'hostname': hostname,
                'rule_id': rule_id,
                'alert_type': violation_data.get('alert_type', f"{rule.get('RuleType', 'Security')} Violation"),
                'severity': violation_data['severity'],
                'title': violation_data.get('title', f"Rule Violation: {rule.get('RuleName', 'Unknown')}"),
                'description': violation_data['description'],
                'detection_data': violation_data.get('detection_data', '{}'),
                'action': violation_data.get('action', 'Alert'),
                'status': 'New'
            }
            
            # Filter sensitive data
            alert_data = filter_sensitive_data(alert_data)
            
            # Tạo alert
            success = self.alert_db.create_alert(alert_data)
            
            if success:
                # Log security event
                log_security_event(
                    event_type='rule_violation_alert',
                    severity=violation_data['severity'],
                    description=f"Alert created for rule violation: {rule.get('RuleName')}",
                    hostname=hostname,
                    details={
                        'rule_id': rule_id,
                        'rule_name': rule.get('RuleName'),
                        'alert_type': alert_data['alert_type']
                    }
                )
                
                alert_logger.info('alert_created', f'Alert created for {hostname}',
                                hostname=hostname, rule_id=rule_id, severity=violation_data['severity'])
                
                return True, alert_data.get('title')
            else:
                return False, "Failed to create alert in database"
                
        except Exception as e:
            self.logger.error(f"Error creating alert from violation: {e}")
            return False, str(e)
    
    def get_alerts_dashboard_data(self, filters: Dict = None) -> Dict:
        """Lấy dữ liệu dashboard cho alerts"""
        try:
            # Default time range: last 24 hours
            if not filters:
                filters = {}
            
            if 'start_time' not in filters:
                filters['start_time'] = (datetime.now() - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
            
            # Lấy alerts
            alerts = self.alert_db.get_alerts(filters, 1000)
            
            # Tính thống kê
            dashboard_data = {
                'summary': self._calculate_alerts_summary(alerts),
                'trends': self._calculate_alerts_trends(alerts),
                'top_threats': self._get_top_threats(alerts),
                'affected_agents': self._get_affected_agents(alerts),
                'recent_alerts': alerts[:20],  # 20 alerts gần nhất
                'filters_applied': filters,
                'timestamp': datetime.now().isoformat()
            }
            
            return dashboard_data
            
        except Exception as e:
            self.logger.error(f"Error getting alerts dashboard data: {e}")
            return {'error': str(e)}
    
    def _calculate_alerts_summary(self, alerts: List[Dict]) -> Dict:
        """Tính tóm tắt alerts"""
        summary = {
            'total_alerts': len(alerts),
            'by_severity': {},
            'by_status': {},
            'by_type': {},
            'recent_count': 0,
            'critical_count': 0,
            'unresolved_count': 0
        }
        
        recent_threshold = datetime.now() - timedelta(hours=1)
        
        for alert in alerts:
            # By severity
            severity = alert.get('Severity', 'Unknown')
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            
            # By status
            status = alert.get('Status', 'Unknown')
            summary['by_status'][status] = summary['by_status'].get(status, 0) + 1
            
            # By type
            alert_type = alert.get('AlertType', 'Unknown')
            summary['by_type'][alert_type] = summary['by_type'].get(alert_type, 0) + 1
            
            # Counts for special categories
            if severity == 'Critical':
                summary['critical_count'] += 1
            
            if status in ['New', 'In Progress']:
                summary['unresolved_count'] += 1
            
            # Recent alerts (last hour)
            alert_time = alert.get('Time')
            if alert_time:
                try:
                    alert_dt = datetime.strptime(alert_time, '%Y-%m-%d %H:%M:%S')
                    if alert_dt >= recent_threshold:
                        summary['recent_count'] += 1
                except:
                    pass
        
        return summary
    
    def _calculate_alerts_trends(self, alerts: List[Dict]) -> Dict:
        """Tính xu hướng alerts"""
        trends = {
            'hourly_distribution': {},
            'severity_trend': {},
            'peak_hours': [],
            'trend_direction': 'stable'
        }
        
        try:
            # Phân bổ theo giờ
            hourly_counts = {}
            severity_hourly = {'Critical': {}, 'High': {}, 'Medium': {}, 'Low': {}}
            
            for alert in alerts:
                alert_time = alert.get('Time')
                if alert_time:
                    try:
                        alert_dt = datetime.strptime(alert_time, '%Y-%m-%d %H:%M:%S')
                        hour = alert_dt.strftime('%H:00')
                        
                        hourly_counts[hour] = hourly_counts.get(hour, 0) + 1
                        
                        severity = alert.get('Severity', 'Low')
                        if severity in severity_hourly:
                            severity_hourly[severity][hour] = severity_hourly[severity].get(hour, 0) + 1
                            
                    except:
                        continue
            
            trends['hourly_distribution'] = hourly_counts
            trends['severity_trend'] = severity_hourly
            
            # Tìm peak hours
            if hourly_counts:
                sorted_hours = sorted(hourly_counts.items(), key=lambda x: x[1], reverse=True)
                trends['peak_hours'] = [hour for hour, count in sorted_hours[:3]]
            
            # Tính trend direction (simplified)
            if len(alerts) > 10:
                recent_half = alerts[:len(alerts)//2]
                older_half = alerts[len(alerts)//2:]
                
                if len(recent_half) > len(older_half) * 1.2:
                    trends['trend_direction'] = 'increasing'
                elif len(recent_half) < len(older_half) * 0.8:
                    trends['trend_direction'] = 'decreasing'
            
        except Exception as e:
            self.logger.error(f"Error calculating alerts trends: {e}")
        
        return trends
    
    def _get_top_threats(self, alerts: List[Dict], limit: int = 10) -> List[Dict]:
        """Lấy top threats dựa trên alerts"""
        threat_counts = {}
        threat_details = {}
        
        for alert in alerts:
            # Group by rule or alert type
            threat_key = alert.get('RuleName') or alert.get('AlertType', 'Unknown Threat')
            
            if threat_key not in threat_counts:
                threat_counts[threat_key] = 0
                threat_details[threat_key] = {
                    'name': threat_key,
                    'severity': alert.get('Severity', 'Medium'),
                    'alert_type': alert.get('AlertType', 'Unknown'),
                    'rule_id': alert.get('RuleID'),
                    'affected_hosts': set(),
                    'latest_occurrence': alert.get('Time', '')
                }
            
            threat_counts[threat_key] += 1
            threat_details[threat_key]['affected_hosts'].add(alert.get('Hostname', 'Unknown'))
            
            # Update latest occurrence
            if alert.get('Time', '') > threat_details[threat_key]['latest_occurrence']:
                threat_details[threat_key]['latest_occurrence'] = alert.get('Time', '')
        
        # Sort by count and format
        top_threats = []
        sorted_threats = sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)
        
        for threat_name, count in sorted_threats[:limit]:
            details = threat_details[threat_name]
            top_threats.append({
                'name': threat_name,
                'count': count,
                'severity': details['severity'],
                'alert_type': details['alert_type'],
                'affected_hosts_count': len(details['affected_hosts']),
                'latest_occurrence': details['latest_occurrence'],
                'latest_occurrence_ago': calculate_time_ago(details['latest_occurrence']),
                'color': get_severity_color(details['severity'])
            })
        
        return top_threats
    
    def _get_affected_agents(self, alerts: List[Dict]) -> Dict:
        """Lấy thông tin agents bị ảnh hưởng"""
        agent_stats = {}
        
        for alert in alerts:
            hostname = alert.get('Hostname', 'Unknown')
            severity = alert.get('Severity', 'Low')
            
            if hostname not in agent_stats:
                agent_stats[hostname] = {
                    'hostname': hostname,
                    'alert_count': 0,
                    'severities': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0},
                    'latest_alert': '',
                    'highest_severity': 'Low'
                }
            
            agent_stats[hostname]['alert_count'] += 1
            agent_stats[hostname]['severities'][severity] += 1
            
            # Update latest alert
            alert_time = alert.get('Time', '')
            if alert_time > agent_stats[hostname]['latest_alert']:
                agent_stats[hostname]['latest_alert'] = alert_time
            
            # Update highest severity
            if get_severity_priority(severity) > get_severity_priority(agent_stats[hostname]['highest_severity']):
                agent_stats[hostname]['highest_severity'] = severity
        
        # Sort by alert count
        sorted_agents = sorted(agent_stats.values(), key=lambda x: x['alert_count'], reverse=True)
        
        # Add additional info
        for agent in sorted_agents:
            agent['latest_alert_ago'] = calculate_time_ago(agent['latest_alert'])
            agent['risk_level'] = self._calculate_agent_risk_level(agent)
        
        return {
            'total_affected': len(agent_stats),
            'agents': sorted_agents[:20]  # Top 20 most affected
        }
    
    def _calculate_agent_risk_level(self, agent_stats: Dict) -> str:
        """Tính risk level cho agent dựa trên alert stats"""
        critical_count = agent_stats['severities']['Critical']
        high_count = agent_stats['severities']['High']
        total_count = agent_stats['alert_count']
        
        if critical_count >= 3 or total_count >= 20:
            return 'Critical'
        elif critical_count >= 1 or high_count >= 5 or total_count >= 10:
            return 'High'
        elif high_count >= 1 or total_count >= 5:
            return 'Medium'
        else:
            return 'Low'
    
    def process_bulk_alert_actions(self, alert_ids: List[int], action: str, parameters: Dict = None) -> Dict:
        """Xử lý hàng loạt actions cho alerts"""
        try:
            if not parameters:
                parameters = {}
            
            results = {
                'success': [],
                'failed': [],
                'total': len(alert_ids),
                'action': action
            }
            
            for alert_id in alert_ids:
                try:
                    success = False
                    
                    if action == 'update_status':
                        new_status = parameters.get('status', 'Resolved')
                        success = self.alert_db.update_alert_status(alert_id, new_status)
                    
                    elif action == 'mark_resolved':
                        success = self.alert_db.update_alert_status(alert_id, 'Resolved')
                    
                    elif action == 'mark_false_positive':
                        success = self.alert_db.update_alert_status(alert_id, 'False Positive')
                    
                    elif action == 'assign_priority':
                        # Custom action để assign priority
                        priority = parameters.get('priority', 'Medium')
                        # Implement priority assignment logic
                        success = True  # Placeholder
                    
                    else:
                        results['failed'].append({
                            'alert_id': alert_id,
                            'error': f'Unknown action: {action}'
                        })
                        continue
                    
                    if success:
                        results['success'].append(alert_id)
                        
                        # Log action
                        alert_logger.info('bulk_action_success', 
                                        f'Bulk action {action} applied to alert {alert_id}',
                                        alert_id=alert_id, action=action)
                    else:
                        results['failed'].append({
                            'alert_id': alert_id,
                            'error': 'Action failed'
                        })
                        
                except Exception as e:
                    results['failed'].append({
                        'alert_id': alert_id,
                        'error': str(e)
                    })
            
            # Log bulk action summary
            alert_logger.info('bulk_action_completed', 
                            f'Bulk action {action}: {len(results["success"])}/{len(alert_ids)} successful',
                            action=action, total=len(alert_ids), 
                            success_count=len(results['success']))
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error processing bulk alert actions: {e}")
            return {'error': str(e)}
    
    def create_alert_investigation(self, alert_id: int, investigator: str) -> Dict:
        """Tạo investigation cho alert"""
        try:
            # Lấy thông tin alert
            alert = self.alert_db.get_alert_by_id(alert_id)
            if not alert:
                return {'error': 'Alert not found'}
            
            # Tạo investigation data
            investigation = {
                'investigation_id': generate_unique_id(),
                'alert_id': alert_id,
                'investigator': investigator,
                'status': 'In Progress',
                'created_at': datetime.now().isoformat(),
                'findings': [],
                'timeline': [],
                'related_alerts': [],
                'recommendations': []
            }
            
            # Cập nhật alert status
            self.alert_db.update_alert_status(alert_id, 'In Progress')
            
            # Tìm related alerts
            investigation['related_alerts'] = self._find_related_alerts(alert)
            
            # Tạo initial findings
            investigation['findings'] = self._generate_initial_findings(alert)
            
            # Log investigation
            alert_logger.info('investigation_created', 
                            f'Investigation created for alert {alert_id}',
                            alert_id=alert_id, investigator=investigator,
                            investigation_id=investigation['investigation_id'])
            
            return {'success': True, 'investigation': investigation}
            
        except Exception as e:
            self.logger.error(f"Error creating alert investigation: {e}")
            return {'error': str(e)}
    
    def _find_related_alerts(self, alert: Dict, time_window_hours: int = 24) -> List[Dict]:
        """Tìm alerts liên quan"""
        try:
            hostname = alert.get('Hostname')
            alert_time = alert.get('Time')
            rule_id = alert.get('RuleID')
            
            if not hostname or not alert_time:
                return []
            
            # Tính time window
            alert_dt = datetime.strptime(alert_time, '%Y-%m-%d %H:%M:%S')
            start_time = (alert_dt - timedelta(hours=time_window_hours)).strftime('%Y-%m-%d %H:%M:%S')
            end_time = (alert_dt + timedelta(hours=time_window_hours)).strftime('%Y-%m-%d %H:%M:%S')
            
            # Tìm alerts cùng hostname trong time window
            related_filters = {
                'hostname': hostname,
                'start_time': start_time,
                'end_time': end_time
            }
            
            related_alerts = self.alert_db.get_alerts(related_filters, 50)
            
            # Filter out current alert và score relevance
            scored_alerts = []
            current_alert_id = alert.get('AlertID')
            
            for related_alert in related_alerts:
                if related_alert.get('AlertID') == current_alert_id:
                    continue
                
                relevance_score = self._calculate_alert_relevance(alert, related_alert)
                
                if relevance_score > 0:
                    scored_alerts.append({
                        **related_alert,
                        'relevance_score': relevance_score,
                        'relevance_reason': self._get_relevance_reason(alert, related_alert)
                    })
            
            # Sort by relevance score
            scored_alerts.sort(key=lambda x: x['relevance_score'], reverse=True)
            
            return scored_alerts[:10]  # Top 10 most relevant
            
        except Exception as e:
            self.logger.error(f"Error finding related alerts: {e}")
            return []
    
    def _calculate_alert_relevance(self, base_alert: Dict, compare_alert: Dict) -> float:
        """Tính điểm liên quan giữa 2 alerts"""
        score = 0.0
        
        # Same rule
        if base_alert.get('RuleID') == compare_alert.get('RuleID'):
            score += 0.5
        
        # Same alert type
        if base_alert.get('AlertType') == compare_alert.get('AlertType'):
            score += 0.3
        
        # Same severity
        if base_alert.get('Severity') == compare_alert.get('Severity'):
            score += 0.2
        
        # Time proximity (closer = higher score)
        try:
            base_time = datetime.strptime(base_alert.get('Time', ''), '%Y-%m-%d %H:%M:%S')
            compare_time = datetime.strptime(compare_alert.get('Time', ''), '%Y-%m-%d %H:%M:%S')
            
            time_diff_hours = abs((base_time - compare_time).total_seconds()) / 3600
            
            if time_diff_hours <= 1:
                score += 0.4
            elif time_diff_hours <= 6:
                score += 0.2
            elif time_diff_hours <= 24:
                score += 0.1
                
        except:
            pass
        
        return score
    
    def _get_relevance_reason(self, base_alert: Dict, compare_alert: Dict) -> str:
        """Lấy lý do liên quan giữa 2 alerts"""
        reasons = []
        
        if base_alert.get('RuleID') == compare_alert.get('RuleID'):
            reasons.append("Same security rule triggered")
        
        if base_alert.get('AlertType') == compare_alert.get('AlertType'):
            reasons.append("Same type of security event")
        
        if base_alert.get('Severity') == compare_alert.get('Severity'):
            reasons.append("Same severity level")
        
        try:
            base_time = datetime.strptime(base_alert.get('Time', ''), '%Y-%m-%d %H:%M:%S')
            compare_time = datetime.strptime(compare_alert.get('Time', ''), '%Y-%m-%d %H:%M:%S')
            
            time_diff_hours = abs((base_time - compare_time).total_seconds()) / 3600
            
            if time_diff_hours <= 1:
                reasons.append("Occurred within 1 hour")
            elif time_diff_hours <= 6:
                reasons.append("Occurred within 6 hours")
                
        except:
            pass
        
        return "; ".join(reasons) if reasons else "Temporal proximity"
    
    def _generate_initial_findings(self, alert: Dict) -> List[Dict]:
        """Tạo initial findings cho investigation"""
        findings = []
        
        # Analyze detection data
        detection_data_str = alert.get('DetectionData', '{}')
        try:
            detection_data = json.loads(detection_data_str) if isinstance(detection_data_str, str) else detection_data_str
            
            # Process-based findings
            if 'ProcessName' in detection_data:
                findings.append({
                    'type': 'process_analysis',
                    'finding': f"Suspicious process detected: {detection_data['ProcessName']}",
                    'confidence': 'Medium',
                    'details': {
                        'process': detection_data.get('ProcessName'),
                        'command_line': detection_data.get('CommandLine'),
                        'executable_path': detection_data.get('ExecutablePath')
                    }
                })
            
            # File-based findings
            if 'FileName' in detection_data:
                findings.append({
                    'type': 'file_analysis',
                    'finding': f"Suspicious file activity: {detection_data['FileName']}",
                    'confidence': 'Medium',
                    'details': {
                        'file_name': detection_data.get('FileName'),
                        'file_path': detection_data.get('FilePath'),
                        'event_type': detection_data.get('EventType')
                    }
                })
            
            # Network-based findings
            if 'RemoteAddress' in detection_data:
                findings.append({
                    'type': 'network_analysis',
                    'finding': f"Suspicious network connection to {detection_data['RemoteAddress']}",
                    'confidence': 'Medium',
                    'details': {
                        'remote_address': detection_data.get('RemoteAddress'),
                        'remote_port': detection_data.get('RemotePort'),
                        'protocol': detection_data.get('Protocol')
                    }
                })
                
        except Exception as e:
            self.logger.error(f"Error parsing detection data: {e}")
        
        # Add general findings
        findings.append({
            'type': 'alert_metadata',
            'finding': f"Security rule '{alert.get('RuleName', 'Unknown')}' was triggered",
            'confidence': 'High',
            'details': {
                'rule_id': alert.get('RuleID'),
                'alert_type': alert.get('AlertType'),
                'severity': alert.get('Severity')
            }
        })
        
        return findings
    
    def get_alert_statistics_by_period(self, period: str = 'daily', days: int = 7) -> Dict:
        """Lấy thống kê alerts theo period"""
        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(days=days)
            
            filters = {
                'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S'),
                'end_time': end_time.strftime('%Y-%m-%d %H:%M:%S')
            }
            
            alerts = self.alert_db.get_alerts(filters, 10000)
            
            # Group by period
            if period == 'hourly':
                time_format = '%Y-%m-%d %H:00'
                period_delta = timedelta(hours=1)
            elif period == 'daily':
                time_format = '%Y-%m-%d'
                period_delta = timedelta(days=1)
            elif period == 'weekly':
                time_format = '%Y-W%U'  # Year-Week
                period_delta = timedelta(weeks=1)
            else:
                return {'error': 'Invalid period. Use hourly, daily, or weekly'}
            
            # Initialize periods
            periods = {}
            current_time = start_time
            while current_time <= end_time:
                period_key = current_time.strftime(time_format)
                periods[period_key] = {
                    'total': 0,
                    'by_severity': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0},
                    'by_status': {'New': 0, 'In Progress': 0, 'Resolved': 0, 'False Positive': 0}
                }
                current_time += period_delta
            
            # Fill periods with data
            for alert in alerts:
                alert_time = alert.get('Time')
                if alert_time:
                    try:
                        alert_dt = datetime.strptime(alert_time, '%Y-%m-%d %H:%M:%S')
                        period_key = alert_dt.strftime(time_format)
                        
                        if period_key in periods:
                            periods[period_key]['total'] += 1
                            
                            severity = alert.get('Severity', 'Medium')
                            status = alert.get('Status', 'New')
                            
                            if severity in periods[period_key]['by_severity']:
                                periods[period_key]['by_severity'][severity] += 1
                            
                            if status in periods[period_key]['by_status']:
                                periods[period_key]['by_status'][status] += 1
                                
                    except:
                        continue
            
            # Calculate trends
            total_counts = [periods[p]['total'] for p in sorted(periods.keys())]
            trend = 'stable'
            
            if len(total_counts) >= 2:
                if total_counts[-1] > total_counts[-2] * 1.2:
                    trend = 'increasing'
                elif total_counts[-1] < total_counts[-2] * 0.8:
                    trend = 'decreasing'
            
            return {
                'period': period,
                'days': days,
                'periods': periods,
                'trend': trend,
                'total_alerts': len(alerts),
                'summary': self._calculate_alerts_summary(alerts)
            }
            
        except Exception as e:
            self.logger.error(f"Error getting alert statistics by period: {e}")
            return {'error': str(e)}
    
    def generate_alert_report(self, report_type: str = 'summary', filters: Dict = None) -> Dict:
        """Tạo báo cáo alerts"""
        try:
            if not filters:
                filters = {
                    'start_time': (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')
                }
            
            alerts = self.alert_db.get_alerts(filters, 10000)
            
            report = {
                'report_type': report_type,
                'generated_at': datetime.now().isoformat(),
                'period': filters,
                'total_alerts': len(alerts)
            }
            
            if report_type == 'summary':
                report['summary'] = {
                    'overview': self._calculate_alerts_summary(alerts),
                    'trends': self._calculate_alerts_trends(alerts),
                    'top_threats': self._get_top_threats(alerts, 5),
                    'affected_agents': self._get_affected_agents(alerts)
                }
                
            elif report_type == 'detailed':
                report['detailed'] = {
                    'overview': self._calculate_alerts_summary(alerts),
                    'trends': self._calculate_alerts_trends(alerts),
                    'top_threats': self._get_top_threats(alerts, 20),
                    'affected_agents': self._get_affected_agents(alerts),
                    'by_rule': self._get_alerts_by_rule(alerts),
                    'timeline': self._create_alerts_timeline(alerts),
                    'statistics': self.get_alert_statistics_by_period('daily', 7)
                }
                
            elif report_type == 'executive':
                report['executive'] = {
                    'key_metrics': self._get_executive_metrics(alerts),
                    'risk_assessment': self._assess_security_risk(alerts),
                    'recommendations': self._get_executive_recommendations(alerts),
                    'trend_analysis': self._get_trend_analysis(alerts)
                }
            
            return report
            
        except Exception as e:
            self.logger.error(f"Error generating alert report: {e}")
            return {'error': str(e)}
    
    def _get_alerts_by_rule(self, alerts: List[Dict]) -> Dict:
        """Phân tích alerts theo rule"""
        by_rule = {}
        
        for alert in alerts:
            rule_name = alert.get('RuleName', 'Unknown Rule')
            rule_id = alert.get('RuleID')
            
            if rule_name not in by_rule:
                by_rule[rule_name] = {
                    'rule_id': rule_id,
                    'rule_name': rule_name,
                    'count': 0,
                    'severities': {},
                    'affected_hosts': set(),
                    'latest_occurrence': ''
                }
            
            by_rule[rule_name]['count'] += 1
            
            severity = alert.get('Severity', 'Medium')
            by_rule[rule_name]['severities'][severity] = by_rule[rule_name]['severities'].get(severity, 0) + 1
            
            by_rule[rule_name]['affected_hosts'].add(alert.get('Hostname', 'Unknown'))
            
            alert_time = alert.get('Time', '')
            if alert_time > by_rule[rule_name]['latest_occurrence']:
                by_rule[rule_name]['latest_occurrence'] = alert_time
        
        # Convert sets to counts và sort
        rule_stats = []
        for rule_name, stats in by_rule.items():
            stats['affected_hosts_count'] = len(stats['affected_hosts'])
            del stats['affected_hosts']  # Remove set for JSON serialization
            rule_stats.append(stats)
        
        rule_stats.sort(key=lambda x: x['count'], reverse=True)
        
        return {'rules': rule_stats}
    
    def _create_alerts_timeline(self, alerts: List[Dict], limit: int = 50) -> List[Dict]:
        """Tạo timeline của alerts"""
        timeline = []
        
        for alert in alerts[:limit]:  # Limit for performance
            timeline.append({
                'time': alert.get('Time'),
                'alert_id': alert.get('AlertID'),
                'title': alert.get('Title', 'Security Alert'),
                'severity': alert.get('Severity'),
                'hostname': alert.get('Hostname'),
                'alert_type': alert.get('AlertType'),
                'status': alert.get('Status'),
                'description': alert.get('Description', '')[:100] + '...'
            })
        
        return sorted(timeline, key=lambda x: x.get('time', ''), reverse=True)
    
    def _get_executive_metrics(self, alerts: List[Dict]) -> Dict:
        """Lấy metrics cho executive report"""
        total_alerts = len(alerts)
        critical_alerts = len([a for a in alerts if a.get('Severity') == 'Critical'])
        resolved_alerts = len([a for a in alerts if a.get('Status') == 'Resolved'])
        
        resolution_rate = (resolved_alerts / total_alerts * 100) if total_alerts > 0 else 0
        
        unique_hosts = len(set(a.get('Hostname') for a in alerts if a.get('Hostname')))
        
        return {
            'total_security_incidents': total_alerts,
            'critical_incidents': critical_alerts,
            'incident_resolution_rate': round(resolution_rate, 1),
            'affected_systems': unique_hosts,
            'average_severity_score': self._calculate_average_severity_score(alerts),
            'threat_exposure_index': self._calculate_threat_exposure_index(alerts)
        }
    
    def _assess_security_risk(self, alerts: List[Dict]) -> Dict:
        """Đánh giá rủi ro bảo mật"""
        critical_count = len([a for a in alerts if a.get('Severity') == 'Critical'])
        high_count = len([a for a in alerts if a.get('Severity') == 'High'])
        total_count = len(alerts)
        
        # Calculate risk score
        risk_score = (critical_count * 10 + high_count * 5) / max(total_count, 1)
        
        if risk_score >= 8:
            risk_level = 'Critical'
        elif risk_score >= 5:
            risk_level = 'High'
        elif risk_score >= 2:
            risk_level = 'Medium'
        else:
            risk_level = 'Low'
        
        return {
            'overall_risk_level': risk_level,
            'risk_score': round(risk_score, 2),
            'risk_factors': [
                f'{critical_count} critical security incidents',
                f'{high_count} high-severity incidents',
                f'{len(set(a.get("Hostname") for a in alerts))} systems affected'
            ]
        }
    
    def _get_executive_recommendations(self, alerts: List[Dict]) -> List[str]:
        """Lấy khuyến nghị cho executive"""
        recommendations = []
        
        critical_count = len([a for a in alerts if a.get('Severity') == 'Critical'])
        unresolved_count = len([a for a in alerts if a.get('Status') in ['New', 'In Progress']])
        
        if critical_count > 10:
            recommendations.append("Immediate review of critical security incidents required")
        
        if unresolved_count > len(alerts) * 0.5:
            recommendations.append("Increase incident response capacity to address backlog")
        
        # Analyze top threats
        top_threats = self._get_top_threats(alerts, 3)
        if top_threats:
            recommendations.append(f"Focus security efforts on top threat: {top_threats[0]['name']}")
        
        if not recommendations:
            recommendations.append("Continue monitoring and maintain current security posture")
        
        return recommendations
    
    def _get_trend_analysis(self, alerts: List[Dict]) -> Dict:
        """Phân tích xu hướng cho executive"""
        # Group alerts by day
        daily_counts = {}
        for alert in alerts:
            alert_time = alert.get('Time')
            if alert_time:
                try:
                    day = datetime.strptime(alert_time, '%Y-%m-%d %H:%M:%S').strftime('%Y-%m-%d')
                    daily_counts[day] = daily_counts.get(day, 0) + 1
                except:
                    continue
        
        if len(daily_counts) < 2:
            return {'trend': 'insufficient_data', 'change_percentage': 0}
        
        sorted_days = sorted(daily_counts.keys())
        if len(sorted_days) >= 2:
            recent_avg = sum(daily_counts[day] for day in sorted_days[-3:]) / min(3, len(sorted_days))
            older_avg = sum(daily_counts[day] for day in sorted_days[:-3]) / max(1, len(sorted_days) - 3)
            
            change_percentage = ((recent_avg - older_avg) / max(older_avg, 1)) * 100
            
            if change_percentage > 20:
                trend = 'increasing'
            elif change_percentage < -20:
                trend = 'decreasing'
            else:
                trend = 'stable'
        else:
            trend = 'stable'
            change_percentage = 0
        
        return {
            'trend': trend,
            'change_percentage': round(change_percentage, 1),
            'daily_average': round(sum(daily_counts.values()) / len(daily_counts), 1)
        }
    
    def _calculate_average_severity_score(self, alerts: List[Dict]) -> float:
        """Tính điểm severity trung bình"""
        if not alerts:
            return 0
        
        severity_scores = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
        total_score = sum(severity_scores.get(alert.get('Severity', 'Low'), 1) for alert in alerts)
        
        return round(total_score / len(alerts), 2)
    
    def _calculate_threat_exposure_index(self, alerts: List[Dict]) -> float:
        """Tính chỉ số phơi nhiễm threat"""
        if not alerts:
            return 0
        
        # Simplified calculation based on alert count, severity, and affected systems
        total_alerts = len(alerts)
        unique_systems = len(set(a.get('Hostname') for a in alerts if a.get('Hostname')))
        critical_alerts = len([a for a in alerts if a.get('Severity') == 'Critical'])
        
        # Normalize to 0-100 scale
        exposure_index = min(100, (total_alerts * 2 + critical_alerts * 10 + unique_systems * 5) / 10)
        
        return round(exposure_index, 1)