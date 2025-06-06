"""
Alert Database Operations
Xử lý tất cả operations liên quan đến alerts trong database
"""

import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from .connection import DatabaseConnection
from utils.helpers import sanitize_string, generate_unique_id

class AlertDB:
    def __init__(self):
        self.db = DatabaseConnection()
        self.db.connect()
        self.logger = logging.getLogger(__name__)
    
    def create_alert(self, alert_data: Dict) -> bool:
        """Tạo alert mới"""
        try:
            # Validate dữ liệu bắt buộc
            required_fields = ['hostname', 'rule_id', 'severity', 'description']
            for field in required_fields:
                if field not in alert_data:
                    self.logger.error(f"Missing required field: {field}")
                    return False
            
            # Chuẩn bị dữ liệu
            normalized_data = self._normalize_alert_data(alert_data)
            
            # Insert vào database
            success = self.db.insert_data('Alerts', normalized_data)
            
            if success:
                self.logger.info(f"Alert created for {alert_data['hostname']}: {alert_data.get('title', 'No title')}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error creating alert: {e}")
            return False
    
    def _normalize_alert_data(self, alert_data: Dict) -> Dict:
        """Normalize dữ liệu alert"""
        normalized = {
            'Time': datetime.now(),
            'Hostname': sanitize_string(alert_data['hostname']),
            'RuleID': alert_data['rule_id'],
            'AlertType': sanitize_string(alert_data.get('alert_type', 'Security Alert')),
            'Severity': sanitize_string(alert_data['severity']),
            'Status': sanitize_string(alert_data.get('status', 'New')),
            'Title': sanitize_string(alert_data.get('title', 'Security Alert')),
            'Description': sanitize_string(alert_data['description']),
            'Action': sanitize_string(alert_data.get('action', 'Alert'))
        }
        
        # Detection data (JSON)
        detection_data = alert_data.get('detection_data', {})
        if isinstance(detection_data, dict):
            normalized['DetectionData'] = json.dumps(detection_data)
        else:
            normalized['DetectionData'] = str(detection_data)
        
        return normalized
    
    def get_alert_by_id(self, alert_id: int) -> Optional[Dict]:
        """Lấy alert theo ID"""
        try:
            query = "SELECT * FROM Alerts WHERE AlertID = ?"
            alert = self.db.fetch_one(query, [alert_id])
            
            if alert:
                # Parse JSON fields
                alert = self._parse_alert_json_fields(alert)
            
            return alert
            
        except Exception as e:
            self.logger.error(f"Error getting alert {alert_id}: {e}")
            return None
    
    def get_alerts(self, filters: Dict = None, limit: int = 100) -> List[Dict]:
        """Lấy alerts với filters"""
        try:
            query = "SELECT TOP (?) * FROM Alerts"
            params = [limit]
            where_conditions = []
            
            if filters:
                if 'hostname' in filters:
                    where_conditions.append("Hostname = ?")
                    params.append(filters['hostname'])
                
                if 'severity' in filters:
                    where_conditions.append("Severity = ?")
                    params.append(filters['severity'])
                
                if 'status' in filters:
                    where_conditions.append("Status = ?")
                    params.append(filters['status'])
                
                if 'alert_type' in filters:
                    where_conditions.append("AlertType = ?")
                    params.append(filters['alert_type'])
                
                if 'rule_id' in filters:
                    where_conditions.append("RuleID = ?")
                    params.append(filters['rule_id'])
                
                if 'start_time' in filters:
                    where_conditions.append("Time >= ?")
                    params.append(filters['start_time'])
                
                if 'end_time' in filters:
                    where_conditions.append("Time <= ?")
                    params.append(filters['end_time'])
            
            if where_conditions:
                query += " WHERE " + " AND ".join(where_conditions)
            
            query += " ORDER BY Time DESC"
            
            alerts = self.db.fetch_all(query, params)
            
            # Parse JSON fields for all alerts
            return [self._parse_alert_json_fields(alert) for alert in alerts]
            
        except Exception as e:
            self.logger.error(f"Error getting alerts: {e}")
            return []
    
    def _parse_alert_json_fields(self, alert: Dict) -> Dict:
        """Parse JSON fields trong alert"""
        try:
            if 'DetectionData' in alert and alert['DetectionData']:
                try:
                    alert['DetectionData'] = json.loads(alert['DetectionData'])
                except (json.JSONDecodeError, TypeError):
                    # Keep as string if not valid JSON
                    pass
            
            # Convert datetime to string for JSON serialization
            if 'Time' in alert and hasattr(alert['Time'], 'strftime'):
                alert['Time'] = alert['Time'].strftime('%Y-%m-%d %H:%M:%S')
            
            return alert
            
        except Exception as e:
            self.logger.error(f"Error parsing alert JSON fields: {e}")
            return alert
    
    def update_alert_status(self, alert_id: int, status: str) -> bool:
        """Cập nhật trạng thái alert"""
        try:
            update_data = {
                'Status': sanitize_string(status)
            }
            
            # Nếu resolve thì set thời gian
            if status.lower() in ['resolved', 'closed']:
                update_data['ResolvedAt'] = datetime.now()
            
            return self.db.update_data(
                'Alerts',
                update_data,
                'AlertID = ?',
                [alert_id]
            )
            
        except Exception as e:
            self.logger.error(f"Error updating alert status {alert_id}: {e}")
            return False
    
    def get_recent_alerts(self, hostname: str = None, hours: int = 24, limit: int = 50) -> List[Dict]:
        """Lấy alerts gần đây"""
        try:
            start_time = datetime.now() - timedelta(hours=hours)
            
            filters = {
                'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S')
            }
            
            if hostname:
                filters['hostname'] = hostname
            
            return self.get_alerts(filters, limit)
            
        except Exception as e:
            self.logger.error(f"Error getting recent alerts: {e}")
            return []
    
    def get_alerts_by_severity(self, severity: str, limit: int = 100) -> List[Dict]:
        """Lấy alerts theo severity"""
        try:
            filters = {'severity': severity}
            return self.get_alerts(filters, limit)
            
        except Exception as e:
            self.logger.error(f"Error getting alerts by severity {severity}: {e}")
            return []
    
    def get_unresolved_alerts(self, limit: int = 100) -> List[Dict]:
        """Lấy alerts chưa resolve"""
        try:
            query = """
                SELECT TOP (?) * FROM Alerts 
                WHERE Status IN ('New', 'In Progress', 'Open')
                ORDER BY Time DESC, Severity DESC
            """
            
            alerts = self.db.fetch_all(query, [limit])
            return [self._parse_alert_json_fields(alert) for alert in alerts]
            
        except Exception as e:
            self.logger.error(f"Error getting unresolved alerts: {e}")
            return []
    
    def get_alerts_statistics(self, hours: int = 24) -> Dict:
        """Lấy thống kê alerts"""
        try:
            start_time = datetime.now() - timedelta(hours=hours)
            
            stats = {
                'total_alerts': 0,
                'by_severity': {},
                'by_status': {},
                'by_type': {},
                'recent_count': 0,
                'resolved_count': 0,
                'avg_resolution_time': 0
            }
            
            # Total alerts in time range
            total_result = self.db.fetch_one(
                "SELECT COUNT(*) as total FROM Alerts WHERE Time >= ?",
                [start_time]
            )
            if total_result:
                stats['total_alerts'] = total_result['total']
            
            # By severity
            severity_stats = self.db.fetch_all(
                "SELECT Severity, COUNT(*) as count FROM Alerts WHERE Time >= ? GROUP BY Severity",
                [start_time]
            )
            for row in severity_stats:
                stats['by_severity'][row['Severity']] = row['count']
            
            # By status
            status_stats = self.db.fetch_all(
                "SELECT Status, COUNT(*) as count FROM Alerts WHERE Time >= ? GROUP BY Status",
                [start_time]
            )
            for row in status_stats:
                stats['by_status'][row['Status']] = row['count']
            
            # By type
            type_stats = self.db.fetch_all(
                "SELECT AlertType, COUNT(*) as count FROM Alerts WHERE Time >= ? GROUP BY AlertType",
                [start_time]
            )
            for row in type_stats:
                stats['by_type'][row['AlertType']] = row['count']
            
            # Recent count (last hour)
            recent_threshold = datetime.now() - timedelta(hours=1)
            recent_result = self.db.fetch_one(
                "SELECT COUNT(*) as recent FROM Alerts WHERE Time >= ?",
                [recent_threshold]
            )
            if recent_result:
                stats['recent_count'] = recent_result['recent']
            
            # Resolved count
            resolved_result = self.db.fetch_one(
                "SELECT COUNT(*) as resolved FROM Alerts WHERE Time >= ? AND Status = 'Resolved'",
                [start_time]
            )
            if resolved_result:
                stats['resolved_count'] = resolved_result['resolved']
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error getting alerts statistics: {e}")
            return {}
    
    def search_alerts(self, search_term: str, limit: int = 100) -> List[Dict]:
        """Tìm kiếm alerts"""
        try:
            search_pattern = f"%{search_term}%"
            
            query = """
                SELECT TOP (?) * FROM Alerts 
                WHERE 
                    Title LIKE ? OR 
                    Description LIKE ? OR 
                    Hostname LIKE ? OR
                    AlertType LIKE ?
                ORDER BY Time DESC
            """
            
            alerts = self.db.fetch_all(query, [limit, search_pattern, search_pattern, search_pattern, search_pattern])
            return [self._parse_alert_json_fields(alert) for alert in alerts]
            
        except Exception as e:
            self.logger.error(f"Error searching alerts: {e}")
            return []
    
    def bulk_update_alert_status(self, alert_ids: List[int], status: str) -> Dict:
        """Bulk update status cho nhiều alerts"""
        try:
            success_count = 0
            failed_count = 0
            
            with self.db.transaction():
                for alert_id in alert_ids:
                    if self.update_alert_status(alert_id, status):
                        success_count += 1
                    else:
                        failed_count += 1
            
            self.logger.info(f"Bulk update alerts: {success_count} success, {failed_count} failed")
            
            return {
                'success_count': success_count,
                'failed_count': failed_count,
                'total': len(alert_ids)
            }
            
        except Exception as e:
            self.logger.error(f"Error in bulk update alerts: {e}")
            return {'success_count': 0, 'failed_count': len(alert_ids), 'total': len(alert_ids)}
    
    def delete_alert(self, alert_id: int) -> bool:
        """Xóa alert"""
        try:
            return self.db.delete_data('Alerts', 'AlertID = ?', [alert_id])
            
        except Exception as e:
            self.logger.error(f"Error deleting alert {alert_id}: {e}")
            return False
    
    def cleanup_old_alerts(self, days: int = 30) -> int:
        """Dọn dẹp alerts cũ"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days)
            
            # Chỉ xóa alerts đã resolved
            query = "DELETE FROM Alerts WHERE Time < ? AND Status = 'Resolved'"
            
            cursor = self.db.execute_query(query, [cutoff_date])
            if cursor:
                deleted_count = cursor.rowcount
                cursor.close()
                
                self.logger.info(f"Cleaned up {deleted_count} old alerts")
                return deleted_count
            
            return 0
            
        except Exception as e:
            self.logger.error(f"Error cleaning up old alerts: {e}")
            return 0
    
    def get_top_alert_types(self, hours: int = 24, limit: int = 10) -> List[Dict]:
        """Lấy top alert types"""
        try:
            start_time = datetime.now() - timedelta(hours=hours)
            
            query = """
                SELECT TOP (?) AlertType, COUNT(*) as Count,
                       MAX(Time) as LatestTime
                FROM Alerts 
                WHERE Time >= ?
                GROUP BY AlertType
                ORDER BY Count DESC
            """
            
            return self.db.fetch_all(query, [limit, start_time])
            
        except Exception as e:
            self.logger.error(f"Error getting top alert types: {e}")
            return []
    
    def get_alerts_by_rule(self, rule_id: int, limit: int = 100) -> List[Dict]:
        """Lấy alerts theo rule ID"""
        try:
            filters = {'rule_id': rule_id}
            return self.get_alerts(filters, limit)
            
        except Exception as e:
            self.logger.error(f"Error getting alerts by rule {rule_id}: {e}")
            return []
    
    def get_alert_timeline(self, hours: int = 24) -> List[Dict]:
        """Lấy timeline alerts"""
        try:
            start_time = datetime.now() - timedelta(hours=hours)
            
            query = """
                SELECT 
                    DATEPART(hour, Time) as Hour,
                    COUNT(*) as AlertCount,
                    COUNT(CASE WHEN Severity = 'Critical' THEN 1 END) as CriticalCount,
                    COUNT(CASE WHEN Severity = 'High' THEN 1 END) as HighCount
                FROM Alerts 
                WHERE Time >= ?
                GROUP BY DATEPART(hour, Time)
                ORDER BY Hour
            """
            
            return self.db.fetch_all(query, [start_time])
            
        except Exception as e:
            self.logger.error(f"Error getting alert timeline: {e}")
            return []
    
    def get_alerts_by_agent(self, hostname: str, limit: int = 100) -> List[Dict]:
        """Lấy tất cả alerts của một agent"""
        try:
            filters = {'hostname': hostname}
            return self.get_alerts(filters, limit)
            
        except Exception as e:
            self.logger.error(f"Error getting alerts for agent {hostname}: {e}")
            return []
    
    def create_bulk_alerts(self, alerts_data: List[Dict]) -> Dict:
        """Tạo nhiều alerts cùng lúc"""
        try:
            success_count = 0
            failed_count = 0
            errors = []
            
            with self.db.transaction():
                for alert_data in alerts_data:
                    try:
                        if self.create_alert(alert_data):
                            success_count += 1
                        else:
                            failed_count += 1
                            errors.append(f"Failed to create alert for {alert_data.get('hostname', 'unknown')}")
                    except Exception as e:
                        failed_count += 1
                        errors.append(f"Error creating alert: {str(e)}")
            
            return {
                'success_count': success_count,
                'failed_count': failed_count,
                'total': len(alerts_data),
                'errors': errors
            }
            
        except Exception as e:
            self.logger.error(f"Error in bulk create alerts: {e}")
            return {
                'success_count': 0,
                'failed_count': len(alerts_data),
                'total': len(alerts_data),
                'errors': [str(e)]
            }
    
    def get_alert_correlation(self, alert_id: int, time_window_minutes: int = 60) -> List[Dict]:
        """Tìm alerts liên quan trong time window"""
        try:
            # Lấy alert gốc
            base_alert = self.get_alert_by_id(alert_id)
            if not base_alert:
                return []
            
            base_time = datetime.strptime(base_alert['Time'], '%Y-%m-%d %H:%M:%S')
            hostname = base_alert['Hostname']
            
            # Tính time window
            start_time = base_time - timedelta(minutes=time_window_minutes)
            end_time = base_time + timedelta(minutes=time_window_minutes)
            
            query = """
                SELECT * FROM Alerts 
                WHERE Hostname = ? 
                AND Time BETWEEN ? AND ?
                AND AlertID != ?
                ORDER BY Time DESC
            """
            
            alerts = self.db.fetch_all(query, [
                hostname, 
                start_time.strftime('%Y-%m-%d %H:%M:%S'),
                end_time.strftime('%Y-%m-%d %H:%M:%S'),
                alert_id
            ])
            
            return [self._parse_alert_json_fields(alert) for alert in alerts]
            
        except Exception as e:
            self.logger.error(f"Error getting alert correlation for {alert_id}: {e}")
            return []
    
    def get_escalated_alerts(self, escalation_threshold_hours: int = 2) -> List[Dict]:
        """Lấy alerts cần escalate"""
        try:
            threshold_time = datetime.now() - timedelta(hours=escalation_threshold_hours)
            
            query = """
                SELECT * FROM Alerts 
                WHERE Status IN ('New', 'In Progress')
                AND Severity IN ('Critical', 'High')
                AND Time <= ?
                ORDER BY Time ASC, Severity DESC
            """
            
            alerts = self.db.fetch_all(query, [threshold_time])
            return [self._parse_alert_json_fields(alert) for alert in alerts]
            
        except Exception as e:
            self.logger.error(f"Error getting escalated alerts: {e}")
            return []
    
    def add_alert_comment(self, alert_id: int, comment: str, author: str = 'System') -> bool:
        """Thêm comment vào alert (stored in JSON)"""
        try:
            # Lấy alert hiện tại
            alert = self.get_alert_by_id(alert_id)
            if not alert:
                return False
            
            # Lấy detection data hiện tại
            detection_data = alert.get('DetectionData', {})
            if isinstance(detection_data, str):
                try:
                    detection_data = json.loads(detection_data)
                except:
                    detection_data = {}
            
            # Thêm comment
            if 'comments' not in detection_data:
                detection_data['comments'] = []
            
            detection_data['comments'].append({
                'timestamp': datetime.now().isoformat(),
                'author': author,
                'comment': comment
            })
            
            # Update alert
            return self.db.update_data(
                'Alerts',
                {'DetectionData': json.dumps(detection_data)},
                'AlertID = ?',
                [alert_id]
            )
            
        except Exception as e:
            self.logger.error(f"Error adding comment to alert {alert_id}: {e}")
            return False
    
    def get_alert_metrics(self, days: int = 7) -> Dict:
        """Lấy metrics chi tiết về alerts"""
        try:
            start_time = datetime.now() - timedelta(days=days)
            
            metrics = {
                'period_days': days,
                'total_alerts': 0,
                'alerts_per_day': [],
                'severity_distribution': {},
                'resolution_stats': {
                    'resolved_count': 0,
                    'resolution_rate': 0,
                    'avg_resolution_time_hours': 0
                },
                'top_affected_agents': [],
                'alert_types_trend': []
            }
            
            # Total alerts
            total_result = self.db.fetch_one(
                "SELECT COUNT(*) as total FROM Alerts WHERE Time >= ?",
                [start_time]
            )
            if total_result:
                metrics['total_alerts'] = total_result['total']
            
            # Alerts per day
            daily_stats = self.db.fetch_all("""
                SELECT 
                    CAST(Time as DATE) as AlertDate,
                    COUNT(*) as DailyCount
                FROM Alerts 
                WHERE Time >= ?
                GROUP BY CAST(Time as DATE)
                ORDER BY AlertDate
            """, [start_time])
            
            metrics['alerts_per_day'] = [
                {'date': str(row['AlertDate']), 'count': row['DailyCount']}
                for row in daily_stats
            ]
            
            # Severity distribution
            severity_stats = self.db.fetch_all(
                "SELECT Severity, COUNT(*) as count FROM Alerts WHERE Time >= ? GROUP BY Severity",
                [start_time]
            )
            for row in severity_stats:
                metrics['severity_distribution'][row['Severity']] = row['count']
            
            # Resolution stats
            resolved_alerts = self.db.fetch_all("""
                SELECT Time, ResolvedAt FROM Alerts 
                WHERE Time >= ? AND Status = 'Resolved' AND ResolvedAt IS NOT NULL
            """, [start_time])
            
            if resolved_alerts:
                metrics['resolution_stats']['resolved_count'] = len(resolved_alerts)
                metrics['resolution_stats']['resolution_rate'] = (
                    len(resolved_alerts) / metrics['total_alerts'] * 100 
                    if metrics['total_alerts'] > 0 else 0
                )
                
                # Calculate average resolution time
                total_resolution_time = 0
                for alert in resolved_alerts:
                    try:
                        created_time = alert['Time']
                        resolved_time = alert['ResolvedAt']
                        if created_time and resolved_time:
                            diff = resolved_time - created_time
                            total_resolution_time += diff.total_seconds() / 3600  # Convert to hours
                    except:
                        continue
                
                if len(resolved_alerts) > 0:
                    metrics['resolution_stats']['avg_resolution_time_hours'] = (
                        total_resolution_time / len(resolved_alerts)
                    )
            
            # Top affected agents
            agent_stats = self.db.fetch_all("""
                SELECT TOP 10 Hostname, COUNT(*) as AlertCount
                FROM Alerts 
                WHERE Time >= ?
                GROUP BY Hostname
                ORDER BY AlertCount DESC
            """, [start_time])
            
            metrics['top_affected_agents'] = [
                {'hostname': row['Hostname'], 'alert_count': row['AlertCount']}
                for row in agent_stats
            ]
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"Error getting alert metrics: {e}")
            return {}