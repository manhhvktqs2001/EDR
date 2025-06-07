"""
Dashboard API Endpoints
Xử lý tất cả API calls liên quan đến dashboard
"""

from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
import logging
from database.agents import AgentDB
from database.alerts import AlertDB
from database.logs import LogDB
from database.rules import RuleDB
from services.agent_service import AgentService
from services.alert_service import AlertService
from utils.helpers import create_success_response, create_error_response, safe_int

dashboard_api = Blueprint('dashboard_api', __name__, url_prefix='/api/dashboard')
logger = logging.getLogger(__name__)

@dashboard_api.route('', methods=['GET'])
def get_dashboard_overview():
    """Lấy tổng quan dashboard"""
    try:
        # Get time range
        hours = int(request.args.get('hours', 24))
        
        # Initialize services
        agent_service = AgentService()
        alert_service = AlertService()
        
        # Get data from various services
        agents_data = agent_service.get_agent_dashboard_data()
        
        # Build filters for alerts
        filters = {}
        if hours > 0:
            start_time = datetime.now() - timedelta(hours=hours)
            filters['start_time'] = start_time.strftime('%Y-%m-%d %H:%M:%S')
        
        alerts_data = alert_service.get_alerts_dashboard_data(filters)
        
        # Get basic statistics
        log_db = LogDB()
        rule_db = RuleDB()
        
        log_stats = log_db.get_log_statistics(hours)
        rule_stats = rule_db.get_rules_statistics()
        
        # Combine all data
        dashboard_data = {
            'overview': {
                'agents': agents_data.get('summary', {}),
                'alerts': alerts_data.get('summary', {}),
                'logs': log_stats,
                'rules': rule_stats
            },
            'agents': agents_data,
            'alerts': alerts_data,
            'time_range': {
                'hours': hours,
                'start_time': filters.get('start_time'),
                'end_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            },
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify(create_success_response(dashboard_data)), 200
        
    except Exception as e:
        logger.error(f"Error getting dashboard overview: {e}")
        return jsonify(create_error_response(str(e))), 500

def _get_top_threats_data(hours):
    """Get top threats data for charts"""
    try:
        alert_db = AlertDB()
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
        
        alerts = alert_db.get_alerts({
            'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S')
        }, 1000)
        
        # Group by alert type
        threat_counts = {}
        for alert in alerts:
            alert_type = alert.get('AlertType', 'Unknown')
            threat_counts[alert_type] = threat_counts.get(alert_type, 0) + 1
        
        # Sort and get top 10
        sorted_threats = sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            'labels': [threat[0] for threat in sorted_threats],
            'data': [threat[1] for threat in sorted_threats],
            'total': len(alerts)
        }
        
    except Exception as e:
        logger.error(f"Error getting top threats data: {e}")
        return {'labels': [], 'data': [], 'total': 0}

def _get_system_uptime():
    """Get system uptime"""
    try:
        import psutil
        boot_time = psutil.boot_time()
        uptime_seconds = datetime.now().timestamp() - boot_time
        
        days = int(uptime_seconds // 86400)
        hours = int((uptime_seconds % 86400) // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        
        return f"{days}d {hours}h {minutes}m"
        
    except ImportError:
        # Fallback if psutil not available
        return "Unknown"
    except Exception as e:
        logger.error(f"Error getting system uptime: {e}")
        return "Unknown"

@dashboard_api.route('/summary', methods=['GET'])
def get_dashboard_summary():
    """Lấy tóm tắt nhanh dashboard"""
    try:
        agent_db = AgentDB()
        alert_db = AlertDB()
        log_db = LogDB()
        
        # Get quick stats
        agent_stats = agent_db.get_agents_statistics()
        alert_stats = alert_db.get_alerts_statistics(24)  # Last 24 hours
        log_stats = log_db.get_log_statistics(24)
        
        # Calculate health score
        total_agents = agent_stats.get('total_agents', 0)
        online_agents = agent_stats.get('online_agents', 0)
        critical_alerts = alert_stats.get('by_severity', {}).get('Critical', 0)
        
        health_score = 100
        if total_agents > 0:
            health_score -= (total_agents - online_agents) * 10  # -10 per offline agent
        health_score -= critical_alerts * 5  # -5 per critical alert
        health_score = max(0, min(100, health_score))
        
        summary = {
            'system_health': {
                'score': health_score,
                'status': 'healthy' if health_score >= 80 else 'warning' if health_score >= 60 else 'critical'
            },
            'quick_stats': {
                'total_agents': total_agents,
                'online_agents': online_agents,
                'total_alerts_24h': alert_stats.get('total_alerts', 0),
                'critical_alerts': critical_alerts,
                'total_logs_24h': log_stats.get('total_logs', 0)
            },
            'status_indicators': {
                'agents_online': online_agents > 0,
                'no_critical_alerts': critical_alerts == 0,
                'logs_flowing': log_stats.get('total_logs', 0) > 0,
                'rules_active': True  # Placeholder
            },
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify(create_success_response(summary)), 200
        
    except Exception as e:
        logger.error(f"Error getting dashboard summary: {e}")
        return jsonify(create_error_response(str(e))), 500

@dashboard_api.route('/metrics', methods=['GET'])
def get_dashboard_metrics():
    """Lấy metrics chi tiết cho dashboard"""
    try:
        hours = int(request.args.get('hours', 24))
        
        # Time calculations
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
        
        # Get metrics from different components
        agent_db = AgentDB()
        alert_db = AlertDB()
        log_db = LogDB()
        
        # Agent metrics
        all_agents = agent_db.get_all_agents()
        agent_metrics = {
            'total': len(all_agents),
            'online': len([a for a in all_agents if a.get('Status') == 'Online']),
            'by_os': {},
            'by_status': {}
        }
        
        for agent in all_agents:
            os_type = agent.get('OSType', 'Unknown')
            status = agent.get('Status', 'Unknown')
            
            agent_metrics['by_os'][os_type] = agent_metrics['by_os'].get(os_type, 0) + 1
            agent_metrics['by_status'][status] = agent_metrics['by_status'].get(status, 0) + 1
        
        # Alert metrics
        filters = {'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S')}
        alerts = alert_db.get_alerts(filters, 1000)
        
        alert_metrics = {
            'total': len(alerts),
            'by_severity': {},
            'by_status': {},
            'recent_trend': []
        }
        
        for alert in alerts:
            severity = alert.get('Severity', 'Unknown')
            status = alert.get('Status', 'Unknown')
            
            alert_metrics['by_severity'][severity] = alert_metrics['by_severity'].get(severity, 0) + 1
            alert_metrics['by_status'][status] = alert_metrics['by_status'].get(status, 0) + 1
        
        # Log metrics
        log_metrics = log_db.get_log_statistics(hours)
        
        # Performance metrics
        performance_metrics = {
            'alerts_per_hour': len(alerts) / max(hours, 1),
            'logs_per_hour': log_metrics.get('total_logs', 0) / max(hours, 1),
            'agent_utilization': (agent_metrics['online'] / max(agent_metrics['total'], 1)) * 100,
            'alert_resolution_rate': self._calculate_resolution_rate(alerts)
        }
        
        # Combine all metrics
        metrics = {
            'agents': agent_metrics,
            'alerts': alert_metrics,
            'logs': log_metrics,
            'performance': performance_metrics,
            'time_range': {
                'hours': hours,
                'start': start_time.isoformat(),
                'end': end_time.isoformat()
            },
            'generated_at': datetime.now().isoformat()
        }
        
        return jsonify(create_success_response(metrics)), 200
        
    except Exception as e:
        logger.error(f"Error getting dashboard metrics: {e}")
        return jsonify(create_error_response(str(e))), 500

@dashboard_api.route('/charts', methods=['GET'])
def get_dashboard_charts():
    """Lấy dữ liệu cho charts dashboard"""
    try:
        chart_type = request.args.get('type', 'all')
        hours = int(request.args.get('hours', 24))
        
        charts_data = {}
        
        if chart_type in ['all', 'alerts_timeline']:
            charts_data['alerts_timeline'] = self._get_alerts_timeline_data(hours)
        
        if chart_type in ['all', 'agent_status']:
            charts_data['agent_status'] = self._get_agent_status_data()
        
        if chart_type in ['all', 'log_distribution']:
            charts_data['log_distribution'] = self._get_log_distribution_data(hours)
        
        if chart_type in ['all', 'threat_levels']:
            charts_data['threat_levels'] = self._get_threat_levels_data(hours)
        
        if chart_type in ['all', 'top_threats']:
            charts_data['top_threats'] = self._get_top_threats_data(hours)
        
        return jsonify(create_success_response(charts_data)), 200
        
    except Exception as e:
        logger.error(f"Error getting dashboard charts: {e}")
        return jsonify(create_error_response(str(e))), 500

@dashboard_api.route('/real-time', methods=['GET'])
def get_realtime_data():
    """Lấy dữ liệu real-time cho dashboard"""
    try:
        # Get data for last 5 minutes
        end_time = datetime.now()
        start_time = end_time - timedelta(minutes=5)
        
        alert_db = AlertDB()
        log_db = LogDB()
        
        # Recent alerts
        recent_alerts = alert_db.get_alerts({
            'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S')
        }, 10)
        
        # Recent logs count
        recent_logs_count = {
            'process': len(log_db.get_process_logs(from_time=start_time.strftime('%Y-%m-%d %H:%M:%S'), limit=100)),
            'file': len(log_db.get_file_logs(from_time=start_time.strftime('%Y-%m-%d %H:%M:%S'), limit=100)),
            'network': len(log_db.get_network_logs(from_time=start_time.strftime('%Y-%m-%d %H:%M:%S'), limit=100))
        }
        
        # System activity indicators
        activity_indicators = {
            'alerts_last_5min': len(recent_alerts),
            'logs_last_5min': sum(recent_logs_count.values()),
            'critical_alerts': len([a for a in recent_alerts if a.get('Severity') == 'Critical']),
            'timestamp': datetime.now().isoformat()
        }
        
        realtime_data = {
            'recent_alerts': recent_alerts,
            'log_activity': recent_logs_count,
            'activity_indicators': activity_indicators,
            'last_updated': datetime.now().isoformat()
        }
        
        return jsonify(create_success_response(realtime_data)), 200
        
    except Exception as e:
        logger.error(f"Error getting real-time data: {e}")
        return jsonify(create_error_response(str(e))), 500

@dashboard_api.route('/status', methods=['GET'])
def get_system_status():
    """Lấy trạng thái hệ thống"""
    try:
        from database.connection import test_database_connection
        
        # Test database connection
        db_healthy, db_message = test_database_connection()
        
        # Get component status
        agent_db = AgentDB()
        agents = agent_db.get_all_agents()
        
        status = {
            'overall_status': 'healthy',
            'components': {
                'database': {
                    'status': 'healthy' if db_healthy else 'error',
                    'message': db_message,
                    'last_check': datetime.now().isoformat()
                },
                'agents': {
                    'status': 'healthy' if agents else 'warning',
                    'total_agents': len(agents),
                    'online_agents': len([a for a in agents if a.get('Status') == 'Online']),
                    'last_check': datetime.now().isoformat()
                },
                'rule_engine': {
                    'status': 'healthy',
                    'message': 'Rule engine operational',
                    'last_check': datetime.now().isoformat()
                },
                'socketio': {
                    'status': 'healthy',
                    'message': 'SocketIO service operational',
                    'last_check': datetime.now().isoformat()
                }
            },
            'uptime': self._get_system_uptime(),
            'last_updated': datetime.now().isoformat()
        }
        
        # Determine overall status
        component_statuses = [comp['status'] for comp in status['components'].values()]
        if 'error' in component_statuses:
            status['overall_status'] = 'error'
        elif 'warning' in component_statuses:
            status['overall_status'] = 'warning'
        
        return jsonify(create_success_response(status)), 200
        
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        return jsonify(create_error_response(str(e))), 500

# Helper methods
def _calculate_resolution_rate(alerts):
    """Calculate alert resolution rate"""
    if not alerts:
        return 0
    
    resolved_count = len([a for a in alerts if a.get('Status') == 'Resolved'])
    return (resolved_count / len(alerts)) * 100

def _get_alerts_timeline_data(hours):
    """Get alerts timeline data for charts"""
    try:
        alert_db = AlertDB()
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
        
        alerts = alert_db.get_alerts({
            'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S')
        }, 1000)
        
        # Group by hour
        timeline = {}
        for alert in alerts:
            alert_time = alert.get('Time')
            if alert_time:
                try:
                    hour = datetime.strptime(alert_time, '%Y-%m-%d %H:%M:%S').strftime('%H:00')
                    timeline[hour] = timeline.get(hour, 0) + 1
                except:
                    continue
        
        return {
            'labels': sorted(timeline.keys()),
            'data': [timeline[hour] for hour in sorted(timeline.keys())],
            'total': len(alerts)
        }
        
    except Exception as e:
        logger.error(f"Error getting alerts timeline data: {e}")
        return {'labels': [], 'data': [], 'total': 0}

def _get_agent_status_data():
    """Get agent status data for charts"""
    try:
        agent_db = AgentDB()
        agents = agent_db.get_all_agents()
        
        status_counts = {}
        for agent in agents:
            status = agent.get('Status', 'Unknown')
            status_counts[status] = status_counts.get(status, 0) + 1
        
        return {
            'labels': list(status_counts.keys()),
            'data': list(status_counts.values()),
            'total': len(agents)
        }
        
    except Exception as e:
        logger.error(f"Error getting agent status data: {e}")
        return {'labels': [], 'data': [], 'total': 0}

def _get_log_distribution_data(hours):
    """Get log distribution data for charts"""
    try:
        log_db = LogDB()
        log_stats = log_db.get_log_statistics(hours)
        
        return {
            'labels': ['Process', 'File', 'Network'],
            'data': [
                log_stats.get('process_logs', 0),
                log_stats.get('file_logs', 0),
                log_stats.get('network_logs', 0)
            ],
            'total': log_stats.get('total_logs', 0)
        }
        
    except Exception as e:
        logger.error(f"Error getting log distribution data: {e}")
        return {'labels': [], 'data': [], 'total': 0}

def _get_threat_levels_data(hours):
    """Get threat levels data for charts"""
    try:
        alert_db = AlertDB()
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
        
        alerts = alert_db.get_alerts({
            'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S')
        }, 1000)
        
        severity_counts = {}
        for alert in alerts:
            severity = alert.get('Severity', 'Unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            'labels': list(severity_counts.keys()),
            'data': list(severity_counts.values()),
            'total': len(alerts)
        }
        
    except Exception as e:
        logger.error(f"Error getting threat levels data: {e}")
        return {'labels': [], 'data': [], 'total': 0}