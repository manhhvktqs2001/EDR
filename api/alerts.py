"""
Alerts API Endpoints
Xử lý tất cả API calls liên quan đến alerts
"""

from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
import logging
import json
from database.alerts import AlertDB
from services.alert_service import AlertService
from utils.helpers import create_success_response, create_error_response, paginate_results, safe_int

alerts_api = Blueprint('alerts_api', __name__, url_prefix='/alerts')
logger = logging.getLogger(__name__)

@alerts_api.route('', methods=['GET'])
def get_alerts():
    """Lấy danh sách alerts với filtering"""
    try:
        alert_db = AlertDB()
        
        # Extract query parameters
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        severity = request.args.get('severity')
        status = request.args.get('status')
        hostname = request.args.get('hostname')
        alert_type = request.args.get('type')
        rule_id = safe_int(request.args.get('rule_id'))
        hours = safe_int(request.args.get('hours', 24))
        limit = int(request.args.get('limit', 1000))
        
        # Build filters
        filters = {}
        
        if severity:
            filters['severity'] = severity
        if status:
            filters['status'] = status
        if hostname:
            filters['hostname'] = hostname
        if alert_type:
            filters['alert_type'] = alert_type
        if rule_id:
            filters['rule_id'] = rule_id
        
        # Time range filter
        if hours > 0:
            start_time = datetime.now() - timedelta(hours=hours)
            filters['start_time'] = start_time.strftime('%Y-%m-%d %H:%M:%S')
        
        # Get alerts
        alerts = alert_db.get_alerts(filters, limit)
        
        # Paginate results
        paginated = paginate_results(alerts, page, per_page)
        
        return jsonify(create_success_response(paginated)), 200
        
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return jsonify(create_error_response(str(e))), 500

@alerts_api.route('/<int:alert_id>', methods=['GET'])
def get_alert(alert_id):
    """Lấy thông tin chi tiết alert"""
    try:
        alert_db = AlertDB()
        alert = alert_db.get_alert_by_id(alert_id)
        
        if not alert:
            return jsonify(create_error_response("Alert not found")), 404
        
        return jsonify(create_success_response(alert)), 200
        
    except Exception as e:
        logger.error(f"Error getting alert {alert_id}: {e}")
        return jsonify(create_error_response(str(e))), 500

@alerts_api.route('', methods=['POST'])
def create_alert():
    """Tạo alert mới"""
    try:
        data = request.get_json()
        if not data:
            return jsonify(create_error_response("No data provided")), 400
        
        # Validate required fields
        required_fields = ['hostname', 'rule_id', 'severity', 'description']
        for field in required_fields:
            if field not in data:
                return jsonify(create_error_response(f"Missing required field: {field}")), 400
        
        alert_db = AlertDB()
        success = alert_db.create_alert(data)
        
        if success:
            return jsonify(create_success_response(
                None, 
                f"Alert created for {data['hostname']}"
            )), 201
        else:
            return jsonify(create_error_response("Failed to create alert")), 500
            
    except Exception as e:
        logger.error(f"Error creating alert: {e}")
        return jsonify(create_error_response(str(e))), 500

@alerts_api.route('/<int:alert_id>/status', methods=['PUT'])
def update_alert_status(alert_id):
    """Cập nhật trạng thái alert"""
    try:
        data = request.get_json()
        if not data or 'status' not in data:
            return jsonify(create_error_response("Status is required")), 400
        
        status = data['status']
        valid_statuses = ['New', 'In Progress', 'Resolved', 'False Positive', 'Closed']
        
        if status not in valid_statuses:
            return jsonify(create_error_response(f"Invalid status. Must be one of: {valid_statuses}")), 400
        
        alert_db = AlertDB()
        success = alert_db.update_alert_status(alert_id, status)
        
        if success:
            return jsonify(create_success_response(
                {'alert_id': alert_id, 'status': status},
                f"Alert status updated to {status}"
            )), 200
        else:
            return jsonify(create_error_response("Failed to update alert status")), 500
            
    except Exception as e:
        logger.error(f"Error updating alert status {alert_id}: {e}")
        return jsonify(create_error_response(str(e))), 500

@alerts_api.route('/bulk/status', methods=['PUT'])
def bulk_update_alert_status():
    """Bulk update status cho nhiều alerts"""
    try:
        data = request.get_json()
        if not data or 'alert_ids' not in data or 'status' not in data:
            return jsonify(create_error_response("alert_ids and status are required")), 400
        
        alert_ids = data['alert_ids']
        status = data['status']
        
        if not isinstance(alert_ids, list):
            return jsonify(create_error_response("alert_ids must be a list")), 400
        
        valid_statuses = ['New', 'In Progress', 'Resolved', 'False Positive', 'Closed']
        if status not in valid_statuses:
            return jsonify(create_error_response(f"Invalid status. Must be one of: {valid_statuses}")), 400
        
        alert_service = AlertService()
        result = alert_service.process_bulk_alert_actions(
            alert_ids, 
            'update_status', 
            {'status': status}
        )
        
        return jsonify(create_success_response(result)), 200
        
    except Exception as e:
        logger.error(f"Error in bulk update alert status: {e}")
        return jsonify(create_error_response(str(e))), 500

@alerts_api.route('/bulk/actions', methods=['POST'])
def bulk_alert_actions():
    """Thực hiện bulk actions trên alerts"""
    try:
        data = request.get_json()
        if not data or 'alert_ids' not in data or 'action' not in data:
            return jsonify(create_error_response("alert_ids and action are required")), 400
        
        alert_ids = data['alert_ids']
        action = data['action']
        parameters = data.get('parameters', {})
        
        if not isinstance(alert_ids, list):
            return jsonify(create_error_response("alert_ids must be a list")), 400
        
        valid_actions = ['update_status', 'mark_resolved', 'mark_false_positive', 'assign_priority']
        if action not in valid_actions:
            return jsonify(create_error_response(f"Invalid action. Must be one of: {valid_actions}")), 400
        
        alert_service = AlertService()
        result = alert_service.process_bulk_alert_actions(alert_ids, action, parameters)
        
        return jsonify(create_success_response(result)), 200
        
    except Exception as e:
        logger.error(f"Error in bulk alert actions: {e}")
        return jsonify(create_error_response(str(e))), 500

@alerts_api.route('/statistics', methods=['GET'])
def get_alerts_statistics():
    """Lấy thống kê alerts"""
    try:
        hours = int(request.args.get('hours', 24))
        
        alert_db = AlertDB()
        stats = alert_db.get_alerts_statistics(hours)
        
        return jsonify(create_success_response(stats)), 200
        
    except Exception as e:
        logger.error(f"Error getting alerts statistics: {e}")
        return jsonify(create_error_response(str(e))), 500

@alerts_api.route('/dashboard', methods=['GET'])
def get_alerts_dashboard():
    """Lấy dữ liệu dashboard cho alerts"""
    try:
        # Extract query parameters
        hours = int(request.args.get('hours', 24))
        
        filters = {}
        if hours > 0:
            start_time = datetime.now() - timedelta(hours=hours)
            filters['start_time'] = start_time.strftime('%Y-%m-%d %H:%M:%S')
        
        alert_service = AlertService()
        dashboard_data = alert_service.get_alerts_dashboard_data(filters)
        
        return jsonify(create_success_response(dashboard_data)), 200
        
    except Exception as e:
        logger.error(f"Error getting alerts dashboard: {e}")
        return jsonify(create_error_response(str(e))), 500

@alerts_api.route('/recent', methods=['GET'])
def get_recent_alerts():
    """Lấy alerts gần đây"""
    try:
        hours = int(request.args.get('hours', 1))
        limit = int(request.args.get('limit', 50))
        hostname = request.args.get('hostname')
        
        alert_db = AlertDB()
        alerts = alert_db.get_recent_alerts(hostname, hours, limit)
        
        return jsonify(create_success_response({
            'alerts': alerts,
            'count': len(alerts),
            'hours': hours,
            'hostname': hostname
        })), 200
        
    except Exception as e:
        logger.error(f"Error getting recent alerts: {e}")
        return jsonify(create_error_response(str(e))), 500

@alerts_api.route('/unresolved', methods=['GET'])
def get_unresolved_alerts():
    """Lấy alerts chưa được giải quyết"""
    try:
        limit = int(request.args.get('limit', 100))
        
        alert_db = AlertDB()
        alerts = alert_db.get_unresolved_alerts(limit)
        
        return jsonify(create_success_response({
            'alerts': alerts,
            'count': len(alerts)
        })), 200
        
    except Exception as e:
        logger.error(f"Error getting unresolved alerts: {e}")
        return jsonify(create_error_response(str(e))), 500

@alerts_api.route('/search', methods=['GET'])
def search_alerts():
    """Tìm kiếm alerts"""
    try:
        search_term = request.args.get('q', '').strip()
        if not search_term:
            return jsonify(create_error_response("Search term is required")), 400
        
        limit = int(request.args.get('limit', 100))
        
        alert_db = AlertDB()
        alerts = alert_db.search_alerts(search_term, limit)
        
        return jsonify(create_success_response({
            'alerts': alerts,
            'count': len(alerts),
            'search_term': search_term
        })), 200
        
    except Exception as e:
        logger.error(f"Error searching alerts: {e}")
        return jsonify(create_error_response(str(e))), 500

@alerts_api.route('/severity/<severity>', methods=['GET'])
def get_alerts_by_severity(severity):
    """Lấy alerts theo severity"""
    try:
        valid_severities = ['Critical', 'High', 'Medium', 'Low']
        if severity not in valid_severities:
            return jsonify(create_error_response(f"Invalid severity. Must be one of: {valid_severities}")), 400
        
        limit = int(request.args.get('limit', 100))
        
        alert_db = AlertDB()
        alerts = alert_db.get_alerts_by_severity(severity, limit)
        
        return jsonify(create_success_response({
            'alerts': alerts,
            'count': len(alerts),
            'severity': severity
        })), 200
        
    except Exception as e:
        logger.error(f"Error getting alerts by severity {severity}: {e}")
        return jsonify(create_error_response(str(e))), 500

@alerts_api.route('/rule/<int:rule_id>', methods=['GET'])
def get_alerts_by_rule(rule_id):
    """Lấy alerts theo rule ID"""
    try:
        limit = int(request.args.get('limit', 100))
        
        alert_db = AlertDB()
        alerts = alert_db.get_alerts_by_rule(rule_id, limit)
        
        return jsonify(create_success_response({
            'alerts': alerts,
            'count': len(alerts),
            'rule_id': rule_id
        })), 200
        
    except Exception as e:
        logger.error(f"Error getting alerts by rule {rule_id}: {e}")
        return jsonify(create_error_response(str(e))), 500

@alerts_api.route('/timeline', methods=['GET'])
def get_alerts_timeline():
    """Lấy timeline của alerts"""
    try:
        hours = int(request.args.get('hours', 24))
        
        alert_db = AlertDB()
        timeline = alert_db.get_alert_timeline(hours)
        
        return jsonify(create_success_response({
            'timeline': timeline,
            'hours': hours
        })), 200
        
    except Exception as e:
        logger.error(f"Error getting alerts timeline: {e}")
        return jsonify(create_error_response(str(e))), 500

@alerts_api.route('/<int:alert_id>/investigate', methods=['POST'])
def create_investigation(alert_id):
    """Tạo investigation cho alert"""
    try:
        data = request.get_json() or {}
        investigator = data.get('investigator', 'System')
        
        alert_service = AlertService()
        result = alert_service.create_alert_investigation(alert_id, investigator)
        
        if result.get('success'):
            return jsonify(create_success_response(
                result['investigation'],
                "Investigation created successfully"
            )), 201
        else:
            return jsonify(create_error_response(result.get('error', 'Failed to create investigation'))), 500
            
    except Exception as e:
        logger.error(f"Error creating investigation for alert {alert_id}: {e}")
        return jsonify(create_error_response(str(e))), 500

@alerts_api.route('/<int:alert_id>/correlation', methods=['GET'])
def get_alert_correlation(alert_id):
    """Lấy alerts liên quan"""
    try:
        time_window = int(request.args.get('window_minutes', 60))
        
        alert_db = AlertDB()
        correlated_alerts = alert_db.get_alert_correlation(alert_id, time_window)
        
        return jsonify(create_success_response({
            'alert_id': alert_id,
            'correlated_alerts': correlated_alerts,
            'count': len(correlated_alerts),
            'time_window_minutes': time_window
        })), 200
        
    except Exception as e:
        logger.error(f"Error getting alert correlation for {alert_id}: {e}")
        return jsonify(create_error_response(str(e))), 500

@alerts_api.route('/<int:alert_id>/comment', methods=['POST'])
def add_alert_comment(alert_id):
    """Thêm comment vào alert"""
    try:
        data = request.get_json()
        if not data or 'comment' not in data:
            return jsonify(create_error_response("Comment is required")), 400
        
        comment = data['comment']
        author = data.get('author', 'System')
        
        alert_db = AlertDB()
        success = alert_db.add_alert_comment(alert_id, comment, author)
        
        if success:
            return jsonify(create_success_response(
                {'alert_id': alert_id, 'comment': comment, 'author': author},
                "Comment added successfully"
            )), 200
        else:
            return jsonify(create_error_response("Failed to add comment")), 500
            
    except Exception as e:
        logger.error(f"Error adding comment to alert {alert_id}: {e}")
        return jsonify(create_error_response(str(e))), 500

@alerts_api.route('/escalated', methods=['GET'])
def get_escalated_alerts():
    """Lấy alerts cần escalate"""
    try:
        threshold_hours = int(request.args.get('threshold_hours', 2))
        
        alert_db = AlertDB()
        escalated_alerts = alert_db.get_escalated_alerts(threshold_hours)
        
        return jsonify(create_success_response({
            'alerts': escalated_alerts,
            'count': len(escalated_alerts),
            'threshold_hours': threshold_hours
        })), 200
        
    except Exception as e:
        logger.error(f"Error getting escalated alerts: {e}")
        return jsonify(create_error_response(str(e))), 500

@alerts_api.route('/metrics', methods=['GET'])
def get_alert_metrics():
    """Lấy metrics chi tiết về alerts"""
    try:
        days = int(request.args.get('days', 7))
        
        alert_db = AlertDB()
        metrics = alert_db.get_alert_metrics(days)
        
        return jsonify(create_success_response(metrics)), 200
        
    except Exception as e:
        logger.error(f"Error getting alert metrics: {e}")
        return jsonify(create_error_response(str(e))), 500

@alerts_api.route('/report', methods=['GET'])
def generate_alert_report():
    """Tạo báo cáo alerts"""
    try:
        report_type = request.args.get('type', 'summary')
        days = int(request.args.get('days', 7))
        
        valid_types = ['summary', 'detailed', 'executive']
        if report_type not in valid_types:
            return jsonify(create_error_response(f"Invalid report type. Must be one of: {valid_types}")), 400
        
        # Build filters for report
        filters = {}
        if days > 0:
            start_time = datetime.now() - timedelta(days=days)
            filters['start_time'] = start_time.strftime('%Y-%m-%d %H:%M:%S')
        
        alert_service = AlertService()
        report = alert_service.generate_alert_report(report_type, filters)
        
        return jsonify(create_success_response(report)), 200
        
    except Exception as e:
        logger.error(f"Error generating alert report: {e}")
        return jsonify(create_error_response(str(e))), 500

@alerts_api.route('/export', methods=['GET'])
def export_alerts():
    """Export alerts data"""
    try:
        format_type = request.args.get('format', 'json').lower()
        hours = int(request.args.get('hours', 24))
        hostname = request.args.get('hostname')
        severity = request.args.get('severity')
        limit = int(request.args.get('limit', 1000))
        
        # Build filters
        filters = {}
        if hours > 0:
            start_time = datetime.now() - timedelta(hours=hours)
            filters['start_time'] = start_time.strftime('%Y-%m-%d %H:%M:%S')
        if hostname:
            filters['hostname'] = hostname
        if severity:
            filters['severity'] = severity
        
        alert_db = AlertDB()
        alerts = alert_db.get_alerts(filters, limit)
        
        if format_type == 'csv':
            return _export_alerts_csv(alerts)
        else:
            return jsonify(create_success_response({
                'alerts': alerts,
                'count': len(alerts),
                'filters': filters,
                'exported_at': datetime.now().isoformat()
            })), 200
        
    except Exception as e:
        logger.error(f"Error exporting alerts: {e}")
        return jsonify(create_error_response(str(e))), 500

@alerts_api.route('/cleanup', methods=['POST'])
def cleanup_old_alerts():
    """Dọn dẹp alerts cũ"""
    try:
        data = request.get_json() or {}
        days = data.get('days', 30)
        
        alert_db = AlertDB()
        deleted_count = alert_db.cleanup_old_alerts(days)
        
        return jsonify(create_success_response({
            'deleted_count': deleted_count,
            'retention_days': days
        }, f"Cleaned up {deleted_count} old alerts")), 200
        
    except Exception as e:
        logger.error(f"Error cleaning up old alerts: {e}")
        return jsonify(create_error_response(str(e))), 500

@alerts_api.route('/stats/period', methods=['GET'])
def get_alert_statistics_by_period():
    """Lấy thống kê alerts theo period"""
    try:
        period = request.args.get('period', 'daily')
        days = int(request.args.get('days', 7))
        
        valid_periods = ['hourly', 'daily', 'weekly']
        if period not in valid_periods:
            return jsonify(create_error_response(f"Invalid period. Must be one of: {valid_periods}")), 400
        
        alert_service = AlertService()
        stats = alert_service.get_alert_statistics_by_period(period, days)
        
        return jsonify(create_success_response(stats)), 200
        
    except Exception as e:
        logger.error(f"Error getting alert statistics by period: {e}")
        return jsonify(create_error_response(str(e))), 500

@alerts_api.route('/top/types', methods=['GET'])
def get_top_alert_types():
    """Lấy top alert types"""
    try:
        hours = int(request.args.get('hours', 24))
        limit = int(request.args.get('limit', 10))
        
        alert_db = AlertDB()
        top_types = alert_db.get_top_alert_types(hours, limit)
        
        return jsonify(create_success_response({
            'top_types': top_types,
            'hours': hours,
            'limit': limit
        })), 200
        
    except Exception as e:
        logger.error(f"Error getting top alert types: {e}")
        return jsonify(create_error_response(str(e))), 500

@alerts_api.route('/<int:alert_id>', methods=['DELETE'])
def delete_alert(alert_id):
    """Xóa alert"""
    try:
        alert_db = AlertDB()
        success = alert_db.delete_alert(alert_id)
        
        if success:
            return jsonify(create_success_response(
                {'alert_id': alert_id},
                f"Alert {alert_id} deleted"
            )), 200
        else:
            return jsonify(create_error_response("Failed to delete alert")), 500
            
    except Exception as e:
        logger.error(f"Error deleting alert {alert_id}: {e}")
        return jsonify(create_error_response(str(e))), 500

@alerts_api.route('/agent/<hostname>', methods=['GET'])
def get_alerts_by_agent(hostname):
    """Lấy alerts của một agent cụ thể"""
    try:
        limit = int(request.args.get('limit', 100))
        hours = int(request.args.get('hours', 24))
        
        # Build filters
        filters = {'hostname': hostname}
        if hours > 0:
            start_time = datetime.now() - timedelta(hours=hours)
            filters['start_time'] = start_time.strftime('%Y-%m-%d %H:%M:%S')
        
        alert_db = AlertDB()
        alerts = alert_db.get_alerts(filters, limit)
        
        # Calculate summary
        summary = {
            'total_alerts': len(alerts),
            'by_severity': {},
            'by_status': {},
            'recent_count': 0
        }
        
        recent_threshold = datetime.now() - timedelta(hours=1)
        
        for alert in alerts:
            # By severity
            severity = alert.get('Severity', 'Unknown')
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            
            # By status
            status = alert.get('Status', 'Unknown')
            summary['by_status'][status] = summary['by_status'].get(status, 0) + 1
            
            # Recent alerts (last hour)
            alert_time = alert.get('Time')
            if alert_time:
                try:
                    alert_dt = datetime.strptime(alert_time, '%Y-%m-%d %H:%M:%S')
                    if alert_dt >= recent_threshold:
                        summary['recent_count'] += 1
                except:
                    pass
        
        return jsonify(create_success_response({
            'hostname': hostname,
            'alerts': alerts,
            'summary': summary,
            'period_hours': hours
        })), 200
        
    except Exception as e:
        logger.error(f"Error getting alerts for agent {hostname}: {e}")
        return jsonify(create_error_response(str(e))), 500

@alerts_api.route('/bulk/create', methods=['POST'])
def bulk_create_alerts():
    """Tạo nhiều alerts cùng lúc"""
    try:
        data = request.get_json()
        if not data or 'alerts' not in data:
            return jsonify(create_error_response("alerts data is required")), 400
        
        alerts_data = data['alerts']
        if not isinstance(alerts_data, list):
            return jsonify(create_error_response("alerts must be a list")), 400
        
        alert_db = AlertDB()
        result = alert_db.create_bulk_alerts(alerts_data)
        
        return jsonify(create_success_response(result)), 201
        
    except Exception as e:
        logger.error(f"Error in bulk create alerts: {e}")
        return jsonify(create_error_response(str(e))), 500

# Helper functions
def _export_alerts_csv(alerts):
    """Export alerts as CSV"""
    try:
        import csv
        import io
        from flask import Response
        
        output = io.StringIO()
        
        if alerts:
            # Get all possible fieldnames
            fieldnames = set()
            for alert in alerts:
                fieldnames.update(alert.keys())
            
            fieldnames = sorted(list(fieldnames))
            
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            
            for alert in alerts:
                # Convert complex data to strings
                row = {}
                for field in fieldnames:
                    value = alert.get(field, '')
                    if isinstance(value, (dict, list)):
                        row[field] = json.dumps(value)
                    else:
                        row[field] = str(value) if value is not None else ''
                writer.writerow(row)
        
        csv_content = output.getvalue()
        output.close()
        
        return Response(
            csv_content,
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename=alerts_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            }
        )
        
    except Exception as e:
        logger.error(f"Error exporting alerts CSV: {e}")
        return jsonify(create_error_response(str(e))), 500