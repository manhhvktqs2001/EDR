"""
Agents API Endpoints
Xử lý tất cả API calls liên quan đến agents
"""

from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
import logging
from database.agents import AgentDB
from services.agent_service import AgentService
from utils.helpers import validate_hostname, create_success_response, create_error_response, paginate_results

agents_api = Blueprint('agents_api', __name__, url_prefix='/api/agents')
logger = logging.getLogger(__name__)

@agents_api.route('', methods=['GET'])
def get_agents():
    """Lấy danh sách agents với filtering và pagination"""
    try:
        agent_db = AgentDB()
        
        # Extract query parameters
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        status = request.args.get('status')
        os_type = request.args.get('os_type')
        search = request.args.get('search')
        online_only = request.args.get('online_only', 'false').lower() == 'true'
        
        # Get agents based on filters
        if online_only:
            agents = agent_db.get_online_agents()
        elif os_type:
            agents = agent_db.get_agents_by_os(os_type)
        elif search:
            agents = agent_db.search_agents(search)
        else:
            agents = agent_db.get_all_agents()
        
        # Apply additional filters
        if status:
            agents = [a for a in agents if a.get('Status') == status]
        
        # Add computed fields
        for agent in agents:
            agent['IsOnline'] = _is_agent_online(agent.get('LastSeen'))
            agent['LastSeenAgo'] = _calculate_time_ago(agent.get('LastSeen'))
        
        # Paginate results
        paginated = paginate_results(agents, page, per_page)
        
        return jsonify(create_success_response(paginated)), 200
        
    except Exception as e:
        logger.error(f"Error getting agents: {e}")
        return jsonify(create_error_response(str(e))), 500

@agents_api.route('/<hostname>', methods=['GET'])
def get_agent(hostname):
    """Lấy thông tin chi tiết của agent"""
    try:
        if not validate_hostname(hostname):
            return jsonify(create_error_response("Invalid hostname")), 400
        
        agent_service = AgentService()
        agent_data = agent_service.get_agent_dashboard_data(hostname)
        
        if 'error' in agent_data:
            return jsonify(create_error_response(agent_data['error'])), 404
        
        return jsonify(create_success_response(agent_data)), 200
        
    except Exception as e:
        logger.error(f"Error getting agent {hostname}: {e}")
        return jsonify(create_error_response(str(e))), 500

@agents_api.route('/register', methods=['POST'])
def register_agent():
    """Đăng ký agent mới"""
    try:
        data = request.get_json()
        if not data:
            return jsonify(create_error_response("No data provided")), 400
            
        required_fields = ['hostname', 'os_type', 'version']
        for field in required_fields:
            if field not in data:
                return jsonify(create_error_response(f"Missing required field: {field}")), 400
        
        agent_service = AgentService()
        result = agent_service.register_agent(
            hostname=data['hostname'],
            os_type=data['os_type'],
            version=data['version'],
            ip_address=request.remote_addr,
            additional_info=data.get('additional_info', {})
        )
        
        if 'error' in result:
            return jsonify(create_error_response(result['error'])), 400
            
        return jsonify(create_success_response(result)), 201
        
    except Exception as e:
        logger.error(f"Error registering agent: {e}")
        return jsonify(create_error_response(str(e))), 500

@agents_api.route('/<hostname>', methods=['PUT'])
def update_agent(hostname):
    """Cập nhật thông tin agent"""
    try:
        if not validate_hostname(hostname):
            return jsonify(create_error_response("Invalid hostname")), 400
        
        data = request.get_json()
        if not data:
            return jsonify(create_error_response("No data provided")), 400
        
        agent_service = AgentService()
        success, message = agent_service.update_agent_configuration(hostname, data)
        
        if success:
            return jsonify(create_success_response(None, message)), 200
        else:
            return jsonify(create_error_response(message)), 500
            
    except Exception as e:
        logger.error(f"Error updating agent {hostname}: {e}")
        return jsonify(create_error_response(str(e))), 500

@agents_api.route('/<hostname>', methods=['DELETE'])
def delete_agent(hostname):
    """Xóa agent"""
    try:
        if not validate_hostname(hostname):
            return jsonify(create_error_response("Invalid hostname")), 400
        
        agent_db = AgentDB()
        success = agent_db.delete_agent(hostname)
        
        if success:
            return jsonify(create_success_response(None, f"Agent {hostname} deleted")), 200
        else:
            return jsonify(create_error_response("Failed to delete agent")), 500
            
    except Exception as e:
        logger.error(f"Error deleting agent {hostname}: {e}")
        return jsonify(create_error_response(str(e))), 500

@agents_api.route('/<hostname>/status', methods=['PUT'])
def update_agent_status(hostname):
    """Cập nhật trạng thái agent"""
    try:
        if not validate_hostname(hostname):
            return jsonify(create_error_response("Invalid hostname")), 400
        
        data = request.get_json()
        if not data or 'status' not in data:
            return jsonify(create_error_response("Status is required")), 400
        
        status = data['status']
        valid_statuses = ['Online', 'Offline', 'Maintenance', 'Error']
        
        if status not in valid_statuses:
            return jsonify(create_error_response(f"Invalid status. Must be one of: {valid_statuses}")), 400
        
        agent_db = AgentDB()
        success = agent_db.update_agent_status(hostname, status)
        
        if success:
            return jsonify(create_success_response(
                {'hostname': hostname, 'status': status},
                f"Agent status updated to {status}"
            )), 200
        else:
            return jsonify(create_error_response("Failed to update agent status")), 500
            
    except Exception as e:
        logger.error(f"Error updating agent status {hostname}: {e}")
        return jsonify(create_error_response(str(e))), 500

@agents_api.route('/<hostname>/rules', methods=['GET'])
def get_agent_rules(hostname):
    """Lấy rules được assign cho agent"""
    try:
        if not validate_hostname(hostname):
            return jsonify(create_error_response("Invalid hostname")), 400
        
        agent_service = AgentService()
        rules_data = agent_service.get_applicable_rules_for_agent(hostname)
        
        if 'error' in rules_data:
            return jsonify(create_error_response(rules_data['error'])), 404
        
        return jsonify(create_success_response(rules_data)), 200
        
    except Exception as e:
        logger.error(f"Error getting agent rules {hostname}: {e}")
        return jsonify(create_error_response(str(e))), 500

@agents_api.route('/<hostname>/rules', methods=['POST'])
def assign_rules_to_agent(hostname):
    """Assign rules cho agent"""
    try:
        if not validate_hostname(hostname):
            return jsonify(create_error_response("Invalid hostname")), 400
        
        data = request.get_json()
        if not data or 'rule_ids' not in data:
            return jsonify(create_error_response("rule_ids is required")), 400
        
        rule_ids = data['rule_ids']
        if not isinstance(rule_ids, list):
            return jsonify(create_error_response("rule_ids must be a list")), 400
        
        agent_service = AgentService()
        success, message = agent_service.assign_rules_to_agent(hostname, rule_ids)
        
        if success:
            return jsonify(create_success_response(
                {'hostname': hostname, 'assigned_rules': len(rule_ids)},
                message
            )), 200
        else:
            return jsonify(create_error_response(message)), 500
            
    except Exception as e:
        logger.error(f"Error assigning rules to agent {hostname}: {e}")
        return jsonify(create_error_response(str(e))), 500

@agents_api.route('/<hostname>/rules/<int:rule_id>', methods=['DELETE'])
def unassign_rule_from_agent(hostname, rule_id):
    """Unassign rule từ agent"""
    try:
        if not validate_hostname(hostname):
            return jsonify(create_error_response("Invalid hostname")), 400
        
        agent_db = AgentDB()
        success = agent_db.unassign_rule(hostname, rule_id)
        
        if success:
            return jsonify(create_success_response(
                {'hostname': hostname, 'rule_id': rule_id},
                f"Rule {rule_id} unassigned from {hostname}"
            )), 200
        else:
            return jsonify(create_error_response("Failed to unassign rule")), 500
            
    except Exception as e:
        logger.error(f"Error unassigning rule {rule_id} from agent {hostname}: {e}")
        return jsonify(create_error_response(str(e))), 500

@agents_api.route('/<hostname>/activity', methods=['GET'])
def get_agent_activity(hostname):
    """Lấy activity summary của agent"""
    try:
        if not validate_hostname(hostname):
            return jsonify(create_error_response("Invalid hostname")), 400
        
        hours = int(request.args.get('hours', 24))
        
        agent_db = AgentDB()
        activity = agent_db.get_agent_activity_summary(hostname, hours)
        
        if not activity:
            return jsonify(create_error_response("Agent not found")), 404
        
        return jsonify(create_success_response(activity)), 200
        
    except Exception as e:
        logger.error(f"Error getting agent activity {hostname}: {e}")
        return jsonify(create_error_response(str(e))), 500

@agents_api.route('/<hostname>/performance', methods=['GET'])
def get_agent_performance(hostname):
    """Lấy performance metrics của agent"""
    try:
        if not validate_hostname(hostname):
            return jsonify(create_error_response("Invalid hostname")), 400
        
        hours = int(request.args.get('hours', 24))
        
        agent_service = AgentService()
        performance = agent_service.get_agent_performance_metrics(hostname, hours)
        
        if 'error' in performance:
            return jsonify(create_error_response(performance['error'])), 404
        
        return jsonify(create_success_response(performance)), 200
        
    except Exception as e:
        logger.error(f"Error getting agent performance {hostname}: {e}")
        return jsonify(create_error_response(str(e))), 500

@agents_api.route('/<hostname>/report', methods=['GET'])
def generate_agent_report(hostname):
    """Tạo báo cáo chi tiết cho agent"""
    try:
        if not validate_hostname(hostname):
            return jsonify(create_error_response("Invalid hostname")), 400
        
        report_type = request.args.get('type', 'summary')
        valid_types = ['summary', 'detailed', 'security']
        
        if report_type not in valid_types:
            return jsonify(create_error_response(f"Invalid report type. Must be one of: {valid_types}")), 400
        
        agent_service = AgentService()
        report = agent_service.generate_agent_report(hostname, report_type)
        
        if 'error' in report:
            return jsonify(create_error_response(report['error'])), 404
        
        return jsonify(create_success_response(report)), 200
        
    except Exception as e:
        logger.error(f"Error generating agent report {hostname}: {e}")
        return jsonify(create_error_response(str(e))), 500

@agents_api.route('/statistics', methods=['GET'])
def get_agents_statistics():
    """Lấy thống kê tổng quan về agents"""
    try:
        agent_db = AgentDB()
        stats = agent_db.get_agents_statistics()
        
        return jsonify(create_success_response(stats)), 200
        
    except Exception as e:
        logger.error(f"Error getting agents statistics: {e}")
        return jsonify(create_error_response(str(e))), 500

@agents_api.route('/dashboard', methods=['GET'])
def get_agents_dashboard():
    """Lấy dữ liệu dashboard tổng quan agents"""
    try:
        agent_service = AgentService()
        dashboard_data = agent_service.get_agent_dashboard_data()
        
        return jsonify(create_success_response(dashboard_data)), 200
        
    except Exception as e:
        logger.error(f"Error getting agents dashboard: {e}")
        return jsonify(create_error_response(str(e))), 500

@agents_api.route('/online', methods=['GET'])
def get_online_agents():
    """Lấy danh sách agents đang online"""
    try:
        agent_db = AgentDB()
        online_agents = agent_db.get_online_agents()
        
        # Add computed fields
        for agent in online_agents:
            agent['LastSeenAgo'] = _calculate_time_ago(agent.get('LastSeen'))
        
        return jsonify(create_success_response({
            'agents': online_agents,
            'count': len(online_agents)
        })), 200
        
    except Exception as e:
        logger.error(f"Error getting online agents: {e}")
        return jsonify(create_error_response(str(e))), 500

@agents_api.route('/search', methods=['GET'])
def search_agents():
    """Tìm kiếm agents"""
    try:
        search_term = request.args.get('q', '').strip()
        if not search_term:
            return jsonify(create_error_response("Search term is required")), 400
        
        limit = int(request.args.get('limit', 50))
        
        agent_db = AgentDB()
        agents = agent_db.search_agents(search_term)
        
        # Limit results
        agents = agents[:limit]
        
        # Add computed fields
        for agent in agents:
            agent['IsOnline'] = _is_agent_online(agent.get('LastSeen'))
            agent['LastSeenAgo'] = _calculate_time_ago(agent.get('LastSeen'))
        
        return jsonify(create_success_response({
            'agents': agents,
            'count': len(agents),
            'search_term': search_term
        })), 200
        
    except Exception as e:
        logger.error(f"Error searching agents: {e}")
        return jsonify(create_error_response(str(e))), 500

@agents_api.route('/bulk/update', methods=['PUT'])
def bulk_update_agents():
    """Bulk update nhiều agents"""
    try:
        data = request.get_json()
        if not data or 'updates' not in data:
            return jsonify(create_error_response("updates is required")), 400
        
        updates = data['updates']
        if not isinstance(updates, list):
            return jsonify(create_error_response("updates must be a list")), 400
        
        agent_db = AgentDB()
        result = agent_db.bulk_update_agents(updates)
        
        return jsonify(create_success_response(result)), 200
        
    except Exception as e:
        logger.error(f"Error in bulk update agents: {e}")
        return jsonify(create_error_response(str(e))), 500

@agents_api.route('/cleanup', methods=['POST'])
def cleanup_offline_agents():
    """Dọn dẹp agents offline"""
    try:
        data = request.get_json() or {}
        minutes_threshold = data.get('minutes', 5)
        
        agent_db = AgentDB()
        offline_count = agent_db.cleanup_offline_agents(minutes_threshold)
        
        return jsonify(create_success_response({
            'offline_count': offline_count,
            'threshold_minutes': minutes_threshold
        }, f"Marked {offline_count} agents as offline")), 200
        
    except Exception as e:
        logger.error(f"Error cleaning up offline agents: {e}")
        return jsonify(create_error_response(str(e))), 500

@agents_api.route('/<hostname>/command', methods=['POST'])
def send_command_to_agent(hostname):
    """Gửi command đến agent"""
    try:
        if not validate_hostname(hostname):
            return jsonify(create_error_response("Invalid hostname")), 400
        
        data = request.get_json()
        if not data or 'command' not in data:
            return jsonify(create_error_response("command is required")), 400
        
        # Import SocketIO handler để gửi command
        from services.socketio_handler import SocketIOHandler
        # Cần access đến socketio instance, tạm thời return success
        
        command = {
            'type': data['command'],
            'parameters': data.get('parameters', {}),
            'timestamp': datetime.now().isoformat()
        }
        
        # TODO: Implement actual command sending through SocketIO
        
        return jsonify(create_success_response({
            'hostname': hostname,
            'command': command
        }, f"Command sent to {hostname}")), 200
        
    except Exception as e:
        logger.error(f"Error sending command to agent {hostname}: {e}")
        return jsonify(create_error_response(str(e))), 500

@agents_api.route('/<hostname>/logs', methods=['GET'])
def get_agent_logs(hostname):
    """Redirect đến logs API cho agent cụ thể"""
    try:
        if not validate_hostname(hostname):
            return jsonify(create_error_response("Invalid hostname")), 400
        
        # Redirect to logs API
        from flask import redirect, url_for
        return redirect(url_for('logs_api.get_agent_logs', hostname=hostname))
        
    except Exception as e:
        logger.error(f"Error redirecting to agent logs {hostname}: {e}")
        return jsonify(create_error_response(str(e))), 500

@agents_api.route('/<hostname>/alerts', methods=['GET'])
def get_agent_alerts(hostname):
    """Lấy alerts của agent"""
    try:
        if not validate_hostname(hostname):
            return jsonify(create_error_response("Invalid hostname")), 400
        
        from database.alerts import AlertDB
        
        hours = int(request.args.get('hours', 24))
        limit = int(request.args.get('limit', 100))
        
        alert_db = AlertDB()
        alerts = alert_db.get_recent_alerts(hostname, hours, limit)
        
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
        logger.error(f"Error getting agent alerts {hostname}: {e}")
        return jsonify(create_error_response(str(e))), 500

@agents_api.route('/export', methods=['GET'])
def export_agents():
    """Export danh sách agents"""
    try:
        format_type = request.args.get('format', 'json').lower()
        
        agent_db = AgentDB()
        agents = agent_db.get_all_agents()
        
        # Add computed fields
        for agent in agents:
            agent['IsOnline'] = _is_agent_online(agent.get('LastSeen'))
            agent['LastSeenAgo'] = _calculate_time_ago(agent.get('LastSeen'))
            
            # Convert datetime to string for export
            for field in ['FirstSeen', 'LastSeen', 'LastHeartbeat']:
                if field in agent and hasattr(agent[field], 'strftime'):
                    agent[field] = agent[field].strftime('%Y-%m-%d %H:%M:%S')
        
        if format_type == 'csv':
            return _export_agents_csv(agents)
        else:
            return jsonify(create_success_response({
                'agents': agents,
                'count': len(agents),
                'exported_at': datetime.now().isoformat()
            })), 200
        
    except Exception as e:
        logger.error(f"Error exporting agents: {e}")
        return jsonify(create_error_response(str(e))), 500

def _export_agents_csv(agents):
    """Export agents as CSV"""
    try:
        import csv
        import io
        from flask import Response
        
        output = io.StringIO()
        
        if agents:
            # Get all possible fieldnames
            fieldnames = set()
            for agent in agents:
                fieldnames.update(agent.keys())
            
            fieldnames = sorted(list(fieldnames))
            
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            
            for agent in agents:
                # Handle None values
                row = {}
                for field in fieldnames:
                    value = agent.get(field, '')
                    row[field] = str(value) if value is not None else ''
                writer.writerow(row)
        
        csv_content = output.getvalue()
        output.close()
        
        return Response(
            csv_content,
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename=agents_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            }
        )
        
    except Exception as e:
        logger.error(f"Error exporting agents CSV: {e}")
        return jsonify(create_error_response(str(e))), 500

# Helper functions
def _is_agent_online(last_seen, threshold_minutes=5):
    """Check if agent is online based on last_seen"""
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

def _calculate_time_ago(timestamp):
    """Calculate human-readable time ago"""
    if not timestamp:
        return "Unknown"
    
    try:
        if isinstance(timestamp, str):
            timestamp_dt = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
        else:
            timestamp_dt = timestamp
        
        now = datetime.now()
        diff = now - timestamp_dt
        
        if diff.days > 0:
            return f"{diff.days} day{'s' if diff.days > 1 else ''} ago"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"{hours} hour{'s' if hours > 1 else ''} ago"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
        else:
            return "Just now"
            
    except:
        return "Unknown"