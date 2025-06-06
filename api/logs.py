from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
import logging
import json
from database.logs import LogDB
from database.agents import AgentDB

logs_api = Blueprint('logs_api', __name__, url_prefix='/logs')
logger = logging.getLogger(__name__)

@logs_api.route('', methods=['GET'])
def get_logs():
    """Get logs with filtering"""
    try:
        log_db = LogDB()
        
        # Extract filter parameters
        log_type = request.args.get('type', 'all')  # process, file, network, all
        hostname = request.args.get('hostname')
        from_time = request.args.get('from')
        to_time = request.args.get('to')
        hours = request.args.get('hours')  # Last N hours
        limit = int(request.args.get('limit', 100))
        
        # Build time filters
        filters = {}
        if hostname:
            filters['Hostname'] = hostname
        
        # Handle time range
        if hours:
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=int(hours))
            from_time = start_time.strftime('%Y-%m-%d %H:%M:%S')
            to_time = end_time.strftime('%Y-%m-%d %H:%M:%S')
        
        # Get logs based on type
        logs_result = {}
        
        if log_type in ['process', 'all']:
            logs_result['process'] = log_db.get_process_logs(
                hostname=hostname, 
                from_time=from_time, 
                to_time=to_time, 
                limit=limit
            )
        
        if log_type in ['file', 'all']:
            logs_result['file'] = log_db.get_file_logs(
                hostname=hostname, 
                from_time=from_time, 
                to_time=to_time, 
                limit=limit
            )
        
        if log_type in ['network', 'all']:
            logs_result['network'] = log_db.get_network_logs(
                hostname=hostname, 
                from_time=from_time, 
                to_time=to_time, 
                limit=limit
            )
        
        # Calculate totals
        total_count = sum(len(logs) for logs in logs_result.values())
        
        return jsonify({
            'status': 'success',
            'data': logs_result,
            'total_count': total_count,
            'filters': {
                'type': log_type,
                'hostname': hostname,
                'from_time': from_time,
                'to_time': to_time,
                'limit': limit
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting logs: {e}")
        return jsonify({'error': str(e)}), 500

@logs_api.route('/process', methods=['GET'])
def get_process_logs():
    """Get process logs specifically"""
    try:
        log_db = LogDB()
        
        hostname = request.args.get('hostname')
        from_time = request.args.get('from')
        to_time = request.args.get('to')
        limit = int(request.args.get('limit', 100))
        
        logs = log_db.get_process_logs(hostname, from_time, to_time, limit)
        
        return jsonify({
            'status': 'success',
            'data': logs,
            'count': len(logs),
            'type': 'process'
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting process logs: {e}")
        return jsonify({'error': str(e)}), 500

@logs_api.route('/file', methods=['GET'])
def get_file_logs():
    """Get file logs specifically"""
    try:
        log_db = LogDB()
        
        hostname = request.args.get('hostname')
        from_time = request.args.get('from')
        to_time = request.args.get('to')
        limit = int(request.args.get('limit', 100))
        
        logs = log_db.get_file_logs(hostname, from_time, to_time, limit)
        
        return jsonify({
            'status': 'success',
            'data': logs,
            'count': len(logs),
            'type': 'file'
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting file logs: {e}")
        return jsonify({'error': str(e)}), 500

@logs_api.route('/network', methods=['GET'])
def get_network_logs():
    """Get network logs specifically"""
    try:
        log_db = LogDB()
        
        hostname = request.args.get('hostname')
        from_time = request.args.get('from')
        to_time = request.args.get('to')
        limit = int(request.args.get('limit', 100))
        
        logs = log_db.get_network_logs(hostname, from_time, to_time, limit)
        
        return jsonify({
            'status': 'success',
            'data': logs,
            'count': len(logs),
            'type': 'network'
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting network logs: {e}")
        return jsonify({'error': str(e)}), 500

@logs_api.route('/stats', methods=['GET'])
def get_log_statistics():
    """Get log statistics"""
    try:
        log_db = LogDB()
        
        # Get parameters
        hours = int(request.args.get('hours', 24))
        hostname = request.args.get('hostname')
        
        # Calculate time range
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
        
        # Get log counts
        process_logs = log_db.get_process_logs(
            hostname=hostname,
            from_time=start_time.strftime('%Y-%m-%d %H:%M:%S'),
            to_time=end_time.strftime('%Y-%m-%d %H:%M:%S'),
            limit=10000
        )
        
        file_logs = log_db.get_file_logs(
            hostname=hostname,
            from_time=start_time.strftime('%Y-%m-%d %H:%M:%S'),
            to_time=end_time.strftime('%Y-%m-%d %H:%M:%S'),
            limit=10000
        )
        
        network_logs = log_db.get_network_logs(
            hostname=hostname,
            from_time=start_time.strftime('%Y-%m-%d %H:%M:%S'),
            to_time=end_time.strftime('%Y-%m-%d %H:%M:%S'),
            limit=10000
        )
        
        # Calculate statistics
        stats = {
            'total_logs': len(process_logs) + len(file_logs) + len(network_logs),
            'by_type': {
                'process': len(process_logs),
                'file': len(file_logs),
                'network': len(network_logs)
            },
            'time_range': {
                'start': start_time.isoformat(),
                'end': end_time.isoformat(),
                'hours': hours
            }
        }
        
        # Top processes
        process_counts = {}
        for log in process_logs:
            process_name = log.get('ProcessName', 'Unknown')
            process_counts[process_name] = process_counts.get(process_name, 0) + 1
        
        stats['top_processes'] = [
            {'name': name, 'count': count}
            for name, count in sorted(process_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        ]
        
        # Top files
        file_counts = {}
        for log in file_logs:
            file_name = log.get('FileName', 'Unknown')
            file_counts[file_name] = file_counts.get(file_name, 0) + 1
        
        stats['top_files'] = [
            {'name': name, 'count': count}
            for name, count in sorted(file_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        ]
        
        # Top network connections
        network_counts = {}
        for log in network_logs:
            remote_addr = log.get('RemoteAddress', 'Unknown')
            if remote_addr and remote_addr != 'Unknown':
                network_counts[remote_addr] = network_counts.get(remote_addr, 0) + 1
        
        stats['top_connections'] = [
            {'address': addr, 'count': count}
            for addr, count in sorted(network_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        ]
        
        return jsonify({
            'status': 'success',
            'data': stats
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting log statistics: {e}")
        return jsonify({'error': str(e)}), 500

@logs_api.route('/search', methods=['GET'])
def search_logs():
    """Search logs by keywords"""
    try:
        log_db = LogDB()
        
        # Get search parameters
        query = request.args.get('q', '').strip()
        log_type = request.args.get('type', 'all')
        hostname = request.args.get('hostname')
        limit = int(request.args.get('limit', 100))
        
        if not query:
            return jsonify({'error': 'Search query is required'}), 400
        
        search_results = {
            'query': query,
            'results': {},
            'total_matches': 0
        }
        
        # Search process logs
        if log_type in ['process', 'all']:
            process_logs = log_db.get_process_logs(hostname=hostname, limit=1000)
            process_matches = []
            
            for log in process_logs:
                searchable_text = ' '.join([
                    str(log.get('ProcessName', '')),
                    str(log.get('CommandLine', '')),
                    str(log.get('ExecutablePath', '')),
                    str(log.get('UserName', ''))
                ]).lower()
                
                if query.lower() in searchable_text:
                    process_matches.append(log)
            
            search_results['results']['process'] = process_matches[:limit]
            search_results['total_matches'] += len(process_matches)
        
        # Search file logs
        if log_type in ['file', 'all']:
            file_logs = log_db.get_file_logs(hostname=hostname, limit=1000)
            file_matches = []
            
            for log in file_logs:
                searchable_text = ' '.join([
                    str(log.get('FileName', '')),
                    str(log.get('FilePath', '')),
                    str(log.get('EventType', '')),
                    str(log.get('ProcessName', ''))
                ]).lower()
                
                if query.lower() in searchable_text:
                    file_matches.append(log)
            
            search_results['results']['file'] = file_matches[:limit]
            search_results['total_matches'] += len(file_matches)
        
        # Search network logs
        if log_type in ['network', 'all']:
            network_logs = log_db.get_network_logs(hostname=hostname, limit=1000)
            network_matches = []
            
            for log in network_logs:
                searchable_text = ' '.join([
                    str(log.get('ProcessName', '')),
                    str(log.get('RemoteAddress', '')),
                    str(log.get('Protocol', '')),
                    str(log.get('LocalAddress', ''))
                ]).lower()
                
                if query.lower() in searchable_text:
                    network_matches.append(log)
            
            search_results['results']['network'] = network_matches[:limit]
            search_results['total_matches'] += len(network_matches)
        
        return jsonify({
            'status': 'success',
            'data': search_results
        }), 200
        
    except Exception as e:
        logger.error(f"Error searching logs: {e}")
        return jsonify({'error': str(e)}), 500

@logs_api.route('/export', methods=['GET'])
def export_logs():
    """Export logs to CSV format"""
    try:
        log_db = LogDB()
        
        # Get parameters
        log_type = request.args.get('type', 'all')
        hostname = request.args.get('hostname')
        from_time = request.args.get('from')
        to_time = request.args.get('to')
        limit = int(request.args.get('limit', 1000))
        
        # Collect logs
        all_logs = []
        
        if log_type in ['process', 'all']:
            process_logs = log_db.get_process_logs(hostname, from_time, to_time, limit)
            for log in process_logs:
                log['LogType'] = 'Process'
                all_logs.append(log)
        
        if log_type in ['file', 'all']:
            file_logs = log_db.get_file_logs(hostname, from_time, to_time, limit)
            for log in file_logs:
                log['LogType'] = 'File'
                all_logs.append(log)
        
        if log_type in ['network', 'all']:
            network_logs = log_db.get_network_logs(hostname, from_time, to_time, limit)
            for log in network_logs:
                log['LogType'] = 'Network'
                all_logs.append(log)
        
        # Sort by time
        all_logs.sort(key=lambda x: x.get('Time', ''), reverse=True)
        
        # Create CSV content
        import csv
        import io
        
        output = io.StringIO()
        
        if all_logs:
            # Get all possible fieldnames
            fieldnames = set()
            for log in all_logs:
                fieldnames.update(log.keys())
            
            fieldnames = sorted(list(fieldnames))
            
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            
            for log in all_logs:
                # Convert any complex data to strings
                row = {}
                for field in fieldnames:
                    value = log.get(field, '')
                    if isinstance(value, (dict, list)):
                        row[field] = json.dumps(value)
                    else:
                        row[field] = str(value) if value is not None else ''
                writer.writerow(row)
        
        csv_content = output.getvalue()
        output.close()
        
        # Return CSV as download
        from flask import Response
        return Response(
            csv_content,
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename=edr_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            }
        )
        
    except Exception as e:
        logger.error(f"Error exporting logs: {e}")
        return jsonify({'error': str(e)}), 500

@logs_api.route('/agents/<hostname>', methods=['GET'])
def get_agent_logs(hostname):
    """Get all logs for a specific agent"""
    try:
        # Verify agent exists
        agent_db = AgentDB()
        agent = agent_db.get_agent(hostname)
        if not agent:
            return jsonify({'error': 'Agent not found'}), 404
        
        log_db = LogDB()
        
        # Get parameters
        hours = int(request.args.get('hours', 24))
        limit = int(request.args.get('limit', 500))
        
        # Calculate time range
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
        from_time = start_time.strftime('%Y-%m-%d %H:%M:%S')
        to_time = end_time.strftime('%Y-%m-%d %H:%M:%S')
        
        # Get all types of logs
        logs_data = {
            'process': log_db.get_process_logs(hostname, from_time, to_time, limit),
            'file': log_db.get_file_logs(hostname, from_time, to_time, limit),
            'network': log_db.get_network_logs(hostname, from_time, to_time, limit)
        }
        
        # Calculate summary
        total_logs = sum(len(logs) for logs in logs_data.values())
        
        # Recent activity
        all_logs = []
        for log_type, logs in logs_data.items():
            for log in logs:
                log['log_type'] = log_type
                all_logs.append(log)
        
        # Sort by time
        all_logs.sort(key=lambda x: x.get('Time', ''), reverse=True)
        
        return jsonify({
            'status': 'success',
            'data': {
                'agent': {
                    'hostname': hostname,
                    'os_type': agent.get('OSType'),
                    'status': agent.get('Status'),
                    'last_seen': agent.get('LastSeen')
                },
                'logs': logs_data,
                'recent_activity': all_logs[:50],  # 50 most recent
                'summary': {
                    'total_logs': total_logs,
                    'by_type': {
                        'process': len(logs_data['process']),
                        'file': len(logs_data['file']),
                        'network': len(logs_data['network'])
                    },
                    'time_range': {
                        'hours': hours,
                        'from': from_time,
                        'to': to_time
                    }
                }
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting agent logs for {hostname}: {e}")
        return jsonify({'error': str(e)}), 500

@logs_api.route('/cleanup', methods=['POST'])
def cleanup_old_logs():
    """Clean up old logs"""
    try:
        data = request.get_json() or {}
        days = data.get('days', 30)
        
        log_db = LogDB()
        success = log_db.cleanup_old_logs(days)
        
        if success:
            return jsonify({
                'status': 'success',
                'message': f'Cleaned up logs older than {days} days'
            }), 200
        else:
            return jsonify({'error': 'Failed to cleanup logs'}), 500
            
    except Exception as e:
        logger.error(f"Error cleaning up logs: {e}")
        return jsonify({'error': str(e)}), 500

@logs_api.route('/recent', methods=['GET'])
def get_recent_logs():
    """Get recent logs across all agents"""
    try:
        log_db = LogDB()
        
        # Get parameters
        hours = int(request.args.get('hours', 1))
        limit = int(request.args.get('limit', 100))
        log_type = request.args.get('type', 'all')
        
        # Calculate time range
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
        from_time = start_time.strftime('%Y-%m-%d %H:%M:%S')
        to_time = end_time.strftime('%Y-%m-%d %H:%M:%S')
        
        recent_logs = []
        
        # Collect recent logs
        if log_type in ['process', 'all']:
            process_logs = log_db.get_process_logs(from_time=from_time, to_time=to_time, limit=limit)
            for log in process_logs:
                log['log_type'] = 'process'
                recent_logs.append(log)
        
        if log_type in ['file', 'all']:
            file_logs = log_db.get_file_logs(from_time=from_time, to_time=to_time, limit=limit)
            for log in file_logs:
                log['log_type'] = 'file'
                recent_logs.append(log)
        
        if log_type in ['network', 'all']:
            network_logs = log_db.get_network_logs(from_time=from_time, to_time=to_time, limit=limit)
            for log in network_logs:
                log['log_type'] = 'network'
                recent_logs.append(log)
        
        # Sort by time and limit
        recent_logs.sort(key=lambda x: x.get('Time', ''), reverse=True)
        recent_logs = recent_logs[:limit]
        
        # Add time ago information
        for log in recent_logs:
            if log.get('Time'):
                try:
                    log_time = datetime.strptime(log['Time'], '%Y-%m-%d %H:%M:%S')
                    time_diff = datetime.now() - log_time
                    log['minutes_ago'] = int(time_diff.total_seconds() / 60)
                except:
                    log['minutes_ago'] = None
        
        return jsonify({
            'status': 'success',
            'data': recent_logs,
            'count': len(recent_logs),
            'filters': {
                'hours': hours,
                'limit': limit,
                'type': log_type
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting recent logs: {e}")
        return jsonify({'error': str(e)}), 500