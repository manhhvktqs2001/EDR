"""
SocketIO Event Handler cho EDR Server
Xử lý tất cả các sự kiện SocketIO từ agents
"""

import time
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from flask_socketio import emit, disconnect
from flask import request

from database.agents import AgentDB
from database.logs import LogDB
from database.alerts import AlertDB
from rules.rule_engine import RuleEngine
from utils.helpers import (
    validate_hostname, sanitize_string, generate_unique_id,
    filter_sensitive_data, calculate_time_ago, safe_int
)
from utils.logger import socketio_logger, log_agent_activity, log_security_event

class SocketIOHandler:
    def __init__(self, socketio):
        self.socketio = socketio
        self.connected_agents = {}  # {sid: agent_info}
        self.agent_db = AgentDB()
        self.log_db = LogDB()
        self.alert_db = AlertDB()
        self.rule_engine = RuleEngine()
        self.logger = logging.getLogger(__name__)
        
    def register_handlers(self):
        """Đăng ký tất cả SocketIO event handlers"""
        self.socketio.on_event('connect', self.handle_connect)
        self.socketio.on_event('disconnect', self.handle_disconnect)
        self.socketio.on_event('register', self.handle_register)
        self.socketio.on_event('heartbeat', self.handle_heartbeat)
        self.socketio.on_event('process_logs', self.handle_process_logs)
        self.socketio.on_event('file_logs', self.handle_file_logs)
        self.socketio.on_event('network_logs', self.handle_network_logs)
        self.socketio.on_event('agent_status', self.handle_agent_status)
        self.socketio.on_event('response_action', self.handle_response_action)
        
        self.logger.info("SocketIO event handlers registered")
    
    def handle_connect(self):
        """Xử lý kết nối agent"""
        try:
            sid = request.sid
            client_ip = request.environ.get('REMOTE_ADDR', 'unknown')
            
            # Lưu thông tin connection
            self.connected_agents[sid] = {
                'hostname': None,
                'connected_at': time.time(),
                'last_seen': time.time(),
                'client_ip': client_ip,
                'status': 'connected'
            }
            
            socketio_logger.info('agent_connect', f'Agent connected from {client_ip}', 
                               sid=sid, client_ip=client_ip)
            
            emit('connect_response', {
                'status': 'connected',
                'sid': sid,
                'server_time': datetime.now().isoformat(),
                'message': 'Connected to EDR Server'
            })
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error handling connect: {e}")
            emit('error', {'message': 'Connection failed'})
            return False
    
    def handle_disconnect(self):
        """Xử lý ngắt kết nối agent"""
        try:
            sid = request.sid
            agent_info = self.connected_agents.pop(sid, {})
            hostname = agent_info.get('hostname')
            
            if hostname:
                # Cập nhật trạng thái agent trong database
                self.agent_db.update_agent_status(hostname, 'Offline')
                
                log_agent_activity(hostname, 'disconnected', {
                    'connection_duration': time.time() - agent_info.get('connected_at', 0),
                    'client_ip': agent_info.get('client_ip')
                })
                
                socketio_logger.info('agent_disconnect', f'Agent {hostname} disconnected',
                                   hostname=hostname, sid=sid)
            else:
                socketio_logger.info('unknown_disconnect', 'Unknown agent disconnected',
                                   sid=sid)
                
        except Exception as e:
            self.logger.error(f"Error handling disconnect: {e}")
    
    def handle_register(self, data):
        """Xử lý đăng ký agent"""
        try:
            sid = request.sid
            
            # Validate dữ liệu đăng ký
            validation_result = self._validate_registration_data(data)
            if not validation_result['valid']:
                emit('error', {'message': validation_result['error']})
                return False
            
            hostname = data['hostname']
            
            # Kiểm tra hostname đã được sử dụng bởi agent khác
            if self._is_hostname_in_use(hostname, sid):
                emit('error', {'message': f'Hostname {hostname} already in use'})
                return False
            
            # Đăng ký agent trong database
            success = self.agent_db.register_agent(data)
            if not success:
                emit('error', {'message': 'Failed to register agent in database'})
                return False
            
            # Cập nhật thông tin connection
            self.connected_agents[sid].update({
                'hostname': hostname,
                'os_type': data.get('os_type', 'Unknown'),
                'agent_version': data.get('agent_version', '1.0.0'),
                'last_seen': time.time()
            })
            
            # Log hoạt động
            log_agent_activity(hostname, 'registered', {
                'os_type': data.get('os_type'),
                'agent_version': data.get('agent_version'),
                'ip_address': data.get('ip_address')
            })
            
            # Gửi phản hồi thành công
            emit('register_response', {
                'status': 'success',
                'message': f'Agent {hostname} registered successfully',
                'hostname': hostname,
                'server_time': datetime.now().isoformat(),
                'config': self._get_agent_config(hostname)
            })
            
            socketio_logger.info('agent_register', f'Agent {hostname} registered successfully',
                                hostname=hostname, os_type=data.get('os_type'))
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error handling registration: {e}")
            emit('error', {'message': f'Registration failed: {str(e)}'})
            return False
    
    def handle_heartbeat(self, data=None):
        """Xử lý heartbeat từ agent"""
        try:
            sid = request.sid
            
            if sid not in self.connected_agents:
                emit('error', {'message': 'Agent not registered'})
                return
            
            # Cập nhật last_seen
            self.connected_agents[sid]['last_seen'] = time.time()
            hostname = self.connected_agents[sid].get('hostname')
            
            if hostname:
                # Cập nhật heartbeat trong database
                self.agent_db.update_heartbeat(hostname)
                
                # Gửi phản hồi heartbeat
                response_data = {
                    'status': 'alive',
                    'server_time': datetime.now().isoformat(),
                    'timestamp': time.time()
                }
                
                # Thêm thông tin bổ sung nếu có
                if data and isinstance(data, dict):
                    system_info = data.get('system_info', {})
                    if system_info:
                        response_data['system_status'] = 'received'
                
                emit('heartbeat_response', response_data)
                
                self.logger.debug(f"Heartbeat received from {hostname}")
            else:
                emit('heartbeat_response', {
                    'status': 'alive',
                    'server_time': datetime.now().isoformat(),
                    'timestamp': time.time()
                })
                
        except Exception as e:
            self.logger.error(f"Error handling heartbeat: {e}")
    
    def handle_process_logs(self, data):
        """Xử lý process logs từ agent"""
        try:
            result = self._handle_logs('process', data)
            emit('log_response', result)
            
        except Exception as e:
            self.logger.error(f"Error handling process logs: {e}")
            emit('error', {'message': 'Error processing process logs'})
    
    def handle_file_logs(self, data):
        """Xử lý file logs từ agent"""
        try:
            result = self._handle_logs('file', data)
            emit('log_response', result)
            
        except Exception as e:
            self.logger.error(f"Error handling file logs: {e}")
            emit('error', {'message': 'Error processing file logs'})
    
    def handle_network_logs(self, data):
        """Xử lý network logs từ agent"""
        try:
            result = self._handle_logs('network', data)
            emit('log_response', result)
            
        except Exception as e:
            self.logger.error(f"Error handling network logs: {e}")
            emit('error', {'message': 'Error processing network logs'})
    
    def handle_agent_status(self, data):
        """Xử lý cập nhật trạng thái agent"""
        try:
            sid = request.sid
            hostname = self.connected_agents.get(sid, {}).get('hostname')
            
            if not hostname:
                emit('error', {'message': 'Agent not registered'})
                return
            
            status = data.get('status', 'Online')
            details = data.get('details', {})
            
            # Cập nhật trạng thái trong database
            success = self.agent_db.update_agent_status(hostname, status)
            
            if success:
                log_agent_activity(hostname, 'status_update', {
                    'new_status': status,
                    'details': details
                })
                
                emit('status_response', {
                    'status': 'success',
                    'message': f'Status updated to {status}'
                })
            else:
                emit('error', {'message': 'Failed to update status'})
                
        except Exception as e:
            self.logger.error(f"Error handling agent status: {e}")
            emit('error', {'message': 'Error updating agent status'})
    
    def handle_response_action(self, data):
        """Xử lý phản hồi action từ agent"""
        try:
            sid = request.sid
            hostname = self.connected_agents.get(sid, {}).get('hostname')
            
            if not hostname:
                emit('error', {'message': 'Agent not registered'})
                return
            
            action_id = data.get('action_id')
            result = data.get('result')
            details = data.get('details', {})
            
            log_agent_activity(hostname, 'action_response', {
                'action_id': action_id,
                'result': result,
                'details': details
            })
            
            socketio_logger.info('action_response', f'Action response from {hostname}',
                                hostname=hostname, action_id=action_id, result=result)
            
            emit('response_acknowledged', {
                'status': 'success',
                'message': 'Action response received'
            })
            
        except Exception as e:
            self.logger.error(f"Error handling response action: {e}")
            emit('error', {'message': 'Error processing action response'})
    
    def _handle_logs(self, log_type: str, data: Dict) -> Dict:
        """Xử lý logs chung cho tất cả loại"""
        try:
            sid = request.sid
            hostname = self.connected_agents.get(sid, {}).get('hostname')
            
            if not hostname:
                return {'status': 'error', 'message': 'Agent not registered'}
            
            # Validate dữ liệu log
            if not isinstance(data, dict) or 'logs' not in data:
                return {'status': 'error', 'message': 'Invalid log data format'}
            
            logs = data['logs']
            if not isinstance(logs, list):
                return {'status': 'error', 'message': 'Logs must be a list'}
            
            processed_count = 0
            alerts_generated = 0
            
            for log in logs:
                try:
                    # Thêm hostname vào log
                    if 'Hostname' not in log:
                        log['Hostname'] = hostname
                    
                    # Lọc dữ liệu nhạy cảm
                    log = filter_sensitive_data(log)
                    
                    # Lưu log vào database
                    if self.log_db.process_log(log_type, log):
                        processed_count += 1
                        
                        # Kiểm tra rules
                        if self._check_rules_and_create_alert(log_type, log, hostname):
                            alerts_generated += 1
                    
                except Exception as e:
                    self.logger.error(f"Error processing individual {log_type} log: {e}")
                    continue
            
            # Log thống kê
            socketio_logger.info('logs_processed', 
                               f'Processed {processed_count}/{len(logs)} {log_type} logs from {hostname}',
                               hostname=hostname, log_type=log_type, 
                               processed=processed_count, total=len(logs),
                               alerts_generated=alerts_generated)
            
            return {
                'status': 'success',
                'processed': processed_count,
                'total': len(logs),
                'alerts_generated': alerts_generated,
                'message': f'Processed {processed_count} {log_type} logs'
            }
            
        except Exception as e:
            self.logger.error(f"Error handling {log_type} logs: {e}")
            return {'status': 'error', 'message': f'Error processing {log_type} logs'}
    
    def _check_rules_and_create_alert(self, log_type: str, log_data: Dict, hostname: str) -> bool:
        """Kiểm tra rules và tạo alert nếu vi phạm"""
        try:
            # Kiểm tra rules
            violation = self.rule_engine.check_rules(
                log_type.upper() + '_LOGS', 
                log_data, 
                hostname
            )
            
            if not violation[0]:  # Không có vi phạm
                return False
            
            rule_violated, description, detection_data, severity, rule_id, action = violation
            
            # Tạo alert data
            alert_data = {
                'hostname': hostname,
                'rule_id': rule_id,
                'alert_type': f'{log_type.title()} Violation',
                'severity': severity,
                'title': self._generate_alert_title(log_type, log_data),
                'description': description,
                'detection_data': detection_data,
                'action': action
            }
            
            # Lưu alert vào database
            alert_success = self.alert_db.create_alert(alert_data)
            
            if alert_success:
                # Gửi alert đến agent
                self._send_alert_to_agent(hostname, {
                    'type': f'{log_type}_violation',
                    'severity': severity,
                    'title': alert_data['title'],
                    'message': description,
                    'action': action,
                    'timestamp': datetime.now().isoformat(),
                    'rule_id': rule_id,
                    'alert_id': generate_unique_id(),
                    **self._extract_alert_context(log_type, log_data)
                })
                
                # Log security event
                log_security_event(
                    event_type=f'{log_type}_rule_violation',
                    severity=severity,
                    description=f'{log_type.title()} rule violation: {description}',
                    hostname=hostname,
                    details={
                        'rule_id': rule_id,
                        'action': action,
                        'log_type': log_type
                    }
                )
                
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking rules for {log_type} log: {e}")
            return False
    
    def _send_alert_to_agent(self, hostname: str, alert_data: Dict):
        """Gửi alert đến agent cụ thể"""
        try:
            # Tìm SID của agent
            agent_sid = self._get_agent_sid_by_hostname(hostname)
            
            if agent_sid:
                self.socketio.emit('alert_notification', alert_data, room=agent_sid)
                socketio_logger.info('alert_sent', f'Alert sent to agent {hostname}',
                                   hostname=hostname, alert_type=alert_data.get('type'))
            else:
                self.logger.warning(f"Agent {hostname} not connected, cannot send alert")
                
        except Exception as e:
            self.logger.error(f"Error sending alert to agent {hostname}: {e}")
    
    def _validate_registration_data(self, data: Dict) -> Dict:
        """Validate dữ liệu đăng ký agent"""
        if not isinstance(data, dict):
            return {'valid': False, 'error': 'Data must be a dictionary'}
        
        # Extract hostname với nhiều tên field có thể
        hostname_fields = ['hostname', 'Hostname', 'host', 'computer_name']
        hostname = None
        for field in hostname_fields:
            if field in data and data[field]:
                hostname = data[field]
                break
        
        if not hostname:
            return {'valid': False, 'error': 'Hostname is required'}
        
        if not validate_hostname(hostname):
            return {'valid': False, 'error': 'Invalid hostname format'}
        
        # Kiểm tra OS type
        os_type_fields = ['os_type', 'OSType', 'operating_system', 'platform']
        os_type = None
        for field in os_type_fields:
            if field in data and data[field]:
                os_type = data[field]
                break
        
        if not os_type:
            return {'valid': False, 'error': 'OS type is required'}
        
        # Validate OS type
        valid_os_types = ['Windows', 'Linux', 'macOS', 'Unknown']
        if os_type not in valid_os_types:
            return {'valid': False, 'error': f'Invalid OS type. Must be one of: {valid_os_types}'}
        
        # Normalize hostname trong data
        data['hostname'] = sanitize_string(hostname)
        data['os_type'] = os_type
        
        return {'valid': True, 'error': None}
    
    def _is_hostname_in_use(self, hostname: str, current_sid: str) -> bool:
        """Kiểm tra hostname đã được sử dụng bởi agent khác"""
        for sid, agent_info in self.connected_agents.items():
            if sid != current_sid and agent_info.get('hostname') == hostname:
                return True
        return False
    
    def _get_agent_config(self, hostname: str) -> Dict:
        """Lấy cấu hình cho agent"""
        try:
            # Lấy rules áp dụng cho agent này
            agent = self.agent_db.get_agent(hostname)
            if not agent:
                return {}
            
            os_type = agent.get('OSType', 'Unknown')
            
            # Lấy rules từ rule engine hoặc database
            # Tạm thời trả về config cơ bản
            return {
                'heartbeat_interval': 30,  # seconds
                'log_batch_size': 50,
                'log_send_interval': 60,  # seconds
                'monitoring_enabled': True,
                'rules_last_updated': datetime.now().isoformat(),
                'server_capabilities': {
                    'real_time_monitoring': True,
                    'file_quarantine': True,
                    'process_termination': True,
                    'network_blocking': True
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error getting agent config for {hostname}: {e}")
            return {}
    
    def _get_agent_sid_by_hostname(self, hostname: str) -> Optional[str]:
        """Lấy SID của agent theo hostname"""
        for sid, agent_info in self.connected_agents.items():
            if agent_info.get('hostname') == hostname:
                return sid
        return None
    
    def _generate_alert_title(self, log_type: str, log_data: Dict) -> str:
        """Tạo tiêu đề alert dựa trên log type và data"""
        try:
            if log_type == 'process':
                process_name = log_data.get('ProcessName', 'Unknown Process')
                return f'Suspicious Process Activity: {process_name}'
            
            elif log_type == 'file':
                file_name = log_data.get('FileName', 'Unknown File')
                event_type = log_data.get('EventType', 'Activity')
                return f'Suspicious File {event_type}: {file_name}'
            
            elif log_type == 'network':
                remote_addr = log_data.get('RemoteAddress', 'Unknown')
                remote_port = log_data.get('RemotePort', '')
                if remote_port:
                    return f'Suspicious Network Connection: {remote_addr}:{remote_port}'
                else:
                    return f'Suspicious Network Connection: {remote_addr}'
            
            else:
                return f'Security Alert: {log_type.title()} Activity'
                
        except Exception as e:
            self.logger.error(f"Error generating alert title: {e}")
            return f'Security Alert: {log_type.title()} Activity'
    
    def _extract_alert_context(self, log_type: str, log_data: Dict) -> Dict:
        """Extract context data cho alert"""
        context = {}
        
        try:
            if log_type == 'process':
                context.update({
                    'process_name': log_data.get('ProcessName', ''),
                    'process_id': safe_int(log_data.get('ProcessID', 0)),
                    'command_line': log_data.get('CommandLine', ''),
                    'executable_path': log_data.get('ExecutablePath', ''),
                    'parent_process_id': safe_int(log_data.get('ParentProcessID', 0)),
                    'user_name': log_data.get('UserName', '')
                })
            
            elif log_type == 'file':
                context.update({
                    'file_name': log_data.get('FileName', ''),
                    'file_path': log_data.get('FilePath', ''),
                    'event_type': log_data.get('EventType', ''),
                    'file_size': safe_int(log_data.get('FileSize', 0)),
                    'process_name': log_data.get('ProcessName', ''),
                    'process_id': safe_int(log_data.get('ProcessID', 0))
                })
            
            elif log_type == 'network':
                context.update({
                    'process_name': log_data.get('ProcessName', ''),
                    'process_id': safe_int(log_data.get('ProcessID', 0)),
                    'protocol': log_data.get('Protocol', ''),
                    'local_address': log_data.get('LocalAddress', ''),
                    'local_port': safe_int(log_data.get('LocalPort', 0)),
                    'remote_address': log_data.get('RemoteAddress', ''),
                    'remote_port': safe_int(log_data.get('RemotePort', 0)),
                    'direction': log_data.get('Direction', '')
                })
            
        except Exception as e:
            self.logger.error(f"Error extracting alert context: {e}")
        
        return context
    
    def send_command_to_agent(self, hostname: str, command: Dict) -> bool:
        """Gửi command đến agent cụ thể"""
        try:
            agent_sid = self._get_agent_sid_by_hostname(hostname)
            
            if not agent_sid:
                self.logger.warning(f"Agent {hostname} not connected")
                return False
            
            # Thêm command ID để tracking
            command['command_id'] = generate_unique_id()
            command['timestamp'] = datetime.now().isoformat()
            
            # Gửi command
            self.socketio.emit('command', command, room=agent_sid)
            
            # Log command
            log_agent_activity(hostname, 'command_sent', {
                'command_id': command['command_id'],
                'command_type': command.get('type'),
                'command_details': command
            })
            
            socketio_logger.info('command_sent', f'Command sent to agent {hostname}',
                               hostname=hostname, command_id=command['command_id'],
                               command_type=command.get('type'))
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending command to agent {hostname}: {e}")
            return False
    
    def broadcast_message(self, message: Dict, agent_filter: Dict = None):
        """Broadcast message đến tất cả hoặc một số agents"""
        try:
            message['timestamp'] = datetime.now().isoformat()
            message['broadcast_id'] = generate_unique_id()
            
            if not agent_filter:
                # Broadcast đến tất cả agents
                self.socketio.emit('broadcast', message)
                socketio_logger.info('broadcast_all', 'Message broadcasted to all agents',
                                   message_type=message.get('type'))
            else:
                # Broadcast có điều kiện
                sent_count = 0
                for sid, agent_info in self.connected_agents.items():
                    if self._agent_matches_filter(agent_info, agent_filter):
                        self.socketio.emit('broadcast', message, room=sid)
                        sent_count += 1
                
                socketio_logger.info('broadcast_filtered', 
                                   f'Message broadcasted to {sent_count} agents',
                                   message_type=message.get('type'), 
                                   sent_count=sent_count, filter=agent_filter)
            
        except Exception as e:
            self.logger.error(f"Error broadcasting message: {e}")
    
    def _agent_matches_filter(self, agent_info: Dict, filter_criteria: Dict) -> bool:
        """Kiểm tra agent có match với filter criteria"""
        try:
            for key, value in filter_criteria.items():
                if key == 'os_type' and agent_info.get('os_type') != value:
                    return False
                elif key == 'hostname' and agent_info.get('hostname') != value:
                    return False
                elif key == 'agent_version' and agent_info.get('agent_version') != value:
                    return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error matching agent filter: {e}")
            return False
    
    def get_connected_agents_summary(self) -> Dict:
        """Lấy thống kê agents đang kết nối"""
        try:
            summary = {
                'total_connected': len(self.connected_agents),
                'by_os_type': {},
                'by_status': {},
                'agents': []
            }
            
            for sid, agent_info in self.connected_agents.items():
                # Thống kê theo OS
                os_type = agent_info.get('os_type', 'Unknown')
                summary['by_os_type'][os_type] = summary['by_os_type'].get(os_type, 0) + 1
                
                # Thống kê theo status
                status = agent_info.get('status', 'Unknown')
                summary['by_status'][status] = summary['by_status'].get(status, 0) + 1
                
                # Thêm thông tin agent
                agent_summary = {
                    'hostname': agent_info.get('hostname'),
                    'os_type': os_type,
                    'agent_version': agent_info.get('agent_version'),
                    'connected_at': agent_info.get('connected_at'),
                    'last_seen': agent_info.get('last_seen'),
                    'client_ip': agent_info.get('client_ip'),
                    'connection_duration': time.time() - agent_info.get('connected_at', 0)
                }
                summary['agents'].append(agent_summary)
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Error getting connected agents summary: {e}")
            return {'total_connected': 0, 'by_os_type': {}, 'by_status': {}, 'agents': []}
    
    def cleanup_stale_connections(self, timeout_seconds: int = 300):
        """Dọn dẹp các kết nối cũ"""
        try:
            current_time = time.time()
            stale_sids = []
            
            for sid, agent_info in self.connected_agents.items():
                last_seen = agent_info.get('last_seen', 0)
                if current_time - last_seen > timeout_seconds:
                    stale_sids.append(sid)
            
            # Disconnect các connection cũ
            for sid in stale_sids:
                agent_info = self.connected_agents.pop(sid, {})
                hostname = agent_info.get('hostname')
                
                if hostname:
                    self.agent_db.update_agent_status(hostname, 'Offline')
                    socketio_logger.warning('stale_connection_cleanup',
                                          f'Cleaned up stale connection for {hostname}',
                                          hostname=hostname, sid=sid)
            
            if stale_sids:
                self.logger.info(f"Cleaned up {len(stale_sids)} stale connections")
            
            return len(stale_sids)
            
        except Exception as e:
            self.logger.error(f"Error cleaning up stale connections: {e}")
            return 0
    
    def cleanup(self):
        """Cleanup resources"""
        try:
            # Cập nhật tất cả agents đang connect thành offline
            for sid, agent_info in self.connected_agents.items():
                hostname = agent_info.get('hostname')
                if hostname:
                    self.agent_db.update_agent_status(hostname, 'Offline')
            
            self.connected_agents.clear()
            self.logger.info("SocketIO handler cleanup completed")
            
        except Exception as e:
            self.logger.error(f"Error during SocketIO cleanup: {e}")