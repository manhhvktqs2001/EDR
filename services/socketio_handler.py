"""
Enhanced SocketIO Event Handler cho EDR Server
Cải thiện performance, security và real-time capabilities
"""

import time
import json
import logging
import asyncio
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
from collections import defaultdict, deque
from dataclasses import dataclass
from flask_socketio import emit, disconnect, join_room, leave_room
from flask import request
import threading
from concurrent.futures import ThreadPoolExecutor
import queue

from database.agents import AgentDB
from database.logs import LogDB
from database.alerts import AlertDB
from rules.rule_engine import RuleEngine
from utils.helpers import (
    validate_hostname, sanitize_string, generate_unique_id,
    filter_sensitive_data, calculate_time_ago, safe_int
)
from utils.logger import socketio_logger, log_agent_activity, log_security_event

@dataclass
class AgentConnection:
    """Enhanced agent connection tracking"""
    hostname: str
    sid: str
    os_type: str
    agent_version: str
    ip_address: str
    connected_at: float
    last_seen: float
    last_heartbeat: float
    status: str
    room: str
    metrics: Dict[str, Any]
    pending_commands: queue.Queue
    
    def __post_init__(self):
        if not hasattr(self, 'pending_commands'):
            self.pending_commands = queue.Queue(maxsize=100)

@dataclass
class LogBatch:
    """Log batch for efficient processing"""
    hostname: str
    log_type: str
    logs: List[Dict]
    timestamp: float
    batch_id: str

class ConnectionPool:
    """Manage agent connections efficiently"""
    
    def __init__(self):
        self.connections: Dict[str, AgentConnection] = {}  # sid -> connection
        self.hostname_to_sid: Dict[str, str] = {}  # hostname -> sid
        self.rooms: Dict[str, Set[str]] = defaultdict(set)  # room -> sids
        self.lock = threading.RLock()
        
        # Performance metrics
        self.metrics = {
            'total_connections': 0,
            'active_connections': 0,
            'failed_connections': 0,
            'messages_processed': 0,
            'avg_response_time': 0.0
        }
    
    def add_connection(self, connection: AgentConnection) -> bool:
        """Add new connection"""
        try:
            with self.lock:
                # Check if hostname already connected
                if connection.hostname in self.hostname_to_sid:
                    old_sid = self.hostname_to_sid[connection.hostname]
                    if old_sid in self.connections:
                        # Disconnect old connection
                        self.remove_connection(old_sid)
                
                self.connections[connection.sid] = connection
                self.hostname_to_sid[connection.hostname] = connection.sid
                self.rooms[connection.room].add(connection.sid)
                
                self.metrics['total_connections'] += 1
                self.metrics['active_connections'] = len(self.connections)
                
                return True
                
        except Exception as e:
            logging.error(f"Error adding connection: {e}")
            return False
    
    def remove_connection(self, sid: str) -> Optional[AgentConnection]:
        """Remove connection"""
        try:
            with self.lock:
                if sid not in self.connections:
                    return None
                
                connection = self.connections[sid]
                
                # Clean up mappings
                del self.connections[sid]
                if connection.hostname in self.hostname_to_sid:
                    del self.hostname_to_sid[connection.hostname]
                
                # Remove from rooms
                for room_sids in self.rooms.values():
                    room_sids.discard(sid)
                
                self.metrics['active_connections'] = len(self.connections)
                
                return connection
                
        except Exception as e:
            logging.error(f"Error removing connection: {e}")
            return None
    
    def get_connection_by_hostname(self, hostname: str) -> Optional[AgentConnection]:
        """Get connection by hostname"""
        with self.lock:
            sid = self.hostname_to_sid.get(hostname)
            return self.connections.get(sid) if sid else None
    
    def get_connection_by_sid(self, sid: str) -> Optional[AgentConnection]:
        """Get connection by session ID"""
        with self.lock:
            return self.connections.get(sid)
    
    def get_all_connections(self) -> List[AgentConnection]:
        """Get all active connections"""
        with self.lock:
            return list(self.connections.values())
    
    def update_heartbeat(self, sid: str) -> bool:
        """Update connection heartbeat"""
        try:
            with self.lock:
                if sid in self.connections:
                    self.connections[sid].last_heartbeat = time.time()
                    self.connections[sid].last_seen = time.time()
                    return True
                return False
        except Exception as e:
            logging.error(f"Error updating heartbeat: {e}")
            return False

class EnhancedSocketIOHandler:
    """Enhanced SocketIO handler with improved performance and features"""
    
    def __init__(self, socketio):
        self.socketio = socketio
        self.connection_pool = ConnectionPool()
        
        # Database connections
        self.agent_db = AgentDB()
        self.log_db = LogDB()
        self.alert_db = AlertDB()
        self.rule_engine = RuleEngine()
        self.logger = logging.getLogger(__name__)
        
        # Performance optimization
        self.log_processor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="LogProcessor")
        self.log_queue = queue.Queue(maxsize=10000)
        self.batch_size = 50
        self.batch_timeout = 5.0  # seconds
        
        # Security features
        self.failed_attempts = defaultdict(int)
        self.blocked_ips = set()
        self.suspicious_activity = defaultdict(list)
        
        # Real-time features
        self.alert_subscribers = set()  # SIDs subscribed to alerts
        self.dashboard_subscribers = set()  # SIDs for dashboard updates
        
        # Background tasks
        self._start_background_tasks()
    
    def _start_background_tasks(self):
        """Start background processing tasks"""
        # Log batch processor
        self.log_batch_thread = threading.Thread(
            target=self._process_log_batches,
            daemon=True,
            name="LogBatchProcessor"
        )
        self.log_batch_thread.start()
        
        # Connection cleanup
        self.cleanup_thread = threading.Thread(
            target=self._cleanup_stale_connections,
            daemon=True,
            name="ConnectionCleanup"
        )
        self.cleanup_thread.start()
        
        # Metrics collection
        self.metrics_thread = threading.Thread(
            target=self._collect_metrics,
            daemon=True,
            name="MetricsCollector"
        )
        self.metrics_thread.start()
    
    def register_handlers(self):
        """Register all SocketIO event handlers"""
        try:
            self.socketio.on_event('connect', self.handle_connect)
            self.socketio.on_event('disconnect', self.handle_disconnect)
            self.socketio.on_event('register', self.handle_register)
            self.socketio.on_event('heartbeat', self.handle_heartbeat)
            self.socketio.on_event('process_logs', self.handle_process_logs)
            self.socketio.on_event('file_logs', self.handle_file_logs)
            self.socketio.on_event('network_logs', self.handle_network_logs)
            self.socketio.on_event('bulk_logs', self.handle_bulk_logs)
            self.socketio.on_event('agent_status', self.handle_agent_status)
            self.socketio.on_event('response_action', self.handle_response_action)
            self.socketio.on_event('subscribe_alerts', self.handle_subscribe_alerts)
            self.socketio.on_event('subscribe_dashboard', self.handle_subscribe_dashboard)
            self.socketio.on_event('agent_metrics', self.handle_agent_metrics)
            
            self.logger.info("Enhanced SocketIO event handlers registered")
            
        except Exception as e:
            self.logger.error(f"Error registering SocketIO handlers: {e}")
    
    def handle_connect(self):
        """Handle agent connection with enhanced security"""
        try:
            sid = request.sid
            client_ip = request.environ.get('REMOTE_ADDR', 'unknown')
            user_agent = request.headers.get('User-Agent', '')
            
            # Security checks
            if client_ip in self.blocked_ips:
                emit('error', {'message': 'IP blocked due to suspicious activity'})
                disconnect()
                return False
            
            if self.failed_attempts[client_ip] > 5:
                self.blocked_ips.add(client_ip)
                emit('error', {'message': 'Too many failed attempts'})
                disconnect()
                return False
            
            # Rate limiting check
            if not self._check_rate_limit(client_ip):
                emit('error', {'message': 'Rate limit exceeded'})
                disconnect()
                return False
            
            socketio_logger.info('agent_connect_attempt', 
                               f'Agent connection attempt from {client_ip}', 
                               sid=sid, client_ip=client_ip, user_agent=user_agent)
            
            emit('connect_response', {
                'status': 'connected',
                'sid': sid,
                'server_time': datetime.now().isoformat(),
                'message': 'Connected to Enhanced EDR Server',
                'server_version': '2.0',
                'protocol_version': '1.1'
            })
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error handling connect: {e}")
            emit('error', {'message': 'Connection failed'})
            return False
    
    def handle_disconnect(self):
        """Handle agent disconnection"""
        try:
            sid = request.sid
            connection = self.connection_pool.remove_connection(sid)
            
            if connection:
                # Update agent status in database
                self.agent_db.update_agent_status(connection.hostname, 'Offline')
                
                # Log activity
                duration = time.time() - connection.connected_at
                log_agent_activity(connection.hostname, 'disconnected', {
                    'connection_duration': duration,
                    'client_ip': connection.ip_address,
                    'last_heartbeat': connection.last_heartbeat,
                    'messages_processed': connection.metrics.get('messages_processed', 0)
                })
                
                socketio_logger.info('agent_disconnect', 
                                   f'Agent {connection.hostname} disconnected',
                                   hostname=connection.hostname, sid=sid, 
                                   duration=duration)
                
                # Remove from subscription lists
                self.alert_subscribers.discard(sid)
                self.dashboard_subscribers.discard(sid)
                
                # Notify dashboard about agent offline
                self._notify_dashboard_agent_status(connection.hostname, 'Offline')
            else:
                socketio_logger.info('unknown_disconnect', 'Unknown agent disconnected', sid=sid)
                
        except Exception as e:
            self.logger.error(f"Error handling disconnect: {e}")
    
    def handle_register(self, data):
        """Handle agent registration with enhanced validation"""
        try:
            sid = request.sid
            client_ip = request.environ.get('REMOTE_ADDR', 'unknown')
            
            # Enhanced validation
            validation_result = self._validate_registration_data(data)
            if not validation_result['valid']:
                self.failed_attempts[client_ip] += 1
                emit('error', {'message': validation_result['error']})
                return False
            
            hostname = data['hostname']
            os_type = data.get('os_type', 'Unknown')
            agent_version = data.get('agent_version', '1.0.0')
            
            # Check for duplicate hostname
            if self.connection_pool.get_connection_by_hostname(hostname):
                emit('error', {'message': f'Hostname {hostname} already connected'})
                return False
            
            # Register in database
            success = self.agent_db.register_agent({
                'hostname': hostname,
                'os_type': os_type,
                'agent_version': agent_version,
                'ip_address': client_ip,
                **data
            })
            
            if not success:
                emit('error', {'message': 'Failed to register agent in database'})
                return False
            
            # Create connection object
            connection = AgentConnection(
                hostname=hostname,
                sid=sid,
                os_type=os_type,
                agent_version=agent_version,
                ip_address=client_ip,
                connected_at=time.time(),
                last_seen=time.time(),
                last_heartbeat=time.time(),
                status='Online',
                room=f"agent_{hostname}",
                metrics={'messages_processed': 0, 'logs_sent': 0, 'alerts_generated': 0}
            )
            
            # Add to connection pool
            self.connection_pool.add_connection(connection)
            
            # Join agent room
            join_room(connection.room)
            
            # Reset failed attempts
            if client_ip in self.failed_attempts:
                del self.failed_attempts[client_ip]
            
            # Log activity
            log_agent_activity(hostname, 'registered', {
                'os_type': os_type,
                'agent_version': agent_version,
                'ip_address': client_ip
            })
            
            # Get agent configuration
            agent_config = self._get_enhanced_agent_config(hostname)
            
            # Send registration response
            emit('register_response', {
                'status': 'success',
                'message': f'Agent {hostname} registered successfully',
                'hostname': hostname,
                'server_time': datetime.now().isoformat(),
                'config': agent_config,
                'room': connection.room
            })
            
            # Notify dashboard
            self._notify_dashboard_agent_status(hostname, 'Online')
            
            socketio_logger.info('agent_register', 
                               f'Agent {hostname} registered successfully',
                               hostname=hostname, os_type=os_type, 
                               agent_version=agent_version)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error handling registration: {e}")
            emit('error', {'message': f'Registration failed: {str(e)}'})
            return False
    
    def handle_heartbeat(self, data=None):
        """Handle heartbeat with metrics collection"""
        try:
            sid = request.sid
            connection = self.connection_pool.get_connection_by_sid(sid)
            
            if not connection:
                emit('error', {'message': 'Agent not registered'})
                return
            
            # Update heartbeat
            self.connection_pool.update_heartbeat(sid)
            
            # Update database
            system_info = data.get('system_info', {}) if data else {}
            self.agent_db.update_heartbeat(connection.hostname, system_info)
            
            # Collect metrics
            if data and 'metrics' in data:
                connection.metrics.update(data['metrics'])
            
            # Send response with server instructions
            response_data = {
                'status': 'alive',
                'server_time': datetime.now().isoformat(),
                'timestamp': time.time(),
                'next_heartbeat': 30,  # seconds
                'batch_size': self.batch_size
            }
            
            # Add any pending commands
            pending_commands = []
            while not connection.pending_commands.empty():
                try:
                    cmd = connection.pending_commands.get_nowait()
                    pending_commands.append(cmd)
                except queue.Empty:
                    break
            
            if pending_commands:
                response_data['commands'] = pending_commands
            
            emit('heartbeat_response', response_data)
            
            self.logger.debug(f"Heartbeat from {connection.hostname}")
            
        except Exception as e:
            self.logger.error(f"Error handling heartbeat: {e}")
    
    def handle_bulk_logs(self, data):
        """Handle bulk log processing for better performance"""
        try:
            sid = request.sid
            connection = self.connection_pool.get_connection_by_sid(sid)
            
            if not connection:
                emit('error', {'message': 'Agent not registered'})
                return
            
            if not isinstance(data, dict) or 'batches' not in data:
                emit('error', {'message': 'Invalid bulk log format'})
                return
            
            batches = data['batches']
            total_processed = 0
            total_alerts = 0
            
            # Process each batch
            for batch_data in batches:
                if not isinstance(batch_data, dict):
                    continue
                
                log_type = batch_data.get('type')
                logs = batch_data.get('logs', [])
                
                if not log_type or not logs:
                    continue
                
                # Create log batch
                batch = LogBatch(
                    hostname=connection.hostname,
                    log_type=log_type,
                    logs=logs,
                    timestamp=time.time(),
                    batch_id=generate_unique_id()
                )
                
                # Queue for processing
                try:
                    self.log_queue.put(batch, timeout=1.0)
                    total_processed += len(logs)
                except queue.Full:
                    self.logger.warning(f"Log queue full, dropping batch from {connection.hostname}")
            
            # Update connection metrics
            connection.metrics['logs_sent'] += total_processed
            connection.metrics['messages_processed'] += 1
            
            # Send response
            emit('bulk_log_response', {
                'status': 'success',
                'processed_batches': len(batches),
                'total_logs': total_processed,
                'batch_id': generate_unique_id(),
                'timestamp': time.time()
            })
            
            socketio_logger.info('bulk_logs_received', 
                               f'Bulk logs from {connection.hostname}',
                               hostname=connection.hostname, 
                               batches=len(batches), total_logs=total_processed)
            
        except Exception as e:
            self.logger.error(f"Error handling bulk logs: {e}")
            emit('error', {'message': 'Error processing bulk logs'})
    
    def handle_process_logs(self, data):
        """Handle process logs (legacy compatibility)"""
        return self._handle_single_log_type('process', data)
    
    def handle_file_logs(self, data):
        """Handle file logs (legacy compatibility)"""
        return self._handle_single_log_type('file', data)
    
    def handle_network_logs(self, data):
        """Handle network logs (legacy compatibility)"""
        return self._handle_single_log_type('network', data)
    
    def _handle_single_log_type(self, log_type: str, data: Dict) -> Dict:
        """Handle single log type (backward compatibility)"""
        try:
            sid = request.sid
            connection = self.connection_pool.get_connection_by_sid(sid)
            
            if not connection:
                emit('error', {'message': 'Agent not registered'})
                return {'status': 'error', 'message': 'Agent not registered'}
            
            if not isinstance(data, dict) or 'logs' not in data:
                return {'status': 'error', 'message': 'Invalid log data format'}
            
            logs = data['logs']
            if not isinstance(logs, list):
                return {'status': 'error', 'message': 'Logs must be a list'}
            
            # Create batch and queue for processing
            batch = LogBatch(
                hostname=connection.hostname,
                log_type=log_type,
                logs=logs,
                timestamp=time.time(),
                batch_id=generate_unique_id()
            )
            
            try:
                self.log_queue.put(batch, timeout=1.0)
            except queue.Full:
                return {'status': 'error', 'message': 'Server too busy, try again later'}
            
            # Update metrics
            connection.metrics['logs_sent'] += len(logs)
            connection.metrics['messages_processed'] += 1
            
            result = {
                'status': 'success',
                'processed': len(logs),
                'total': len(logs),
                'batch_id': batch.batch_id,
                'message': f'Queued {len(logs)} {log_type} logs for processing'
            }
            
            emit('log_response', result)
            return result
            
        except Exception as e:
            self.logger.error(f"Error handling {log_type} logs: {e}")
            error_result = {'status': 'error', 'message': f'Error processing {log_type} logs'}
            emit('error', error_result)
            return error_result
    
    def _process_log_batches(self):
        """Background task to process log batches"""
        batch_buffer = []
        last_flush = time.time()
        
        while True:
            try:
                # Get batch from queue
                try:
                    batch = self.log_queue.get(timeout=1.0)
                    batch_buffer.append(batch)
                except queue.Empty:
                    batch = None
                
                # Process buffer if full or timeout
                current_time = time.time()
                should_flush = (
                    len(batch_buffer) >= 10 or  # Buffer full
                    (batch_buffer and current_time - last_flush > self.batch_timeout)  # Timeout
                )
                
                if should_flush:
                    self._process_batch_buffer(batch_buffer)
                    batch_buffer.clear()
                    last_flush = current_time
                
            except Exception as e:
                self.logger.error(f"Error in log batch processor: {e}")
                time.sleep(1)
    
    def _process_batch_buffer(self, batches: List[LogBatch]):
        """Process a buffer of log batches"""
        try:
            for batch in batches:
                self._process_single_batch(batch)
        except Exception as e:
            self.logger.error(f"Error processing batch buffer: {e}")
    
    def _process_single_batch(self, batch: LogBatch):
        """Process a single log batch"""
        try:
            processed_count = 0
            alerts_generated = 0
            
            for log in batch.logs:
                try:
                    # Add hostname and filter sensitive data
                    if 'Hostname' not in log:
                        log['Hostname'] = batch.hostname
                    
                    log = filter_sensitive_data(log)
                    
                    # Store log
                    if self.log_db.process_log(batch.log_type, log):
                        processed_count += 1
                        
                        # Check rules and create alerts
                        if self._check_rules_and_create_alert(batch.log_type, log, batch.hostname):
                            alerts_generated += 1
                
                except Exception as e:
                    self.logger.error(f"Error processing individual log: {e}")
                    continue
            
            # Update connection metrics
            connection = self.connection_pool.get_connection_by_hostname(batch.hostname)
            if connection:
                connection.metrics['alerts_generated'] += alerts_generated
            
            # Log processing stats
            socketio_logger.info('batch_processed', 
                               f'Processed batch from {batch.hostname}',
                               hostname=batch.hostname, log_type=batch.log_type,
                               processed=processed_count, total=len(batch.logs),
                               alerts_generated=alerts_generated, batch_id=batch.batch_id)
            
        except Exception as e:
            self.logger.error(f"Error processing batch: {e}")
    
    def _check_rules_and_create_alert(self, log_type: str, log_data: Dict, hostname: str) -> bool:
        """Enhanced rule checking and alert creation"""
        try:
            # Check rules using enhanced rule engine
            detection = self.rule_engine.check_rules(
                log_type.upper() + '_LOGS', 
                log_data, 
                hostname
            )
            
            # Handle enhanced detection result
            if hasattr(detection, 'violated') and detection.violated:
                # Create alert data
                alert_data = {
                    'hostname': hostname,
                    'rule_id': detection.rule_id,
                    'alert_type': f'{log_type.title()} Detection',
                    'severity': detection.severity,
                    'title': self._generate_enhanced_alert_title(detection, log_type, log_data),
                    'description': detection.description,
                    'detection_data': detection.detection_data,
                    'action': detection.action,
                    'confidence_score': getattr(detection, 'confidence_score', 0.8),
                    'indicators': getattr(detection, 'indicators', [])
                }
                
                # Save alert
                alert_success = self.alert_db.create_alert(alert_data)
                
                if alert_success:
                    # Send real-time alert to agent
                    self._send_enhanced_alert_to_agent(hostname, {
                        'type': f'{log_type}_detection',
                        'severity': detection.severity,
                        'title': alert_data['title'],
                        'message': detection.description,
                        'action': detection.action,
                        'timestamp': datetime.now().isoformat(),
                        'rule_id': detection.rule_id,
                        'alert_id': generate_unique_id(),
                        'confidence_score': alert_data['confidence_score'],
                        'indicators': alert_data['indicators'],
                        **self._extract_alert_context(log_type, log_data)
                    })
                    
                    # Notify dashboard subscribers
                    self._notify_dashboard_new_alert(alert_data)
                    
                    # Log security event
                    log_security_event(
                        event_type=f'{log_type}_detection',
                        severity=detection.severity,
                        description=f'Enhanced detection: {detection.description}',
                        hostname=hostname,
                        details={
                            'rule_id': detection.rule_id,
                            'confidence_score': alert_data['confidence_score'],
                            'indicators': alert_data['indicators']
                        }
                    )
                    
                    return True
            
            # Handle legacy detection result (backward compatibility)
            elif isinstance(detection, tuple) and len(detection) >= 6:
                rule_violated, description, detection_data, severity, rule_id, action = detection[:6]
                
                if rule_violated:
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
                    
                    alert_success = self.alert_db.create_alert(alert_data)
                    
                    if alert_success:
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
                        
                        return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking rules for {log_type} log: {e}")
            return False
    
    def handle_subscribe_alerts(self, data=None):
        """Handle alert subscription for real-time updates"""
        try:
            sid = request.sid
            self.alert_subscribers.add(sid)
            
            emit('subscription_response', {
                'type': 'alerts',
                'status': 'subscribed',
                'message': 'Subscribed to real-time alerts'
            })
            
            socketio_logger.info('alert_subscription', 'Client subscribed to alerts', sid=sid)
            
        except Exception as e:
            self.logger.error(f"Error handling alert subscription: {e}")
    
    def handle_subscribe_dashboard(self, data=None):
        """Handle dashboard subscription for real-time updates"""
        try:
            sid = request.sid
            self.dashboard_subscribers.add(sid)
            
            emit('subscription_response', {
                'type': 'dashboard',
                'status': 'subscribed',
                'message': 'Subscribed to dashboard updates'
            })
            
            socketio_logger.info('dashboard_subscription', 'Client subscribed to dashboard updates', sid=sid)
            
        except Exception as e:
            self.logger.error(f"Error handling dashboard subscription: {e}")
    
    def handle_agent_metrics(self, data):
        """Handle agent performance metrics"""
        try:
            sid = request.sid
            connection = self.connection_pool.get_connection_by_sid(sid)
            
            if not connection:
                emit('error', {'message': 'Agent not registered'})
                return
            
            if isinstance(data, dict) and 'metrics' in data:
                # Update connection metrics
                connection.metrics.update(data['metrics'])
                
                # Store in database if needed
                # self.agent_db.store_agent_metrics(connection.hostname, data['metrics'])
                
                emit('metrics_response', {
                    'status': 'success',
                    'message': 'Metrics received'
                })
            
        except Exception as e:
            self.logger.error(f"Error handling agent metrics: {e}")
    
    def _generate_enhanced_alert_title(self, detection, log_type: str, log_data: Dict) -> str:
        """Generate enhanced alert title with confidence and indicators"""
        try:
            base_title = self._generate_alert_title(log_type, log_data)
            confidence = getattr(detection, 'confidence_score', 0.0)
            indicators = getattr(detection, 'indicators', [])
            
            title = f"{base_title}"
            if confidence > 0.8:
                title += " [HIGH CONFIDENCE]"
            elif confidence > 0.6:
                title += " [MEDIUM CONFIDENCE]"
            
            if indicators:
                title += f" [{', '.join(indicators[:2])}]"
            
            return title
            
        except Exception as e:
            self.logger.error(f"Error generating enhanced alert title: {e}")
            return self._generate_alert_title(log_type, log_data)
    
    def _generate_alert_title(self, log_type: str, log_data: Dict) -> str:
        """Generate basic alert title"""
        try:
            if log_type == 'process':
                process_name = log_data.get('ProcessName', 'Unknown Process')
                return f"Suspicious Process: {process_name}"
            elif log_type == 'file':
                file_name = log_data.get('FileName', 'Unknown File')
                return f"Suspicious File Activity: {file_name}"
            elif log_type == 'network':
                remote_addr = log_data.get('RemoteAddress', 'Unknown Address')
                return f"Suspicious Network Activity: {remote_addr}"
            else:
                return f"Suspicious {log_type.title()} Activity"
                
        except Exception as e:
            self.logger.error(f"Error generating alert title: {e}")
            return f"Suspicious {log_type.title()} Activity"
    
    def _extract_alert_context(self, log_type: str, log_data: Dict) -> Dict:
        """Extract relevant context for alerts"""
        try:
            context = {
                'log_type': log_type,
                'timestamp': datetime.now().isoformat()
            }
            
            if log_type == 'process':
                context.update({
                    'process_name': log_data.get('ProcessName'),
                    'process_id': log_data.get('ProcessID'),
                    'command_line': log_data.get('CommandLine')
                })
            elif log_type == 'file':
                context.update({
                    'file_name': log_data.get('FileName'),
                    'file_path': log_data.get('FilePath'),
                    'event_type': log_data.get('EventType')
                })
            elif log_type == 'network':
                context.update({
                    'remote_address': log_data.get('RemoteAddress'),
                    'remote_port': log_data.get('RemotePort'),
                    'protocol': log_data.get('Protocol')
                })
            
            return context
            
        except Exception as e:
            self.logger.error(f"Error extracting alert context: {e}")
            return {'log_type': log_type, 'timestamp': datetime.now().isoformat()}
    
    def _send_enhanced_alert_to_agent(self, hostname: str, alert_data: Dict):
        """Send enhanced alert to specific agent"""
        try:
            connection = self.connection_pool.get_connection_by_hostname(hostname)
            if connection:
                self.socketio.emit('alert', alert_data, room=connection.room)
                
        except Exception as e:
            self.logger.error(f"Error sending enhanced alert to agent: {e}")
    
    def _send_alert_to_agent(self, hostname: str, alert_data: Dict):
        """Send basic alert to specific agent (legacy)"""
        try:
            connection = self.connection_pool.get_connection_by_hostname(hostname)
            if connection:
                self.socketio.emit('alert', alert_data, room=connection.room)
                
        except Exception as e:
            self.logger.error(f"Error sending alert to agent: {e}")
    
    def _notify_dashboard_new_alert(self, alert_data: Dict):
        """Notify dashboard subscribers about new alert"""
        try:
            if self.dashboard_subscribers:
                self.socketio.emit('new_alert', alert_data, room='dashboard')
                
        except Exception as e:
            self.logger.error(f"Error notifying dashboard about new alert: {e}")
    
    def _notify_dashboard_agent_status(self, hostname: str, status: str):
        """Notify dashboard about agent status change"""
        try:
            if self.dashboard_subscribers:
                self.socketio.emit('agent_status_change', {
                    'hostname': hostname,
                    'status': status,
                    'timestamp': datetime.now().isoformat()
                }, room='dashboard')
                
        except Exception as e:
            self.logger.error(f"Error notifying dashboard about agent status: {e}")
    
    def _get_enhanced_agent_config(self, hostname: str) -> Dict:
        """Get enhanced agent configuration"""
        try:
            # Get base configuration
            config = self.agent_db.get_agent_config(hostname)
            
            # Add enhanced features
            config.update({
                'batch_size': self.batch_size,
                'batch_timeout': self.batch_timeout,
                'heartbeat_interval': 30,
                'log_retention_days': 30,
                'alert_retention_days': 90,
                'max_log_size': 10485760,  # 10MB
                'compression_enabled': True,
                'encryption_enabled': True,
                'advanced_detection': True
            })
            
            return config
            
        except Exception as e:
            self.logger.error(f"Error getting enhanced agent config: {e}")
            return {}
    
    def _check_rate_limit(self, client_ip: str) -> bool:
        """Check if client has exceeded rate limit"""
        try:
            current_time = time.time()
            if client_ip in self.suspicious_activity:
                # Clean old entries
                self.suspicious_activity[client_ip] = [
                    t for t in self.suspicious_activity[client_ip]
                    if current_time - t < 60  # Last minute
                ]
                
                # Check rate limit (max 100 requests per minute)
                if len(self.suspicious_activity[client_ip]) >= 100:
                    return False
                
                self.suspicious_activity[client_ip].append(current_time)
            else:
                self.suspicious_activity[client_ip] = [current_time]
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error checking rate limit: {e}")
            return False
    
    def _validate_registration_data(self, data: Dict) -> Dict:
        """Validate agent registration data"""
        try:
            if not isinstance(data, dict):
                return {'valid': False, 'error': 'Invalid data format'}
            
            required_fields = ['hostname', 'os_type', 'agent_version']
            for field in required_fields:
                if field not in data:
                    return {'valid': False, 'error': f'Missing required field: {field}'}
            
            if not validate_hostname(data['hostname']):
                return {'valid': False, 'error': 'Invalid hostname format'}
            
            return {'valid': True}
            
        except Exception as e:
            self.logger.error(f"Error validating registration data: {e}")
            return {'valid': False, 'error': 'Validation error'}
    
    def _cleanup_stale_connections(self):
        """Background task to clean up stale connections"""
        while True:
            try:
                current_time = time.time()
                stale_timeout = 300  # 5 minutes
                
                for sid, connection in list(self.connection_pool.connections.items()):
                    if current_time - connection.last_heartbeat > stale_timeout:
                        self.logger.warning(f"Cleaning up stale connection for {connection.hostname}")
                        self.connection_pool.remove_connection(sid)
                        
                        # Update agent status
                        self.agent_db.update_agent_status(connection.hostname, 'Offline')
                        
                        # Notify dashboard
                        self._notify_dashboard_agent_status(connection.hostname, 'Offline')
                
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Error in connection cleanup: {e}")
                time.sleep(60)
    
    def _collect_metrics(self):
        """Background task to collect and store metrics"""
        while True:
            try:
                # Collect connection pool metrics
                pool_metrics = {
                    'active_connections': len(self.connection_pool.connections),
                    'total_connections': self.connection_pool.metrics['total_connections'],
                    'failed_connections': self.connection_pool.metrics['failed_connections'],
                    'messages_processed': self.connection_pool.metrics['messages_processed']
                }
                
                # Collect rule engine metrics
                rule_metrics = self.rule_engine.get_enhanced_stats()
                
                # Combine metrics
                metrics = {
                    'timestamp': datetime.now().isoformat(),
                    'connection_pool': pool_metrics,
                    'rule_engine': rule_metrics,
                    'queue_size': self.log_queue.qsize()
                }
                
                # Store metrics (implement your storage logic)
                # self.metrics_db.store_metrics(metrics)
                
                time.sleep(60)  # Collect every minute
                
            except Exception as e:
                self.logger.error(f"Error collecting metrics: {e}")
                time.sleep(60)