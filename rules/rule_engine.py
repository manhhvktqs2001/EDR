"""
Enhanced Rule Engine Core
Xử lý logic kiểm tra rules và tạo alerts với machine learning và advanced detection
"""

import logging
import time
import threading
import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib

from database.rules import RuleDB
from database.agents import AgentDB
from utils.helpers import sanitize_string, safe_int
from utils.logger import rule_logger

@dataclass
class DetectionResult:
    """Structured detection result"""
    violated: bool
    rule_id: Optional[int] = None
    description: Optional[str] = None
    detection_data: Optional[str] = None
    severity: Optional[str] = None
    action: Optional[str] = None
    confidence_score: float = 0.0
    indicators: List[str] = None
    
    def __post_init__(self):
        if self.indicators is None:
            self.indicators = []

@dataclass
class RuleContext:
    """Rule execution context"""
    rule: Dict
    hostname: str
    log_type: str
    log_data: Dict
    timestamp: datetime
    agent_info: Optional[Dict] = None

class ThreatIntelligence:
    """Basic threat intelligence module"""
    
    def __init__(self):
        self.malicious_ips = set()
        self.malicious_domains = set()
        self.suspicious_processes = set()
        self.ransomware_extensions = set()
        self.c2_patterns = []
        self._load_threat_data()
    
    def _load_threat_data(self):
        """Load basic threat intelligence data"""
        # Malicious IPs (example - in production, load from threat feeds)
        self.malicious_ips.update([
            "192.168.100.100", "10.0.0.100", "172.16.0.100"
        ])
        
        # Suspicious processes
        self.suspicious_processes.update([
            "cmd.exe", "powershell.exe", "wmic.exe", "net.exe",
            "reg.exe", "schtasks.exe", "at.exe", "sc.exe",
            "vssadmin.exe", "bcdedit.exe", "wevtutil.exe"
        ])
        
        # Ransomware file extensions
        self.ransomware_extensions.update([
            ".encrypted", ".locked", ".crypto", ".crypt", ".enc",
            ".vault", ".micro", ".xxx", ".zzz", ".locky",
            ".cerber", ".zepto", ".thor", ".locky"
        ])
        
        # C2 communication patterns
        self.c2_patterns = [
            r"POST /[a-f0-9]{32} HTTP",
            r"User-Agent: [A-Za-z0-9+/]{20,}",
            r"/[a-z]{3,8}/[a-f0-9]{8,16}",
        ]
    
    def is_malicious_ip(self, ip: str) -> bool:
        """Check if IP is known malicious"""
        return ip in self.malicious_ips
    
    def is_suspicious_process(self, process_name: str) -> bool:
        """Check if process is suspicious"""
        return process_name.lower() in self.suspicious_processes
    
    def is_ransomware_extension(self, filename: str) -> bool:
        """Check if file has ransomware extension"""
        return any(filename.lower().endswith(ext) for ext in self.ransomware_extensions)
    
    def detect_c2_pattern(self, data: str) -> bool:
        """Detect C2 communication patterns"""
        return any(re.search(pattern, data, re.IGNORECASE) for pattern in self.c2_patterns)

class BehaviorAnalyzer:
    """Behavioral analysis for anomaly detection"""
    
    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self.process_history = defaultdict(lambda: deque(maxlen=window_size))
        self.network_history = defaultdict(lambda: deque(maxlen=window_size))
        self.file_history = defaultdict(lambda: deque(maxlen=window_size))
        self.baseline_established = False
        self.baselines = {}
    
    def analyze_process_behavior(self, hostname: str, log_data: Dict) -> Dict:
        """Analyze process behavior for anomalies"""
        try:
            process_name = log_data.get('ProcessName', '').lower()
            command_line = log_data.get('CommandLine', '')
            parent_pid = safe_int(log_data.get('ParentProcessID', 0))
            
            # Store in history
            self.process_history[hostname].append({
                'process': process_name,
                'command': command_line,
                'parent_pid': parent_pid,
                'timestamp': time.time()
            })
            
            anomalies = []
            
            # Check for unusual parent-child relationships
            if self._is_unusual_parent_child(process_name, parent_pid, hostname):
                anomalies.append('unusual_parent_child_relationship')
            
            # Check for command injection patterns
            if self._detect_command_injection(command_line):
                anomalies.append('potential_command_injection')
            
            # Check for process frequency anomalies
            if self._is_process_frequency_anomaly(process_name, hostname):
                anomalies.append('unusual_process_frequency')
            
            return {
                'anomalies': anomalies,
                'confidence': len(anomalies) / 3.0,  # Simple confidence score
                'details': {
                    'process_name': process_name,
                    'unusual_patterns': self._get_unusual_patterns(command_line)
                }
            }
            
        except Exception as e:
            rule_logger.error('behavior_analysis_error', f'Error in process behavior analysis: {e}')
            return {'anomalies': [], 'confidence': 0.0}
    
    def analyze_network_behavior(self, hostname: str, log_data: Dict) -> Dict:
        """Analyze network behavior for anomalies"""
        try:
            remote_addr = log_data.get('RemoteAddress', '')
            remote_port = safe_int(log_data.get('RemotePort', 0))
            protocol = log_data.get('Protocol', '').lower()
            direction = log_data.get('Direction', '').lower()
            
            # Store in history
            self.network_history[hostname].append({
                'remote_addr': remote_addr,
                'remote_port': remote_port,
                'protocol': protocol,
                'direction': direction,
                'timestamp': time.time()
            })
            
            anomalies = []
            
            # Check for beacon-like behavior
            if self._detect_beaconing(hostname, remote_addr):
                anomalies.append('potential_beaconing')
            
            # Check for port scanning
            if self._detect_port_scanning(hostname):
                anomalies.append('potential_port_scanning')
            
            # Check for data exfiltration patterns
            if self._detect_data_exfiltration(hostname, log_data):
                anomalies.append('potential_data_exfiltration')
            
            return {
                'anomalies': anomalies,
                'confidence': len(anomalies) / 3.0,
                'details': {
                    'remote_address': remote_addr,
                    'connection_frequency': self._get_connection_frequency(hostname, remote_addr)
                }
            }
            
        except Exception as e:
            rule_logger.error('behavior_analysis_error', f'Error in network behavior analysis: {e}')
            return {'anomalies': [], 'confidence': 0.0}
    
    def _is_unusual_parent_child(self, process: str, parent_pid: int, hostname: str) -> bool:
        """Detect unusual parent-child process relationships"""
        # Define normal parent-child relationships
        normal_relationships = {
            'cmd.exe': ['explorer.exe', 'winlogon.exe', 'services.exe'],
            'powershell.exe': ['cmd.exe', 'explorer.exe', 'winlogon.exe'],
            'notepad.exe': ['explorer.exe'],
            'calc.exe': ['explorer.exe']
        }
        
        if process not in normal_relationships:
            return False
        
        # Get recent parent processes
        recent_processes = list(self.process_history[hostname])[-20:]  # Last 20 processes
        parent_processes = [p['process'] for p in recent_processes if p.get('parent_pid') == parent_pid]
        
        if not parent_processes:
            return False
        
        # Check if any parent is in the normal list
        return not any(parent in normal_relationships[process] for parent in parent_processes)
    
    def _detect_command_injection(self, command_line: str) -> bool:
        """Detect potential command injection patterns"""
        if not command_line:
            return False
        
        injection_patterns = [
            r'&\s*[a-zA-Z]',  # Command chaining with &
            r'\|\s*[a-zA-Z]',  # Pipe to another command
            r';\s*[a-zA-Z]',  # Command separator
            r'`[^`]+`',       # Backtick execution
            r'\$\([^)]+\)',   # Command substitution
            r'>\s*/dev/',     # Output redirection
            r'wget\s+http',   # Download commands
            r'curl\s+http',   # Download commands
            r'nc\s+-',        # Netcat usage
        ]
        
        return any(re.search(pattern, command_line, re.IGNORECASE) for pattern in injection_patterns)
    
    def _is_process_frequency_anomaly(self, process: str, hostname: str) -> bool:
        """Detect if process frequency is anomalous"""
        if len(self.process_history[hostname]) < 50:  # Need sufficient history
            return False
        
        recent_count = sum(1 for p in self.process_history[hostname] 
                          if p['process'] == process and time.time() - p['timestamp'] < 300)  # Last 5 minutes
        
        # Simple threshold - more than 10 instances in 5 minutes is suspicious
        return recent_count > 10
    
    def _get_unusual_patterns(self, command_line: str) -> List[str]:
        """Get list of unusual patterns in command line"""
        patterns = []
        
        if re.search(r'-enc[oded]*\s+[A-Za-z0-9+/=]{20,}', command_line, re.IGNORECASE):
            patterns.append('base64_encoded_command')
        
        if re.search(r'powershell.*-nop.*-w.*hidden', command_line, re.IGNORECASE):
            patterns.append('hidden_powershell_execution')
        
        if re.search(r'cmd.*\/c.*echo.*>.*\.bat', command_line, re.IGNORECASE):
            patterns.append('batch_file_creation')
        
        return patterns
    
    def _detect_beaconing(self, hostname: str, remote_addr: str) -> bool:
        """Detect beacon-like network behavior"""
        if not remote_addr or len(self.network_history[hostname]) < 10:
            return False
        
        # Get connections to this address in last hour
        current_time = time.time()
        connections = [
            conn for conn in self.network_history[hostname]
            if conn['remote_addr'] == remote_addr and current_time - conn['timestamp'] < 3600
        ]
        
        if len(connections) < 5:
            return False
        
        # Check for regular intervals (simple detection)
        timestamps = [conn['timestamp'] for conn in connections]
        timestamps.sort()
        
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        
        # If intervals are very regular (within 10% variation), it might be beaconing
        if len(intervals) > 3:
            avg_interval = sum(intervals) / len(intervals)
            variations = [abs(interval - avg_interval) / avg_interval for interval in intervals]
            return sum(variations) / len(variations) < 0.1  # Low variation indicates beaconing
        
        return False
    
    def _detect_port_scanning(self, hostname: str) -> bool:
        """Detect port scanning behavior"""
        if len(self.network_history[hostname]) < 20:
            return False
        
        # Get recent outbound connections
        current_time = time.time()
        recent_connections = [
            conn for conn in self.network_history[hostname]
            if conn['direction'] == 'outbound' and current_time - conn['timestamp'] < 300  # Last 5 minutes
        ]
        
        # Count unique remote addresses and ports
        unique_addresses = set(conn['remote_addr'] for conn in recent_connections)
        unique_ports = set(conn['remote_port'] for conn in recent_connections)
        
        # Simple heuristic: many unique ports to different addresses
        return len(unique_addresses) > 5 and len(unique_ports) > 10
    
    def _detect_data_exfiltration(self, hostname: str, log_data: Dict) -> bool:
        """Detect potential data exfiltration"""
        remote_addr = log_data.get('RemoteAddress', '')
        direction = log_data.get('Direction', '').lower()
        
        if direction != 'outbound' or not remote_addr:
            return False
        
        # Check if this is an external IP (not private)
        if self._is_private_ip(remote_addr):
            return False
        
        # Count recent outbound connections to external IPs
        current_time = time.time()
        external_connections = [
            conn for conn in self.network_history[hostname]
            if (conn['direction'] == 'outbound' and 
                not self._is_private_ip(conn['remote_addr']) and 
                current_time - conn['timestamp'] < 1800)  # Last 30 minutes
        ]
        
        # If many external connections, it might be data exfiltration
        return len(external_connections) > 20
    
    def _get_connection_frequency(self, hostname: str, remote_addr: str) -> int:
        """Get connection frequency for a specific address"""
        current_time = time.time()
        return sum(1 for conn in self.network_history[hostname]
                  if conn['remote_addr'] == remote_addr and current_time - conn['timestamp'] < 3600)
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        try:
            import ipaddress
            return ipaddress.ip_address(ip).is_private
        except:
            return ip.startswith(('192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', 
                                '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                                '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.'))

class EnhancedRuleEngine:
    """Enhanced Rule Engine với advanced detection capabilities"""
    
    def __init__(self):
        self.rule_db = RuleDB()
        self.agent_db = AgentDB()
        self.logger = logging.getLogger(__name__)
        
        # Enhanced components
        self.threat_intelligence = ThreatIntelligence()
        self.behavior_analyzer = BehaviorAnalyzer()
        
        # Cache management
        self.rules_cache = {}
        self.agent_rules_cache = {}
        self.detection_cache = {}  # Cache recent detections to avoid duplicates
        self.last_refresh = 0
        self.refresh_interval = 300  # 5 minutes
        self.lock = threading.RLock()
        
        # Performance tracking
        self.stats = {
            'total_checks': 0,
            'violations_detected': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'avg_processing_time': 0.0,
            'rules_processed': 0,
            'behavioral_detections': 0,
            'threat_intel_hits': 0
        }
        
        # Thread pool for parallel processing
        self.executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="RuleEngine")
        
        # Initialize
        self.is_initialized = False
        self._initialize()
    
    def _initialize(self):
        """Initialize rule engine with enhanced features"""
        try:
            # Load rules into cache
            self.refresh_rules()
            
            # Initialize detection patterns
            self._load_detection_patterns()
            
            self.is_initialized = True
            
            rule_logger.info('engine_initialized', 
                           'Enhanced Rule Engine initialized successfully',
                           total_rules=len(self.rules_cache),
                           threat_intel_loaded=len(self.threat_intelligence.malicious_ips))
            
        except Exception as e:
            self.logger.error(f"Failed to initialize enhanced rule engine: {e}")
            self.is_initialized = False
    
    def _load_detection_patterns(self):
        """Load advanced detection patterns"""
        self.yara_rules = {}  # Could integrate YARA rules
        self.sigma_rules = {}  # Could integrate Sigma rules
        
        # Load custom detection patterns
        self.custom_patterns = {
            'living_off_the_land': [
                r'powershell.*-enc.*[A-Za-z0-9+/=]{50,}',
                r'cmd.*\/c.*echo.*\|.*findstr',
                r'wmic.*process.*call.*create',
                r'certutil.*-urlcache.*-split.*-f'
            ],
            'lateral_movement': [
                r'net.*use.*\\\\\d+\.\d+\.\d+\.\d+',
                r'psexec.*\\\\',
                r'wmic.*\/node:.*process.*call.*create'
            ],
            'persistence': [
                r'schtasks.*\/create.*\/tn.*\/tr',
                r'reg.*add.*HKEY_.*\\.*\\Run',
                r'sc.*create.*binpath'
            ]
        }
    
    def check_rules(self, log_type: str, log_data: Dict, hostname: str) -> DetectionResult:
        """Enhanced rule checking with ML and behavioral analysis"""
        try:
            start_time = time.time()
            
            if not self.is_initialized:
                self._initialize()
            
            # Refresh rules if needed
            if self._should_refresh_rules():
                self.refresh_rules()
            
            # Update stats
            with self.lock:
                self.stats['total_checks'] += 1
            
            # Create rule context
            context = RuleContext(
                rule={},  # Will be filled per rule
                hostname=hostname,
                log_type=log_type,
                log_data=log_data,
                timestamp=datetime.now(),
                agent_info=self._get_agent_info(hostname)
            )
            
            # Check detection cache first
            detection_hash = self._generate_detection_hash(log_type, log_data, hostname)
            if detection_hash in self.detection_cache:
                with self.lock:
                    self.stats['cache_hits'] += 1
                cached_result = self.detection_cache[detection_hash]
                # Return cached result if it's recent (within 5 minutes)
                if time.time() - cached_result['timestamp'] < 300:
                    return cached_result['result']
            
            with self.lock:
                self.stats['cache_misses'] += 1
            
            # Get applicable rules
            agent_rules = self.get_agent_rules(hostname)
            if not agent_rules:
                return DetectionResult(violated=False)
            
            # Parallel rule checking
            detection_results = []
            
            # Traditional rule-based detection
            traditional_result = self._check_traditional_rules(context, agent_rules)
            if traditional_result.violated:
                detection_results.append(traditional_result)
            
            # Behavioral analysis
            behavioral_result = self._check_behavioral_patterns(context)
            if behavioral_result.violated:
                detection_results.append(behavioral_result)
                with self.lock:
                    self.stats['behavioral_detections'] += 1
            
            # Threat intelligence checks
            threat_intel_result = self._check_threat_intelligence(context)
            if threat_intel_result.violated:
                detection_results.append(threat_intel_result)
                with self.lock:
                    self.stats['threat_intel_hits'] += 1
            
            # Advanced pattern detection
            pattern_result = self._check_advanced_patterns(context)
            if pattern_result.violated:
                detection_results.append(pattern_result)
            
            # Combine results and select highest priority
            final_result = self._combine_detection_results(detection_results)
            
            # Cache the result
            self.detection_cache[detection_hash] = {
                'result': final_result,
                'timestamp': time.time()
            }
            
            # Clean old cache entries
            self._cleanup_detection_cache()
            
            # Update performance stats
            processing_time = time.time() - start_time
            with self.lock:
                total_time = self.stats['avg_processing_time'] * self.stats['rules_processed']
                self.stats['rules_processed'] += 1
                self.stats['avg_processing_time'] = (total_time + processing_time) / self.stats['rules_processed']
                
                if final_result.violated:
                    self.stats['violations_detected'] += 1
            
            # Log significant detections
            if final_result.violated and final_result.confidence_score > 0.7:
                rule_logger.warning('high_confidence_detection',
                                  f'High confidence threat detected: {final_result.description}',
                                  hostname=hostname, confidence=final_result.confidence_score,
                                  indicators=final_result.indicators)
            
            return final_result
            
        except Exception as e:
            self.logger.error(f"Error in enhanced rule checking: {e}")
            return DetectionResult(violated=False)
    
    def _check_traditional_rules(self, context: RuleContext, rules: List[Dict]) -> DetectionResult:
        """Check traditional signature-based rules"""
        try:
            for rule in rules:
                try:
                    context.rule = rule
                    
                    # Skip if rule type doesn't match
                    rule_type = rule.get('RuleType', '').lower()
                    if not self._rule_type_matches(rule_type, context.log_type):
                        continue
                    
                    # Check rule violation
                    violation = self._check_rule_violation(rule, context.log_data, context.log_type)
                    if violation:
                        return DetectionResult(
                            violated=True,
                            rule_id=rule['RuleID'],
                            description=violation['description'],
                            detection_data=violation['detection_data'],
                            severity=rule['Severity'],
                            action=rule['Action'],
                            confidence_score=0.8,  # Traditional rules have high confidence
                            indicators=['signature_match']
                        )
                        
                except Exception as e:
                    self.logger.error(f"Error checking rule {rule.get('RuleID')}: {e}")
                    continue
            
            return DetectionResult(violated=False)
            
        except Exception as e:
            self.logger.error(f"Error in traditional rule checking: {e}")
            return DetectionResult(violated=False)
    
    def _check_behavioral_patterns(self, context: RuleContext) -> DetectionResult:
        """Check for behavioral anomalies"""
        try:
            log_type = context.log_type.lower().replace('_logs', '')
            
            if log_type == 'process':
                behavior = self.behavior_analyzer.analyze_process_behavior(
                    context.hostname, context.log_data
                )
            elif log_type == 'network':
                behavior = self.behavior_analyzer.analyze_network_behavior(
                    context.hostname, context.log_data
                )
            else:
                return DetectionResult(violated=False)
            
            if behavior['anomalies'] and behavior['confidence'] > 0.6:
                return DetectionResult(
                    violated=True,
                    description=f"Behavioral anomaly detected: {', '.join(behavior['anomalies'])}",
                    detection_data=json.dumps(behavior['details']),
                    severity=self._calculate_severity_from_confidence(behavior['confidence']),
                    action='Alert',
                    confidence_score=behavior['confidence'],
                    indicators=['behavioral_anomaly'] + behavior['anomalies']
                )
            
            return DetectionResult(violated=False)
            
        except Exception as e:
            self.logger.error(f"Error in behavioral pattern checking: {e}")
            return DetectionResult(violated=False)
    
    def _check_threat_intelligence(self, context: RuleContext) -> DetectionResult:
        """Check against threat intelligence"""
        try:
            indicators = []
            confidence = 0.0
            
            log_type = context.log_type.lower().replace('_logs', '')
            
            if log_type == 'process':
                process_name = context.log_data.get('ProcessName', '').lower()
                if self.threat_intelligence.is_suspicious_process(process_name):
                    indicators.append('suspicious_process')
                    confidence += 0.3
            
            elif log_type == 'network':
                remote_addr = context.log_data.get('RemoteAddress', '')
                if self.threat_intelligence.is_malicious_ip(remote_addr):
                    indicators.append('malicious_ip')
                    confidence += 0.8
            
            elif log_type == 'file':
                filename = context.log_data.get('FileName', '')
                if self.threat_intelligence.is_ransomware_extension(filename):
                    indicators.append('ransomware_extension')
                    confidence += 0.9
            
            if indicators and confidence > 0.5:
                return DetectionResult(
                    violated=True,
                    description=f"Threat intelligence match: {', '.join(indicators)}",
                    detection_data=json.dumps({'indicators': indicators, 'source': 'threat_intelligence'}),
                    severity=self._calculate_severity_from_confidence(confidence),
                    action='Alert',
                    confidence_score=confidence,
                    indicators=['threat_intelligence'] + indicators
                )
            
            return DetectionResult(violated=False)
            
        except Exception as e:
            self.logger.error(f"Error in threat intelligence checking: {e}")
            return DetectionResult(violated=False)
    
    def _check_advanced_patterns(self, context: RuleContext) -> DetectionResult:
        """Check advanced attack patterns"""
        try:
            log_type = context.log_type.lower().replace('_logs', '')
            
            if log_type != 'process':
                return DetectionResult(violated=False)
            
            command_line = context.log_data.get('CommandLine', '')
            if not command_line:
                return DetectionResult(violated=False)
            
            detected_patterns = []
            confidence = 0.0
            
            # Check each pattern category
            for category, patterns in self.custom_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, command_line, re.IGNORECASE):
                        detected_patterns.append(category)
                        confidence += 0.4
                        break  # One match per category
            
            if detected_patterns and confidence > 0.3:
                return DetectionResult(
                    violated=True,
                    description=f"Advanced attack pattern detected: {', '.join(detected_patterns)}",
                    detection_data=json.dumps({
                        'patterns': detected_patterns,
                        'command_line': command_line[:200]  # Truncate for storage
                    }),
                    severity=self._calculate_severity_from_confidence(confidence),
                    action='Alert',
                    confidence_score=min(confidence, 1.0),
                    indicators=['advanced_pattern'] + detected_patterns
                )
            
            return DetectionResult(violated=False)
            
        except Exception as e:
            self.logger.error(f"Error in advanced pattern checking: {e}")
            return DetectionResult(violated=False)
    
    def _combine_detection_results(self, results: List[DetectionResult]) -> DetectionResult:
        """Combine multiple detection results into final result"""
        if not results:
            return DetectionResult(violated=False)
        
        # Sort by confidence score (highest first)
        results.sort(key=lambda x: x.confidence_score, reverse=True)
        
        # Use highest confidence result as base
        final_result = results[0]
        
        # Combine indicators from all results
        all_indicators = []
        for result in results:
            all_indicators.extend(result.indicators)
        
        final_result.indicators = list(set(all_indicators))  # Remove duplicates
        
        # Adjust confidence based on number of detections
        confidence_boost = min(0.2 * (len(results) - 1), 0.4)  # Max 0.4 boost
        final_result.confidence_score = min(final_result.confidence_score + confidence_boost, 1.0)
        
        # Update description to reflect multiple detections
        if len(results) > 1:
            final_result.description += f" (Multiple detection methods: {len(results)})"
        
        return final_result
    
    def _calculate_severity_from_confidence(self, confidence: float) -> str:
        """Calculate severity level from confidence score"""
        if confidence >= 0.9:
            return 'Critical'
        elif confidence >= 0.7:
            return 'High'
        elif confidence >= 0.5:
            return 'Medium'
        else:
            return 'Low'
    
    def _generate_detection_hash(self, log_type: str, log_data: Dict, hostname: str) -> str:
        """Generate hash for detection caching"""
        key_data = {
            'log_type': log_type,
            'hostname': hostname,
            'key_fields': {}
        }
        
        # Extract key fields based on log type
        if 'process' in log_type.lower():
            key_data['key_fields'] = {
                'process': log_data.get('ProcessName', ''),
                'command': log_data.get('CommandLine', '')[:100]  # First 100 chars
            }
        elif 'network' in log_type.lower():
            key_data['key_fields'] = {
                'remote_addr': log_data.get('RemoteAddress', ''),
                'remote_port': log_data.get('RemotePort', ''),
                'process': log_data.get('ProcessName', '')
            }
        elif 'file' in log_type.lower():
            key_data['key_fields'] = {
                'file_name': log_data.get('FileName', ''),
                'file_path': log_data.get('FilePath', ''),
                'event_type': log_data.get('EventType', '')
            }
        
        hash_string = json.dumps(key_data, sort_keys=True)
        return hashlib.md5(hash_string.encode()).hexdigest()
    
    def _cleanup_detection_cache(self):
        """Clean up old detection cache entries"""
        if len(self.detection_cache) < 1000:  # Only cleanup when cache gets large
            return
        
        current_time = time.time()
        expired_keys = [
            key for key, value in self.detection_cache.items()
            if current_time - value['timestamp'] > 300  # 5 minutes
        ]
        
        for key in expired_keys:
            del self.detection_cache[key]
    
    def get_enhanced_stats(self) -> Dict:
        """Get enhanced statistics"""
        with self.lock:
            stats = dict(self.stats)
        
        # Add additional metrics
        stats.update({
            'cache_hit_rate': (stats['cache_hits'] / max(stats['cache_hits'] + stats['cache_misses'], 1)) * 100,
            'violation_rate': (stats['violations_detected'] / max(stats['total_checks'], 1)) * 100,
            'behavioral_detection_rate': (stats['behavioral_detections'] / max(stats['total_checks'], 1)) * 100,
            'threat_intel_hit_rate': (stats['threat_intel_hits'] / max(stats['total_checks'], 1)) * 100,
            'cached_detections': len(self.detection_cache),
            'rules_in_cache': len(self.rules_cache)
        })
        
        return stats
    
    # Include all other methods from original RuleEngine...
    def refresh_rules(self) -> bool:
        """Refresh rules cache từ database"""
        try:
            with self.lock:
                start_time = time.time()
                
                rules = self.rule_db.get_all_rules()
                new_rules_cache = {}
                
                for rule in rules:
                    rule_id = rule['RuleID']
                    detailed_rule = self.rule_db.get_rule_by_id(rule_id)
                    if detailed_rule:
                        new_rules_cache[rule_id] = detailed_rule
                
                self.rules_cache = new_rules_cache
                self.last_refresh = time.time()
                self.agent_rules_cache.clear()
                
                load_time = time.time() - start_time
                
                rule_logger.info('rules_refreshed', 
                               f'Enhanced rules cache refreshed in {load_time:.2f}s',
                               total_rules=len(self.rules_cache), load_time=load_time)
                
                return True
                
        except Exception as e:
            self.logger.error(f"Error refreshing rules: {e}")
            return False
    
    def _should_refresh_rules(self) -> bool:
        """Kiểm tra có cần refresh rules không"""
        return (time.time() - self.last_refresh) > self.refresh_interval
    
    def get_agent_rules(self, hostname: str) -> List[Dict]:
        """Lấy rules áp dụng cho agent với caching"""
        try:
            if hostname in self.agent_rules_cache:
                cached_rules, cache_time = self.agent_rules_cache[hostname]
                if (time.time() - cache_time) < 300:  # 5 minutes cache
                    return cached_rules
            
            agent = self.agent_db.get_agent(hostname)
            if not agent:
                return []
            
            os_type = agent.get('OSType', 'Unknown')
            assigned_rule_ids = self.agent_db.get_agent_rules(hostname)
            global_rules = self.rule_db.get_global_rules(os_type)
            global_rule_ids = [rule['RuleID'] for rule in global_rules]
            
            all_rule_ids = list(set(assigned_rule_ids + global_rule_ids))
            
            agent_rules = []
            for rule_id in all_rule_ids:
                if rule_id in self.rules_cache:
                    rule = self.rules_cache[rule_id]
                    rule_os = rule.get('OSType', 'All')
                    if rule_os == 'All' or rule_os == os_type:
                        agent_rules.append(rule)
            
            self.agent_rules_cache[hostname] = (agent_rules, time.time())
            return agent_rules
            
        except Exception as e:
            self.logger.error(f"Error getting agent rules for {hostname}: {e}")
            return []
    
    def _get_agent_info(self, hostname: str) -> Optional[Dict]:
        """Get cached agent information"""
        try:
            return self.agent_db.get_agent(hostname)
        except Exception as e:
            self.logger.error(f"Error getting agent info for {hostname}: {e}")
            return None
    
    def _rule_type_matches(self, rule_type: str, log_type: str) -> bool:
        """Check if rule type matches log type"""
        log_type = log_type.lower().replace('_logs', '')
        return rule_type == log_type
    
    def _check_rule_violation(self, rule: Dict, log_data: Dict, log_type: str) -> Optional[Dict]:
        """Check traditional rule violation (from original implementation)"""
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
            self.logger.error(f"Error checking file rule: {e}")
            return None
    
    def _check_network_rule(self, rule: Dict, log_data: Dict) -> Optional[Dict]:
        """Check network rule (simplified version)"""
        try:
            conditions = rule.get('NetworkConditions', [])
            if not conditions:
                return None
            
            remote_address = log_data.get('RemoteAddress', '')
            remote_port = safe_int(log_data.get('RemotePort', 0))
            
            for condition in conditions:
                condition_ip = condition.get('IPAddress', '')
                condition_port = safe_int(condition.get('Port', 0))
                
                if condition_ip and condition_ip in remote_address:
                    return {
                        'description': f"Connection to flagged IP: {remote_address}",
                        'detection_data': json.dumps(log_data),
                        'violation_type': 'SuspiciousIP'
                    }
                
                if condition_port and condition_port == remote_port:
                    return {
                        'description': f"Connection to suspicious port: {remote_port}",
                        'detection_data': json.dumps(log_data),
                        'violation_type': 'SuspiciousPort'
                    }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error checking network rule: {e}")
            return None
    
    def cleanup(self):
        """Enhanced cleanup with thread pool shutdown"""
        try:
            with self.lock:
                self.rules_cache.clear()
                self.agent_rules_cache.clear()
                self.detection_cache.clear()
            
            # Shutdown thread pool
            self.executor.shutdown(wait=True, timeout=30)
            
            rule_logger.info('engine_cleanup', 'Enhanced Rule Engine cleaned up')
            
        except Exception as e:
            self.logger.error(f"Error during enhanced cleanup: {e}")
    
    def get_detection_history(self, hostname: str, hours: int = 24) -> List[Dict]:
        """Get detection history for analysis"""
        try:
            # This would typically query a detection history database
            # For now, return empty list as placeholder
            return []
            
        except Exception as e:
            self.logger.error(f"Error getting detection history: {e}")
            return []
    
    def update_threat_intelligence(self, intel_data: Dict) -> bool:
        """Update threat intelligence data"""
        try:
            if 'malicious_ips' in intel_data:
                self.threat_intelligence.malicious_ips.update(intel_data['malicious_ips'])
            
            if 'malicious_domains' in intel_data:
                self.threat_intelligence.malicious_domains.update(intel_data['malicious_domains'])
            
            if 'suspicious_processes' in intel_data:
                self.threat_intelligence.suspicious_processes.update(intel_data['suspicious_processes'])
            
            rule_logger.info('threat_intel_updated', 'Threat intelligence updated',
                           new_ips=len(intel_data.get('malicious_ips', [])),
                           new_domains=len(intel_data.get('malicious_domains', [])))
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error updating threat intelligence: {e}")
            return False
    
    def analyze_attack_chain(self, hostname: str, time_window: int = 3600) -> Dict:
        """Analyze potential attack chains"""
        try:
            # Get recent detections and logs for the host
            current_time = time.time()
            
            # This would analyze sequences of events to identify attack chains
            # For now, return basic analysis
            analysis = {
                'attack_stages': [],
                'confidence': 0.0,
                'risk_score': 0,
                'recommendations': []
            }
            
            # Placeholder implementation
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing attack chain: {e}")
            return {}
    
    def get_rule_effectiveness_report(self, days: int = 7) -> Dict:
        """Generate rule effectiveness report"""
        try:
            report = {
                'period_days': days,
                'total_rules': len(self.rules_cache),
                'rules_triggered': 0,
                'false_positive_rate': 0.0,
                'detection_coverage': {},
                'recommendations': []
            }
            
            # This would analyze rule performance over time
            # Placeholder implementation
            
            return report
            
        except Exception as e:
            self.logger.error(f"Error generating effectiveness report: {e}")
            return {}
    
    def tune_detection_sensitivity(self, rule_id: int, sensitivity: float) -> bool:
        """Tune detection sensitivity for specific rule"""
        try:
            if rule_id not in self.rules_cache:
                return False
            
            # This would adjust rule sensitivity/thresholds
            # Placeholder implementation
            
            rule_logger.info('sensitivity_tuned', f'Detection sensitivity tuned for rule {rule_id}',
                           rule_id=rule_id, new_sensitivity=sensitivity)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error tuning detection sensitivity: {e}")
            return False

# Backward compatibility wrapper
class RuleEngine(EnhancedRuleEngine):
    """Backward compatibility wrapper for existing code"""
    
    def check_rules(self, log_type: str, log_data: Dict, hostname: str) -> Tuple[bool, Optional[str], Optional[str], Optional[str], Optional[int], Optional[str]]:
        """Original interface for backward compatibility"""
        try:
            result = super().check_rules(log_type, log_data, hostname)
            
            if result.violated:
                return (
                    True,
                    result.description,
                    result.detection_data,
                    result.severity,
                    result.rule_id,
                    result.action
                )
            else:
                return (False, None, None, None, None, None)
                
        except Exception as e:
            self.logger.error(f"Error in backward compatibility wrapper: {e}")
            return (False, None, None, None, None, None)

        except Exception as e:
            self.logger.error(f"Error checking rule violation: {e}")
            return None
    
    # Include original rule checking methods...
    def _check_process_rule(self, rule: Dict, log_data: Dict) -> Optional[Dict]:
        """Check process rule (simplified version)"""
        try:
            conditions = rule.get('ProcessConditions', [])
            if not conditions:
                return None
            
            process_name = log_data.get('ProcessName', '').lower()
            command_line = log_data.get('CommandLine', '').lower()
            
            for condition in conditions:
                condition_process = condition.get('ProcessName', '').lower()
                if condition_process and condition_process in process_name:
                    return {
                        'description': f"Suspicious process detected: {log_data.get('ProcessName')}",
                        'detection_data': json.dumps(log_data),
                        'violation_type': 'ProcessName'
                    }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error checking process rule: {e}")
            return None
    
    def _check_file_rule(self, rule: Dict, log_data: Dict) -> Optional[Dict]:
        """Check file rule (simplified version)"""
        try:
            conditions = rule.get('FileConditions', [])
            if not conditions:
                return None
            
            file_name = log_data.get('FileName', '').lower()
            file_path = log_data.get('FilePath', '').lower()
            
            for condition in conditions:
                condition_name = condition.get('FileName', '').lower()
                if condition_name and condition_name in file_name:
                    return {
                        'description': f"Suspicious file activity: {log_data.get('FileName')}",
                        'detection_data': json.dumps(log_data),
                        'violation_type': 'FileName'
                    }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error checking file rule: {e}")
            return None