"""
Helper functions cho EDR Server
"""

import re
import json
import hashlib
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union, Tuple
import uuid

def validate_hostname(hostname: str) -> bool:
    """Validate hostname format"""
    if not hostname or len(hostname) > 255:
        return False
    
    # Hostname pattern: letters, numbers, hyphens, dots
    pattern = r'^[a-zA-Z0-9\-._]+$'
    return bool(re.match(pattern, hostname))

def validate_ip_address(ip: str) -> bool:
    """Validate IP address (IPv4 or IPv6)"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_mac_address(mac: str) -> bool:
    """Validate MAC address format"""
    if not mac:
        return False
    
    # MAC address patterns
    patterns = [
        r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$',  # XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
        r'^([0-9A-Fa-f]{4}\.){2}([0-9A-Fa-f]{4})$'     # XXXX.XXXX.XXXX
    ]
    
    return any(re.match(pattern, mac) for pattern in patterns)

def normalize_hostname(hostname: str) -> str:
    """Normalize hostname to standard format"""
    if not hostname:
        return ""
    
    # Convert to lowercase and strip whitespace
    normalized = hostname.lower().strip()
    
    # Remove invalid characters
    normalized = re.sub(r'[^a-zA-Z0-9\-._]', '', normalized)
    
    return normalized

def normalize_mac_address(mac: str) -> str:
    """Normalize MAC address to standard format (XX:XX:XX:XX:XX:XX)"""
    if not mac:
        return ""
    
    # Remove all separators and convert to uppercase
    clean_mac = re.sub(r'[:-.]', '', mac).upper()
    
    if len(clean_mac) != 12:
        return ""
    
    # Format as XX:XX:XX:XX:XX:XX
    return ':'.join(clean_mac[i:i+2] for i in range(0, 12, 2))

def generate_unique_id() -> str:
    """Generate unique ID for various purposes"""
    return str(uuid.uuid4())

def generate_hash(data: Union[str, dict]) -> str:
    """Generate SHA256 hash of data"""
    if isinstance(data, dict):
        data = json.dumps(data, sort_keys=True)
    
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def parse_time_range(time_str: str) -> Optional[datetime]:
    """Parse time string to datetime object"""
    if not time_str:
        return None
    
    # Common time formats
    formats = [
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%d %H:%M',
        '%Y-%m-%d',
        '%Y/%m/%d %H:%M:%S',
        '%Y/%m/%d',
        '%d/%m/%Y %H:%M:%S',
        '%d/%m/%Y',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M:%SZ'
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(time_str, fmt)
        except ValueError:
            continue
    
    return None

def calculate_time_ago(timestamp: Union[datetime, str]) -> str:
    """Calculate human-readable time ago string"""
    if not timestamp:
        return "Unknown"
    
    try:
        if isinstance(timestamp, str):
            timestamp = parse_time_range(timestamp)
        
        if not timestamp:
            return "Unknown"
        
        now = datetime.now()
        diff = now - timestamp
        
        if diff.days > 365:
            years = diff.days // 365
            return f"{years} year{'s' if years > 1 else ''} ago"
        elif diff.days > 30:
            months = diff.days // 30
            return f"{months} month{'s' if months > 1 else ''} ago"
        elif diff.days > 0:
            return f"{diff.days} day{'s' if diff.days > 1 else ''} ago"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"{hours} hour{'s' if hours > 1 else ''} ago"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
        else:
            return "Just now"
            
    except Exception:
        return "Unknown"

def format_file_size(size_bytes: int) -> str:
    """Format file size in human readable format"""
    if not size_bytes or size_bytes < 0:
        return "0 B"
    
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    
    return f"{size_bytes:.1f} PB"

def sanitize_string(text: str, max_length: int = 255) -> str:
    """Sanitize string for safe storage/display"""
    if not text:
        return ""
    
    # Remove control characters and limit length
    sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', str(text))
    
    return sanitized[:max_length] if len(sanitized) > max_length else sanitized

def validate_json(json_str: str) -> Tuple[bool, Optional[dict]]:
    """Validate JSON string and return parsed data"""
    try:
        data = json.loads(json_str)
        return True, data
    except (json.JSONDecodeError, TypeError):
        return False, None

def merge_dictionaries(*dicts) -> dict:
    """Merge multiple dictionaries, later ones override earlier ones"""
    result = {}
    for d in dicts:
        if isinstance(d, dict):
            result.update(d)
    return result

def extract_domain_from_email(email: str) -> str:
    """Extract domain from email address"""
    if not email or '@' not in email:
        return ""
    
    try:
        return email.split('@')[1].lower()
    except IndexError:
        return ""

def is_private_ip(ip: str) -> bool:
    """Check if IP address is in private ranges"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

def get_ip_info(ip: str) -> dict:
    """Get information about IP address"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return {
            'ip': str(ip_obj),
            'version': ip_obj.version,
            'is_private': ip_obj.is_private,
            'is_multicast': ip_obj.is_multicast,
            'is_reserved': ip_obj.is_reserved,
            'is_loopback': ip_obj.is_loopback
        }
    except ValueError:
        return {
            'ip': ip,
            'version': 0,
            'is_private': False,
            'is_multicast': False,
            'is_reserved': False,
            'is_loopback': False,
            'error': 'Invalid IP address'
        }

def chunk_list(lst: List, chunk_size: int) -> List[List]:
    """Split list into chunks of specified size"""
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]

def safe_int(value: Any, default: int = 0) -> int:
    """Safely convert value to integer"""
    try:
        if isinstance(value, str) and value.strip() == '':
            return default
        return int(float(value))
    except (ValueError, TypeError):
        return default

def safe_float(value: Any, default: float = 0.0) -> float:
    """Safely convert value to float"""
    try:
        if isinstance(value, str) and value.strip() == '':
            return default
        return float(value)
    except (ValueError, TypeError):
        return default

def safe_bool(value: Any, default: bool = False) -> bool:
    """Safely convert value to boolean"""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ['true', '1', 'yes', 'on', 'enabled']
    if isinstance(value, (int, float)):
        return bool(value)
    return default

def truncate_text(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """Truncate text to specified length with suffix"""
    if not text or len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix

def extract_filename_from_path(file_path: str) -> str:
    """Extract filename from file path"""
    if not file_path:
        return ""
    
    # Handle both Windows and Unix paths
    return file_path.split('\\')[-1].split('/')[-1]

def extract_file_extension(filename: str) -> str:
    """Extract file extension from filename"""
    if not filename or '.' not in filename:
        return ""
    
    return filename.split('.')[-1].lower()

def is_executable_file(filename: str) -> bool:
    """Check if file is executable based on extension"""
    if not filename:
        return False
    
    executable_extensions = [
        'exe', 'bat', 'cmd', 'com', 'scr', 'msi', 'dll',
        'sh', 'bin', 'run', 'app', 'deb', 'rpm'
    ]
    
    extension = extract_file_extension(filename)
    return extension in executable_extensions

def is_suspicious_process(process_name: str) -> bool:
    """Check if process name is potentially suspicious"""
    if not process_name:
        return False
    
    suspicious_processes = [
        'cmd.exe', 'powershell.exe', 'wmic.exe', 'net.exe',
        'reg.exe', 'schtasks.exe', 'at.exe', 'sc.exe',
        'taskkill.exe', 'wevtutil.exe', 'vssadmin.exe',
        'bcdedit.exe', 'bootcfg.exe', 'cacls.exe'
    ]
    
    return process_name.lower() in [p.lower() for p in suspicious_processes]

def normalize_process_path(path: str) -> str:
    """Normalize process path for comparison"""
    if not path:
        return ""
    
    # Convert to lowercase and normalize separators
    normalized = path.lower().replace('\\', '/')
    
    # Remove quotes
    normalized = normalized.strip('"\'')
    
    return normalized

def extract_command_args(command_line: str) -> List[str]:
    """Extract command line arguments"""
    if not command_line:
        return []
    
    # Simple argument parsing (can be enhanced)
    import shlex
    try:
        return shlex.split(command_line)
    except ValueError:
        # Fallback to simple split if shlex fails
        return command_line.split()

def detect_port_service(port: int) -> str:
    """Detect common service running on port"""
    common_ports = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        135: 'RPC',
        139: 'NetBIOS',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        993: 'IMAPS',
        995: 'POP3S',
        1433: 'SQL Server',
        1521: 'Oracle',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        6379: 'Redis',
        27017: 'MongoDB'
    }
    
    return common_ports.get(port, f'Unknown ({port})')

def calculate_risk_score(factors: Dict[str, Any]) -> int:
    """Calculate risk score based on various factors"""
    score = 0
    
    # Process-based factors
    if factors.get('is_suspicious_process'):
        score += 30
    
    if factors.get('has_suspicious_command'):
        score += 25
    
    if factors.get('runs_as_admin'):
        score += 15
    
    # File-based factors
    if factors.get('is_executable'):
        score += 10
    
    if factors.get('in_temp_directory'):
        score += 20
    
    if factors.get('recently_created'):
        score += 15
    
    # Network-based factors
    if factors.get('external_connection'):
        score += 20
    
    if factors.get('suspicious_port'):
        score += 25
    
    if factors.get('high_traffic_volume'):
        score += 15
    
    # Cap at 100
    return min(score, 100)

def format_bytes_per_second(bytes_per_sec: float) -> str:
    """Format network speed in human readable format"""
    for unit in ['B/s', 'KB/s', 'MB/s', 'GB/s']:
        if bytes_per_sec < 1024.0:
            return f"{bytes_per_sec:.1f} {unit}"
        bytes_per_sec /= 1024.0
    return f"{bytes_per_sec:.1f} TB/s"

def get_severity_color(severity: str) -> str:
    """Get color code for severity level"""
    colors = {
        'critical': '#dc3545',
        'high': '#fd7e14', 
        'medium': '#ffc107',
        'low': '#28a745',
        'info': '#17a2b8'
    }
    return colors.get(severity.lower(), '#6c757d')

def get_severity_priority(severity: str) -> int:
    """Get numeric priority for severity (higher = more severe)"""
    priorities = {
        'critical': 4,
        'high': 3,
        'medium': 2,
        'low': 1,
        'info': 0
    }
    return priorities.get(severity.lower(), 0)

def filter_sensitive_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """Filter out sensitive data from logs/alerts"""
    sensitive_keys = [
        'password', 'passwd', 'pwd', 'token', 'key', 'secret',
        'api_key', 'auth', 'credential', 'authorization'
    ]
    
    filtered = {}
    for key, value in data.items():
        if any(sensitive in key.lower() for sensitive in sensitive_keys):
            filtered[key] = '***REDACTED***'
        elif isinstance(value, dict):
            filtered[key] = filter_sensitive_data(value)
        else:
            filtered[key] = value
    
    return filtered

def create_detection_signature(log_data: Dict[str, Any]) -> str:
    """Create unique signature for detection/alert"""
    # Extract key fields for signature
    key_fields = []
    
    if 'ProcessName' in log_data:
        key_fields.append(f"process:{log_data['ProcessName']}")
    
    if 'FileName' in log_data:
        key_fields.append(f"file:{log_data['FileName']}")
    
    if 'RemoteAddress' in log_data:
        key_fields.append(f"remote:{log_data['RemoteAddress']}")
    
    if 'RemotePort' in log_data:
        key_fields.append(f"port:{log_data['RemotePort']}")
    
    signature_string = "|".join(key_fields)
    return generate_hash(signature_string)

def validate_agent_version(version: str) -> bool:
    """Validate agent version format"""
    if not version:
        return False
    
    # Version format: X.Y.Z or X.Y.Z.W
    pattern = r'^\d+\.\d+\.\d+(\.\d+)?$'
    return bool(re.match(pattern, version))

def compare_versions(version1: str, version2: str) -> int:
    """Compare two version strings. Returns -1, 0, or 1"""
    try:
        v1_parts = [int(x) for x in version1.split('.')]
        v2_parts = [int(x) for x in version2.split('.')]
        
        # Pad shorter version with zeros
        max_len = max(len(v1_parts), len(v2_parts))
        v1_parts += [0] * (max_len - len(v1_parts))
        v2_parts += [0] * (max_len - len(v2_parts))
        
        for v1, v2 in zip(v1_parts, v2_parts):
            if v1 < v2:
                return -1
            elif v1 > v2:
                return 1
        
        return 0
        
    except (ValueError, AttributeError):
        return 0

def create_error_response(message: str, code: int = 500, details: Any = None) -> Dict[str, Any]:
    """Create standardized error response"""
    response = {
        'status': 'error',
        'message': message,
        'code': code,
        'timestamp': datetime.now().isoformat()
    }
    
    if details:
        response['details'] = details
    
    return response

def create_success_response(data: Any = None, message: str = None) -> Dict[str, Any]:
    """Create standardized success response"""
    response = {
        'status': 'success',
        'timestamp': datetime.now().isoformat()
    }
    
    if data is not None:
        response['data'] = data
    
    if message:
        response['message'] = message
    
    return response

def paginate_results(data: List[Any], page: int = 1, per_page: int = 50) -> Dict[str, Any]:
    """Paginate list of results"""
    total = len(data)
    start = (page - 1) * per_page
    end = start + per_page
    
    return {
        'data': data[start:end],
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': (total + per_page - 1) // per_page,
            'has_next': end < total,
            'has_prev': page > 1
        }
    }

def rate_limit_key(identifier: str, action: str) -> str:
    """Generate rate limit key"""
    return f"rate_limit:{identifier}:{action}"

class DataValidator:
    """Data validation utility class"""
    
    @staticmethod
    def validate_required_fields(data: Dict, required_fields: List[str]) -> Tuple[bool, List[str]]:
        """Validate required fields in data"""
        missing_fields = []
        
        for field in required_fields:
            if field not in data or data[field] is None or data[field] == '':
                missing_fields.append(field)
        
        return len(missing_fields) == 0, missing_fields
    
    @staticmethod
    def validate_field_types(data: Dict, field_types: Dict[str, type]) -> Tuple[bool, List[str]]:
        """Validate field types"""
        type_errors = []
        
        for field, expected_type in field_types.items():
            if field in data and data[field] is not None:
                if not isinstance(data[field], expected_type):
                    type_errors.append(f"{field} must be of type {expected_type.__name__}")
        
        return len(type_errors) == 0, type_errors
    
    @staticmethod
    def validate_string_length(data: Dict, length_limits: Dict[str, int]) -> Tuple[bool, List[str]]:
        """Validate string field lengths"""
        length_errors = []
        
        for field, max_length in length_limits.items():
            if field in data and isinstance(data[field], str):
                if len(data[field]) > max_length:
                    length_errors.append(f"{field} exceeds maximum length of {max_length}")
        
        return len(length_errors) == 0, length_errors

# Export commonly used functions
__all__ = [
    'validate_hostname', 'validate_ip_address', 'validate_mac_address',
    'normalize_hostname', 'normalize_mac_address', 'generate_unique_id',
    'generate_hash', 'parse_time_range', 'calculate_time_ago',
    'format_file_size', 'sanitize_string', 'validate_json',
    'is_private_ip', 'get_ip_info', 'safe_int', 'safe_float', 'safe_bool',
    'is_executable_file', 'is_suspicious_process', 'detect_port_service',
    'calculate_risk_score', 'get_severity_color', 'filter_sensitive_data',
    'create_detection_signature', 'create_error_response', 'create_success_response',
    'paginate_results', 'DataValidator'
]