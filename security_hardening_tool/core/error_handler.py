"""Error handling and recovery mechanisms for the security hardening tool."""

import logging
import os
import platform
import psutil
import socket
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple

from .interfaces import ErrorHandler as ErrorHandlerInterface
from .models import (
    HardeningError, SystemError, ConfigurationError, ValidationError,
    BackupError, NetworkError, OperationResult, Severity
)


class ErrorHandler(ErrorHandlerInterface):
    """Comprehensive error handling with categorization and recovery mechanisms."""
    
    def __init__(self, logger=None):
        """Initialize error handler with optional logger."""
        self.logger = logger or logging.getLogger(__name__)
        self._error_categories = {
            'permission': ['permission denied', 'access denied', 'unauthorized', 'privilege'],
            'resource': ['memory', 'disk space', 'storage', 'cpu', 'resource'],
            'network': ['network', 'connection', 'timeout', 'dns', 'unreachable'],
            'configuration': ['invalid', 'malformed', 'syntax', 'format'],
            'system': ['system', 'os', 'platform', 'service', 'process'],
            'backup': ['backup', 'restore', 'rollback', 'checksum', 'integrity']
        }
        
    def handle_error(self, error: Exception) -> OperationResult:
        """Handle and categorize errors with appropriate response."""
        try:
            # Categorize the error
            error_category = self._categorize_error(error)
            severity = self._assess_severity(error, error_category)
            
            # Log the error with context
            self._log_error_with_context(error, error_category, severity)
            
            # Generate user-friendly message
            user_message = self._generate_user_message(error, error_category)
            
            # Get remediation suggestions
            remediation_steps = self.suggest_remediation(error)
            
            # Attempt automatic recovery if appropriate
            recovery_attempted = False
            recovery_successful = False
            
            if self._should_attempt_recovery(error, error_category):
                recovery_attempted = True
                recovery_successful = self.attempt_recovery(error)
                
            return OperationResult(
                success=recovery_successful,
                message=user_message,
                data={
                    'error_category': error_category,
                    'severity': severity.value,
                    'error_code': getattr(error, 'error_code', 'UNKNOWN'),
                    'recoverable': getattr(error, 'recoverable', True),
                    'recovery_attempted': recovery_attempted,
                    'recovery_successful': recovery_successful,
                    'remediation_steps': remediation_steps
                },
                errors=[str(error)] if not recovery_successful else [],
                warnings=[] if recovery_successful else remediation_steps
            )
            
        except Exception as handler_error:
            # Fallback error handling
            self.logger.error(f"Error in error handler: {handler_error}")
            return OperationResult(
                success=False,
                message=f"An unexpected error occurred: {str(error)}",
                errors=[str(error), f"Handler error: {str(handler_error)}"]
            )
    
    def suggest_remediation(self, error: Exception) -> List[str]:
        """Suggest remediation steps for errors."""
        error_category = self._categorize_error(error)
        error_msg = str(error).lower()
        
        remediation_steps = []
        
        if error_category == 'permission':
            remediation_steps.extend(self._get_permission_remediation(error_msg))
        elif error_category == 'resource':
            remediation_steps.extend(self._get_resource_remediation(error_msg))
        elif error_category == 'network':
            remediation_steps.extend(self._get_network_remediation(error_msg))
        elif error_category == 'configuration':
            remediation_steps.extend(self._get_configuration_remediation(error_msg))
        elif error_category == 'system':
            remediation_steps.extend(self._get_system_remediation(error_msg))
        elif error_category == 'backup':
            remediation_steps.extend(self._get_backup_remediation(error_msg))
        else:
            remediation_steps.extend(self._get_generic_remediation(error_msg))
            
        return remediation_steps
    
    def attempt_recovery(self, error: Exception) -> bool:
        """Attempt automatic error recovery."""
        error_category = self._categorize_error(error)
        
        try:
            if error_category == 'permission':
                return self._attempt_permission_recovery(error)
            elif error_category == 'resource':
                return self._attempt_resource_recovery(error)
            elif error_category == 'network':
                return self._attempt_network_recovery(error)
            elif error_category == 'system':
                return self._attempt_system_recovery(error)
            else:
                return False
                
        except Exception as recovery_error:
            self.logger.error(f"Recovery attempt failed: {recovery_error}")
            return False
    
    def _categorize_error(self, error: Exception) -> str:
        """Categorize error based on type and message."""
        error_msg = str(error).lower()
        error_type = type(error).__name__.lower()
        
        # Check exception type first
        if isinstance(error, SystemError):
            return 'system'
        elif isinstance(error, ConfigurationError):
            return 'configuration'
        elif isinstance(error, ValidationError):
            return 'configuration'
        elif isinstance(error, BackupError):
            return 'backup'
        elif isinstance(error, NetworkError):
            return 'network'
        elif isinstance(error, PermissionError):
            return 'permission'
        elif isinstance(error, OSError):
            return 'system'
        
        # Check message content
        for category, keywords in self._error_categories.items():
            if any(keyword in error_msg or keyword in error_type for keyword in keywords):
                return category
                
        return 'unknown'
    
    def _assess_severity(self, error: Exception, category: str) -> Severity:
        """Assess error severity based on type and impact."""
        if hasattr(error, 'severity'):
            return error.severity
            
        # High severity conditions
        if category in ['permission', 'system'] and 'critical' in str(error).lower():
            return Severity.CRITICAL
        elif category == 'backup' and 'corruption' in str(error).lower():
            return Severity.CRITICAL
        elif category == 'resource' and ('memory' in str(error).lower() or 'disk' in str(error).lower()):
            return Severity.HIGH
        elif category == 'permission':
            return Severity.HIGH
        elif category in ['network', 'configuration']:
            return Severity.MEDIUM
        else:
            return Severity.LOW
    
    def _should_attempt_recovery(self, error: Exception, category: str) -> bool:
        """Determine if automatic recovery should be attempted."""
        if hasattr(error, 'recoverable') and not error.recoverable:
            return False
            
        # Only attempt recovery for certain categories
        recoverable_categories = ['network', 'resource', 'system']
        return category in recoverable_categories
    
    def _get_permission_remediation(self, error_msg: str) -> List[str]:
        """Get remediation steps for permission errors."""
        steps = []
        
        if platform.system() == "Windows":
            steps.extend([
                "Run the application as Administrator:",
                "  1. Right-click on the application or command prompt",
                "  2. Select 'Run as administrator'",
                "  3. Click 'Yes' when prompted by UAC",
                "Check if your account has the necessary privileges:",
                "  1. Open 'Local Security Policy' (secpol.msc)",
                "  2. Navigate to 'User Rights Assignment'",
                "  3. Verify your account has required privileges"
            ])
        else:  # Linux
            steps.extend([
                "Run the command with sudo privileges:",
                "  sudo python3 -m security_hardening_tool [options]",
                "Check if your account is in the sudo group:",
                "  groups $USER",
                "If not in sudo group, add your user:",
                "  sudo usermod -aG sudo $USER",
                "  (then log out and back in)"
            ])
            
        return steps
    
    def _get_resource_remediation(self, error_msg: str) -> List[str]:
        """Get remediation steps for resource errors."""
        steps = []
        
        if 'memory' in error_msg:
            steps.extend([
                "Free up system memory:",
                "  1. Close unnecessary applications",
                "  2. Check for memory leaks in running processes",
                "  3. Consider increasing virtual memory/swap space",
                "Monitor memory usage: Task Manager (Windows) or 'free -h' (Linux)"
            ])
        elif 'disk' in error_msg or 'storage' in error_msg:
            steps.extend([
                "Free up disk space:",
                "  1. Delete temporary files and logs",
                "  2. Clean up old backups if safe to do so",
                "  3. Move large files to external storage",
                "Check disk usage: 'dir' (Windows) or 'df -h' (Linux)"
            ])
        else:
            steps.extend([
                "Check system resources:",
                "  1. Monitor CPU and memory usage",
                "  2. Close resource-intensive applications",
                "  3. Wait for system load to decrease"
            ])
            
        return steps
    
    def _get_network_remediation(self, error_msg: str) -> List[str]:
        """Get remediation steps for network errors."""
        return [
            "Check network connectivity:",
            "  1. Verify internet connection is active",
            "  2. Test DNS resolution: 'nslookup google.com'",
            "  3. Check firewall settings",
            "  4. Verify proxy settings if applicable",
            "If using VPN, try disconnecting temporarily",
            "Wait a moment and retry the operation"
        ]
    
    def _get_configuration_remediation(self, error_msg: str) -> List[str]:
        """Get remediation steps for configuration errors."""
        return [
            "Check configuration file syntax:",
            "  1. Verify YAML/JSON formatting is correct",
            "  2. Check for missing quotes or brackets",
            "  3. Validate parameter names and values",
            "Review the configuration documentation",
            "Use a configuration validator tool if available",
            "Compare with working configuration examples"
        ]
    
    def _get_system_remediation(self, error_msg: str) -> List[str]:
        """Get remediation steps for system errors."""
        return [
            "Check system status:",
            "  1. Verify required services are running",
            "  2. Check system logs for related errors",
            "  3. Ensure system is not in maintenance mode",
            "Try restarting the affected service",
            "Consider rebooting the system if safe to do so",
            "Check for system updates or patches"
        ]
    
    def _get_backup_remediation(self, error_msg: str) -> List[str]:
        """Get remediation steps for backup errors."""
        return [
            "Check backup integrity:",
            "  1. Verify backup files are not corrupted",
            "  2. Check available disk space for backups",
            "  3. Ensure backup directory is accessible",
            "If backup is corrupted, use an earlier backup",
            "Consider creating a new backup before proceeding",
            "Check backup storage permissions"
        ]
    
    def _get_generic_remediation(self, error_msg: str) -> List[str]:
        """Get generic remediation steps."""
        return [
            "General troubleshooting steps:",
            "  1. Check the error message for specific details",
            "  2. Verify system requirements are met",
            "  3. Ensure all dependencies are installed",
            "  4. Try running the operation again",
            "Check the application logs for more details",
            "Contact support if the issue persists"
        ]
    
    def _attempt_permission_recovery(self, error: Exception) -> bool:
        """Attempt to recover from permission errors."""
        # Check if we can detect privilege elevation
        if platform.system() == "Windows":
            return self._check_windows_elevation()
        else:
            return self._check_linux_sudo()
    
    def _attempt_resource_recovery(self, error: Exception) -> bool:
        """Attempt to recover from resource errors."""
        try:
            # Basic resource cleanup
            import gc
            gc.collect()
            
            # Check available resources
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # If resources are critically low, return False
            if memory.percent > 95 or disk.percent > 95:
                return False
                
            # Wait a moment for resources to free up
            time.sleep(2)
            return True
            
        except Exception:
            return False
    
    def _attempt_network_recovery(self, error: Exception) -> bool:
        """Attempt to recover from network errors."""
        try:
            # Simple connectivity test
            import socket
            socket.create_connection(("8.8.8.8", 53), timeout=5)
            return True
        except Exception:
            return False
    
    def _attempt_system_recovery(self, error: Exception) -> bool:
        """Attempt to recover from system errors."""
        # For now, just wait and return True to indicate retry is possible
        time.sleep(1)
        return True
    
    def _check_windows_elevation(self) -> bool:
        """Check if running with Windows administrator privileges."""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    
    def _check_linux_sudo(self) -> bool:
        """Check if running with sudo privileges or can use sudo."""
        try:
            # Check if running as root
            if os.geteuid() == 0:
                return True
                
            # Check if sudo is available
            result = subprocess.run(['sudo', '-n', 'true'], 
                                  capture_output=True, timeout=5)
            return result.returncode == 0
        except Exception:
            return False
    
    def _log_error_with_context(self, error: Exception, category: str, severity: Severity):
        """Log error with comprehensive context."""
        context = {
            'error_type': type(error).__name__,
            'error_message': str(error),
            'category': category,
            'severity': severity.value,
            'platform': platform.system(),
            'python_version': sys.version,
            'timestamp': time.time()
        }
        
        # Add system context
        try:
            context.update({
                'memory_usage': psutil.virtual_memory().percent,
                'disk_usage': psutil.disk_usage('/').percent,
                'cpu_count': psutil.cpu_count(),
                'process_id': os.getpid()
            })
        except Exception:
            pass  # Don't fail if we can't get system info
            
        self.logger.error(f"Error handled: {error}", extra={'context': context})
    
    def _generate_user_message(self, error: Exception, category: str) -> str:
        """Generate user-friendly error message."""
        base_messages = {
            'permission': "Permission denied. Administrator/root privileges may be required.",
            'resource': "System resources are insufficient. Please free up memory or disk space.",
            'network': "Network connectivity issue detected. Please check your connection.",
            'configuration': "Configuration error detected. Please check your settings.",
            'system': "System error occurred. Please check system status and logs.",
            'backup': "Backup operation failed. Please check backup integrity and storage.",
            'unknown': "An unexpected error occurred."
        }
        
        base_msg = base_messages.get(category, base_messages['unknown'])
        
        # Add specific error details if available
        if hasattr(error, 'message'):
            return f"{base_msg} Details: {error.message}"
        else:
            return f"{base_msg} Details: {str(error)}"


class PrivilegeEscalationHandler:
    """Handles privilege escalation detection and guidance."""
    
    @staticmethod
    def detect_privilege_requirements() -> Dict[str, bool]:
        """Detect current privilege level and requirements."""
        result = {
            'has_admin_privileges': False,
            'can_elevate': False,
            'elevation_method': None,
            'current_user': None
        }
        
        try:
            if platform.system() == "Windows":
                result.update(PrivilegeEscalationHandler._check_windows_privileges())
            else:
                result.update(PrivilegeEscalationHandler._check_linux_privileges())
        except Exception as e:
            logging.error(f"Error detecting privileges: {e}")
            
        return result
    
    @staticmethod
    def _check_windows_privileges() -> Dict[str, bool]:
        """Check Windows privilege status."""
        result = {}
        
        try:
            import ctypes
            result['has_admin_privileges'] = ctypes.windll.shell32.IsUserAnAdmin() != 0
            result['current_user'] = os.environ.get('USERNAME', 'Unknown')
            result['can_elevate'] = True  # Assume UAC is available
            result['elevation_method'] = 'UAC'
        except Exception:
            result['has_admin_privileges'] = False
            result['can_elevate'] = False
            
        return result
    
    @staticmethod
    def _check_linux_privileges() -> Dict[str, bool]:
        """Check Linux privilege status."""
        result = {}
        
        try:
            result['has_admin_privileges'] = os.geteuid() == 0
            result['current_user'] = os.environ.get('USER', 'Unknown')
            
            # Check if sudo is available
            sudo_result = subprocess.run(['sudo', '-n', 'true'], 
                                       capture_output=True, timeout=5)
            result['can_elevate'] = sudo_result.returncode == 0
            result['elevation_method'] = 'sudo' if result['can_elevate'] else None
        except Exception:
            result['has_admin_privileges'] = False
            result['can_elevate'] = False
            
        return result
    
    @staticmethod
    def get_elevation_guidance() -> List[str]:
        """Get platform-specific elevation guidance."""
        if platform.system() == "Windows":
            return [
                "To run with administrator privileges:",
                "1. Right-click on Command Prompt or PowerShell",
                "2. Select 'Run as administrator'",
                "3. Click 'Yes' when prompted by User Account Control (UAC)",
                "4. Re-run the security hardening tool from the elevated prompt"
            ]
        else:
            return [
                "To run with elevated privileges:",
                "1. Use sudo: sudo python3 -m security_hardening_tool [options]",
                "2. Or switch to root: su - (then run the tool)",
                "3. Ensure your user account is in the sudo group",
                "4. If not in sudo group: sudo usermod -aG sudo $USER"
            ]


class SystemResourceMonitor:
    """Monitors system resources and provides warnings."""
    
    @staticmethod
    def check_system_resources() -> Dict[str, any]:
        """Check current system resource usage."""
        try:
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            cpu_percent = psutil.cpu_percent(interval=1)
            
            return {
                'memory': {
                    'total': memory.total,
                    'available': memory.available,
                    'percent': memory.percent,
                    'warning': memory.percent > 80,
                    'critical': memory.percent > 95
                },
                'disk': {
                    'total': disk.total,
                    'free': disk.free,
                    'percent': disk.percent,
                    'warning': disk.percent > 80,
                    'critical': disk.percent > 95
                },
                'cpu': {
                    'percent': cpu_percent,
                    'warning': cpu_percent > 80,
                    'critical': cpu_percent > 95
                }
            }
        except Exception as e:
            logging.error(f"Error checking system resources: {e}")
            return {}
    
    @staticmethod
    def get_resource_warnings() -> List[str]:
        """Get resource usage warnings."""
        warnings = []
        resources = SystemResourceMonitor.check_system_resources()
        
        if resources.get('memory', {}).get('critical'):
            warnings.append("CRITICAL: Memory usage is above 95%. Operations may fail.")
        elif resources.get('memory', {}).get('warning'):
            warnings.append("WARNING: Memory usage is above 80%. Consider closing applications.")
            
        if resources.get('disk', {}).get('critical'):
            warnings.append("CRITICAL: Disk usage is above 95%. Free up space immediately.")
        elif resources.get('disk', {}).get('warning'):
            warnings.append("WARNING: Disk usage is above 80%. Consider freeing up space.")
            
        if resources.get('cpu', {}).get('critical'):
            warnings.append("CRITICAL: CPU usage is above 95%. System may be unresponsive.")
        elif resources.get('cpu', {}).get('warning'):
            warnings.append("WARNING: CPU usage is above 80%. Performance may be affected.")
            
        return warnings
    
    @staticmethod
    def check_resource_availability_for_operation(operation_type: str = "default") -> Tuple[bool, List[str]]:
        """Check if system has sufficient resources for the specified operation."""
        resources = SystemResourceMonitor.check_system_resources()
        issues = []
        can_proceed = True
        
        # Define resource thresholds for different operations
        thresholds = {
            "default": {"memory": 90, "disk": 90, "cpu": 90},
            "backup": {"memory": 85, "disk": 80, "cpu": 95},
            "remediation": {"memory": 85, "disk": 90, "cpu": 90},
            "assessment": {"memory": 95, "disk": 95, "cpu": 95}
        }
        
        threshold = thresholds.get(operation_type, thresholds["default"])
        
        if resources.get('memory', {}).get('percent', 0) > threshold['memory']:
            issues.append(f"Memory usage ({resources['memory']['percent']:.1f}%) exceeds safe threshold for {operation_type}")
            can_proceed = False
            
        if resources.get('disk', {}).get('percent', 0) > threshold['disk']:
            issues.append(f"Disk usage ({resources['disk']['percent']:.1f}%) exceeds safe threshold for {operation_type}")
            can_proceed = False
            
        if resources.get('cpu', {}).get('percent', 0) > threshold['cpu']:
            issues.append(f"CPU usage ({resources['cpu']['percent']:.1f}%) exceeds safe threshold for {operation_type}")
            can_proceed = False
            
        return can_proceed, issues


class NetworkConnectivityHandler:
    """Handles network connectivity issues and timeout management."""
    
    @staticmethod
    def test_connectivity(hosts: List[str] = None, timeout: int = 5) -> Dict[str, any]:
        """Test network connectivity to specified hosts."""
        if hosts is None:
            hosts = ["8.8.8.8", "1.1.1.1", "google.com"]
            
        results = {
            'overall_status': True,
            'host_results': {},
            'dns_working': False,
            'internet_available': False
        }
        
        for host in hosts:
            try:
                # Try to resolve hostname first if it's not an IP
                if not host.replace('.', '').isdigit():
                    socket.gethostbyname(host)
                    results['dns_working'] = True
                
                # Test connection
                sock = socket.create_connection((host, 53 if host.replace('.', '').isdigit() else 80), timeout=timeout)
                sock.close()
                
                results['host_results'][host] = {'status': 'success', 'error': None}
                results['internet_available'] = True
                
            except socket.gaierror as e:
                results['host_results'][host] = {'status': 'dns_error', 'error': str(e)}
                results['overall_status'] = False
            except socket.timeout:
                results['host_results'][host] = {'status': 'timeout', 'error': 'Connection timeout'}
                results['overall_status'] = False
            except Exception as e:
                results['host_results'][host] = {'status': 'error', 'error': str(e)}
                results['overall_status'] = False
                
        return results
    
    @staticmethod
    def get_network_diagnostics() -> Dict[str, any]:
        """Get comprehensive network diagnostics."""
        diagnostics = {
            'interfaces': [],
            'default_gateway': None,
            'dns_servers': [],
            'connectivity_test': None
        }
        
        try:
            # Get network interfaces
            for interface, addrs in psutil.net_if_addrs().items():
                interface_info = {'name': interface, 'addresses': []}
                for addr in addrs:
                    if addr.family == socket.AF_INET:  # IPv4
                        interface_info['addresses'].append({
                            'type': 'IPv4',
                            'address': addr.address,
                            'netmask': addr.netmask
                        })
                diagnostics['interfaces'].append(interface_info)
            
            # Test connectivity
            diagnostics['connectivity_test'] = NetworkConnectivityHandler.test_connectivity()
            
        except Exception as e:
            logging.error(f"Error getting network diagnostics: {e}")
            
        return diagnostics
    
    @staticmethod
    def suggest_network_fixes(connectivity_result: Dict[str, any]) -> List[str]:
        """Suggest fixes based on connectivity test results."""
        suggestions = []
        
        if not connectivity_result.get('overall_status', False):
            if not connectivity_result.get('dns_working', False):
                suggestions.extend([
                    "DNS resolution is failing:",
                    "  1. Check DNS server settings",
                    "  2. Try using public DNS (8.8.8.8, 1.1.1.1)",
                    "  3. Flush DNS cache:",
                    "     Windows: ipconfig /flushdns",
                    "     Linux: sudo systemctl restart systemd-resolved"
                ])
            
            if not connectivity_result.get('internet_available', False):
                suggestions.extend([
                    "Internet connectivity is not available:",
                    "  1. Check network cable/WiFi connection",
                    "  2. Verify network adapter is enabled",
                    "  3. Check firewall settings",
                    "  4. Contact network administrator"
                ])
            
            # Check for timeout issues
            timeout_hosts = [host for host, result in connectivity_result.get('host_results', {}).items() 
                           if result.get('status') == 'timeout']
            if timeout_hosts:
                suggestions.extend([
                    f"Connection timeouts detected for: {', '.join(timeout_hosts)}",
                    "  1. Check if a firewall is blocking connections",
                    "  2. Verify proxy settings",
                    "  3. Try increasing timeout values",
                    "  4. Check for network congestion"
                ])
        
        return suggestions
    
    @staticmethod
    def wait_for_connectivity(max_wait_time: int = 30, check_interval: int = 5) -> bool:
        """Wait for network connectivity to be restored."""
        start_time = time.time()
        
        while time.time() - start_time < max_wait_time:
            connectivity = NetworkConnectivityHandler.test_connectivity(timeout=3)
            if connectivity.get('overall_status', False):
                return True
            
            logging.info(f"Waiting for network connectivity... ({int(time.time() - start_time)}s)")
            time.sleep(check_interval)
            
        return False


class TimeoutManager:
    """Manages operation timeouts and provides timeout handling."""
    
    def __init__(self, default_timeout: int = 30):
        """Initialize timeout manager with default timeout."""
        self.default_timeout = default_timeout
        self.operation_timeouts = {
            'registry_operation': 10,
            'service_operation': 15,
            'file_operation': 20,
            'network_operation': 30,
            'backup_operation': 60,
            'assessment_operation': 120,
            'remediation_operation': 300
        }
    
    def get_timeout_for_operation(self, operation_type: str) -> int:
        """Get appropriate timeout for operation type."""
        return self.operation_timeouts.get(operation_type, self.default_timeout)
    
    def execute_with_timeout(self, func, args=None, kwargs=None, 
                           operation_type: str = "default") -> Tuple[bool, any, str]:
        """Execute function with timeout handling."""
        import threading
        import queue
        
        if args is None:
            args = []
        if kwargs is None:
            kwargs = {}
            
        timeout = self.get_timeout_for_operation(operation_type)
        result_queue = queue.Queue()
        exception_queue = queue.Queue()
        
        def target():
            try:
                result = func(*args, **kwargs)
                result_queue.put(result)
            except Exception as e:
                exception_queue.put(e)
        
        thread = threading.Thread(target=target)
        thread.daemon = True
        thread.start()
        thread.join(timeout)
        
        if thread.is_alive():
            # Timeout occurred
            return False, None, f"Operation timed out after {timeout} seconds"
        
        if not exception_queue.empty():
            # Exception occurred
            exception = exception_queue.get()
            return False, None, f"Operation failed: {str(exception)}"
        
        if not result_queue.empty():
            # Success
            result = result_queue.get()
            return True, result, "Operation completed successfully"
        
        # Unknown state
        return False, None, "Operation completed with unknown status"