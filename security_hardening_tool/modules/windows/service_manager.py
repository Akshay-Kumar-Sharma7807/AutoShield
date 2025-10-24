"""Windows Service Manager for system service hardening."""

import sys
import time
from typing import Any, Dict, List, Optional, Tuple

from ...core.models import (
    HardeningError, HardeningResult, Parameter, ParameterBackup, SystemError
)

# Windows-specific imports
if sys.platform == "win32":
    try:
        import win32service
        import win32serviceutil
        import pywintypes
    except ImportError:
        win32service = None
        win32serviceutil = None
        pywintypes = None
else:
    win32service = None
    win32serviceutil = None
    pywintypes = None


class WindowsServiceManager:
    """Manages Windows services for security hardening."""
    
    # Service startup types
    SERVICE_DISABLED = 4
    SERVICE_MANUAL = 3
    SERVICE_AUTOMATIC = 2
    SERVICE_AUTO_DELAYED = 2  # With delayed start flag
    
    # Service states
    SERVICE_STOPPED = 1
    SERVICE_START_PENDING = 2
    SERVICE_STOP_PENDING = 3
    SERVICE_RUNNING = 4
    SERVICE_CONTINUE_PENDING = 5
    SERVICE_PAUSE_PENDING = 6
    SERVICE_PAUSED = 7
    
    def __init__(self):
        """Initialize Windows Service Manager."""
        if not self._is_windows():
            raise SystemError("Windows Service Manager can only be used on Windows systems")
        
        if not all([win32service, win32serviceutil, pywintypes]):
            raise SystemError("Windows service modules not available. Install pywin32.")
        
        # Services to be hardened according to Annexure-A
        self.security_services = {
            # Services that should be disabled for security
            "BTAGService": {
                "name": "Bluetooth Audio Gateway Service",
                "target_state": "disabled",
                "description": "Bluetooth Audio Gateway Service should be disabled",
                "severity": "medium"
            },
            "bthserv": {
                "name": "Bluetooth Support Service",
                "target_state": "disabled",
                "description": "Bluetooth Support Service should be disabled",
                "severity": "medium"
            },
            "Browser": {
                "name": "Computer Browser",
                "target_state": "disabled",
                "description": "Computer Browser service should be disabled",
                "severity": "medium"
            },
            "lfsvc": {
                "name": "Geolocation Service",
                "target_state": "disabled",
                "description": "Geolocation Service should be disabled",
                "severity": "low"
            },
            "SharedAccess": {
                "name": "Internet Connection Sharing (ICS)",
                "target_state": "disabled",
                "description": "Internet Connection Sharing should be disabled",
                "severity": "high"
            },
            "SessionEnv": {
                "name": "Remote Desktop Configuration",
                "target_state": "disabled",
                "description": "Remote Desktop Configuration should be disabled",
                "severity": "high"
            },
            "TermService": {
                "name": "Remote Desktop Services",
                "target_state": "disabled",
                "description": "Remote Desktop Services should be disabled",
                "severity": "high"
            },
            "UmRdpService": {
                "name": "Remote Desktop Services UserMode Port Redirector",
                "target_state": "disabled",
                "description": "RDP UserMode Port Redirector should be disabled",
                "severity": "high"
            },
            "RpcLocator": {
                "name": "Remote Procedure Call (RPC) Locator",
                "target_state": "disabled",
                "description": "RPC Locator should be disabled",
                "severity": "medium"
            },
            "RemoteRegistry": {
                "name": "Remote Registry",
                "target_state": "disabled",
                "description": "Remote Registry service should be disabled",
                "severity": "high"
            },
            "RemoteAccess": {
                "name": "Routing and Remote Access",
                "target_state": "disabled",
                "description": "Routing and Remote Access should be disabled",
                "severity": "high"
            },
            "simptcp": {
                "name": "Simple TCP/IP Services",
                "target_state": "disabled",
                "description": "Simple TCP/IP Services should be disabled",
                "severity": "medium"
            },
            "SNMP": {
                "name": "SNMP Service",
                "target_state": "disabled",
                "description": "SNMP Service should be disabled",
                "severity": "medium"
            },
            "upnphost": {
                "name": "UPnP Device Host",
                "target_state": "disabled",
                "description": "UPnP Device Host should be disabled",
                "severity": "medium"
            },
            "WMSvc": {
                "name": "Web Management Service",
                "target_state": "disabled",
                "description": "Web Management Service should be disabled",
                "severity": "medium"
            },
            "WerSvc": {
                "name": "Windows Error Reporting Service",
                "target_state": "disabled",
                "description": "Windows Error Reporting should be disabled",
                "severity": "low"
            },
            "Wecsvc": {
                "name": "Windows Event Collector",
                "target_state": "disabled",
                "description": "Windows Event Collector should be disabled",
                "severity": "low"
            },
            "WMPNetworkSvc": {
                "name": "Windows Media Player Network Sharing Service",
                "target_state": "disabled",
                "description": "WMP Network Sharing should be disabled",
                "severity": "low"
            },
            "icssvc": {
                "name": "Windows Mobile Hotspot Service",
                "target_state": "disabled",
                "description": "Mobile Hotspot Service should be disabled",
                "severity": "medium"
            },
            "PushToInstall": {
                "name": "Windows PushToInstall Service",
                "target_state": "disabled",
                "description": "PushToInstall Service should be disabled",
                "severity": "low"
            },
            "WinRM": {
                "name": "Windows Remote Management (WS-Management)",
                "target_state": "disabled",
                "description": "Windows Remote Management should be disabled",
                "severity": "high"
            },
            "W3SVC": {
                "name": "World Wide Web Publishing Service",
                "target_state": "disabled",
                "description": "WWW Publishing Service should be disabled",
                "severity": "high"
            },
            "XboxGipSvc": {
                "name": "Xbox Accessory Management Service",
                "target_state": "disabled",
                "description": "Xbox Accessory Management should be disabled",
                "severity": "low"
            },
            "XblAuthManager": {
                "name": "Xbox Live Auth Manager",
                "target_state": "disabled",
                "description": "Xbox Live Auth Manager should be disabled",
                "severity": "low"
            },
            "XblGameSave": {
                "name": "Xbox Live Game Save",
                "target_state": "disabled",
                "description": "Xbox Live Game Save should be disabled",
                "severity": "low"
            },
            "XboxNetApiSvc": {
                "name": "Xbox Live Networking Service",
                "target_state": "disabled",
                "description": "Xbox Live Networking should be disabled",
                "severity": "low"
            }
        }
    
    def get_service_status(self, service_name: str) -> Optional[Dict[str, Any]]:
        """Get current status of a Windows service."""
        try:
            # Open service control manager
            scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
            
            try:
                # Open the service
                service_handle = win32service.OpenService(
                    scm, service_name, win32service.SERVICE_QUERY_STATUS | win32service.SERVICE_QUERY_CONFIG
                )
                
                try:
                    # Get service status
                    status = win32service.QueryServiceStatus(service_handle)
                    config = win32service.QueryServiceConfig(service_handle)
                    
                    return {
                        "name": service_name,
                        "display_name": config[1],
                        "state": status[1],
                        "startup_type": config[2],
                        "service_type": config[0],
                        "error_control": config[3],
                        "binary_path": config[4],
                        "load_order_group": config[5],
                        "dependencies": config[7],
                        "service_start_name": config[8]
                    }
                    
                finally:
                    win32service.CloseServiceHandle(service_handle)
                    
            finally:
                win32service.CloseServiceHandle(scm)
                
        except pywintypes.error as e:
            if e.winerror == 1060:  # Service does not exist
                return None
            raise SystemError(f"Failed to query service {service_name}: {str(e)}")
    
    def set_service_startup_type(self, service_name: str, startup_type: int) -> bool:
        """Set service startup type."""
        try:
            # Open service control manager
            scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
            
            try:
                # Open the service
                service_handle = win32service.OpenService(
                    scm, service_name, win32service.SERVICE_CHANGE_CONFIG
                )
                
                try:
                    # Change service configuration
                    win32service.ChangeServiceConfig(
                        service_handle,
                        win32service.SERVICE_NO_CHANGE,  # service type
                        startup_type,  # startup type
                        win32service.SERVICE_NO_CHANGE,  # error control
                        None,  # binary path
                        None,  # load order group
                        0,     # tag id
                        None,  # dependencies
                        None,  # service start name
                        None,  # password
                        None   # display name
                    )
                    
                    return True
                    
                finally:
                    win32service.CloseServiceHandle(service_handle)
                    
            finally:
                win32service.CloseServiceHandle(scm)
                
        except pywintypes.error as e:
            raise SystemError(f"Failed to set startup type for {service_name}: {str(e)}")
    
    def stop_service(self, service_name: str, timeout: int = 30) -> bool:
        """Stop a Windows service."""
        try:
            # Check if service is already stopped
            status = self.get_service_status(service_name)
            if not status or status["state"] == self.SERVICE_STOPPED:
                return True
            
            # Stop the service
            win32serviceutil.StopService(service_name)
            
            # Wait for service to stop
            start_time = time.time()
            while time.time() - start_time < timeout:
                status = self.get_service_status(service_name)
                if status and status["state"] == self.SERVICE_STOPPED:
                    return True
                time.sleep(1)
            
            return False
            
        except pywintypes.error as e:
            if e.winerror == 1062:  # Service has not been started
                return True
            raise SystemError(f"Failed to stop service {service_name}: {str(e)}")
    
    def start_service(self, service_name: str, timeout: int = 30) -> bool:
        """Start a Windows service."""
        try:
            # Check if service is already running
            status = self.get_service_status(service_name)
            if status and status["state"] == self.SERVICE_RUNNING:
                return True
            
            # Start the service
            win32serviceutil.StartService(service_name)
            
            # Wait for service to start
            start_time = time.time()
            while time.time() - start_time < timeout:
                status = self.get_service_status(service_name)
                if status and status["state"] == self.SERVICE_RUNNING:
                    return True
                time.sleep(1)
            
            return False
            
        except pywintypes.error as e:
            raise SystemError(f"Failed to start service {service_name}: {str(e)}")
    
    def disable_service(self, service_name: str) -> bool:
        """Disable a Windows service (set to disabled and stop it)."""
        try:
            # First stop the service if it's running
            self.stop_service(service_name)
            
            # Set startup type to disabled
            return self.set_service_startup_type(service_name, self.SERVICE_DISABLED)
            
        except Exception as e:
            raise SystemError(f"Failed to disable service {service_name}: {str(e)}")
    
    def enable_service(self, service_name: str, startup_type: int = None) -> bool:
        """Enable a Windows service."""
        if startup_type is None:
            startup_type = self.SERVICE_AUTOMATIC
        
        try:
            # Set startup type
            return self.set_service_startup_type(service_name, startup_type)
            
        except Exception as e:
            raise SystemError(f"Failed to enable service {service_name}: {str(e)}")
    
    def backup_service_configuration(self, service_name: str) -> Optional[ParameterBackup]:
        """Create backup of service configuration."""
        status = self.get_service_status(service_name)
        
        if not status:
            # Service doesn't exist
            return ParameterBackup(
                parameter_id=service_name,
                original_value=None,
                restore_method="service",
                restore_data={"exists": False}
            )
        
        return ParameterBackup(
            parameter_id=service_name,
            original_value={
                "startup_type": status["startup_type"],
                "state": status["state"]
            },
            restore_method="service",
            restore_data={
                "exists": True,
                "startup_type": status["startup_type"],
                "state": status["state"]
            }
        )
    
    def restore_service_configuration(self, backup: ParameterBackup) -> bool:
        """Restore service configuration from backup."""
        if backup.restore_method != "service":
            return False
        
        if not backup.restore_data.get("exists", True):
            # Service didn't exist originally, nothing to restore
            return True
        
        try:
            service_name = backup.parameter_id
            original_startup_type = backup.restore_data["startup_type"]
            original_state = backup.restore_data["state"]
            
            # Restore startup type
            self.set_service_startup_type(service_name, original_startup_type)
            
            # Restore service state
            current_status = self.get_service_status(service_name)
            if current_status:
                current_state = current_status["state"]
                
                if original_state == self.SERVICE_RUNNING and current_state != self.SERVICE_RUNNING:
                    self.start_service(service_name)
                elif original_state == self.SERVICE_STOPPED and current_state != self.SERVICE_STOPPED:
                    self.stop_service(service_name)
            
            return True
            
        except Exception:
            return False
    
    def apply_service_hardening(self, parameters: List[Parameter]) -> List[HardeningResult]:
        """Apply service hardening configurations."""
        results = []
        
        # Filter service-related parameters
        service_params = [p for p in parameters if p.category == "services"]
        
        for param in service_params:
            result = HardeningResult(
                parameter_id=param.id,
                previous_value=None,
                applied_value=param.target_value,
                success=False
            )
            
            try:
                # Check if this is a known security service
                if param.id in self.security_services:
                    service_name = param.id
                    service_info = self.security_services[service_name]
                    
                    # Get current status
                    current_status = self.get_service_status(service_name)
                    if current_status:
                        result.previous_value = {
                            "startup_type": current_status["startup_type"],
                            "state": current_status["state"]
                        }
                    
                    # Apply hardening based on target state
                    if service_info["target_state"] == "disabled":
                        if self.disable_service(service_name):
                            result.success = True
                            result.backup_created = True
                            result.requires_reboot = True
                        else:
                            result.error_message = f"Failed to disable service {service_name}"
                    
                else:
                    # Handle generic service parameters
                    result.error_message = f"Unknown service parameter: {param.id}"
                    
            except Exception as e:
                result.error_message = str(e)
            
            results.append(result)
        
        return results
    
    def get_security_services_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all security-related services."""
        services_status = {}
        
        for service_name, service_info in self.security_services.items():
            status = self.get_service_status(service_name)
            services_status[service_name] = {
                "info": service_info,
                "current_status": status,
                "compliant": self._is_service_compliant(service_name, status, service_info)
            }
        
        return services_status
    
    def _is_service_compliant(self, service_name: str, status: Optional[Dict[str, Any]], 
                            service_info: Dict[str, Any]) -> bool:
        """Check if service is compliant with security requirements."""
        if not status:
            # Service doesn't exist, which is compliant for services that should be disabled
            return service_info["target_state"] == "disabled"
        
        if service_info["target_state"] == "disabled":
            return status["startup_type"] == self.SERVICE_DISABLED
        
        return True
    
    def _is_windows(self) -> bool:
        """Check if running on Windows."""
        return sys.platform == "win32"
    
    def get_supported_services(self) -> List[str]:
        """Get list of supported service names."""
        return list(self.security_services.keys())
    
    def is_service_supported(self, service_name: str) -> bool:
        """Check if service is supported by this manager."""
        return service_name in self.security_services
    
    def validate_service_access(self) -> bool:
        """Validate that we have necessary service management permissions."""
        try:
            # Try to open service control manager
            scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
            win32service.CloseServiceHandle(scm)
            return True
            
        except pywintypes.error:
            return False