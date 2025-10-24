"""Operating system detection and system information gathering."""

import platform
import socket
import subprocess
import sys
from typing import Optional

from .interfaces import OSDetector as OSDetectorInterface
from .models import Architecture, OSInfo, Platform, SystemInfo


class OSDetector(OSDetectorInterface):
    """Concrete implementation of OS detection."""
    
    def __init__(self):
        """Initialize OS detector."""
        self._cached_system_info: Optional[SystemInfo] = None
    
    def detect_platform(self) -> str:
        """Detect the operating system platform."""
        system = platform.system().lower()
        
        if system == "windows":
            return Platform.WINDOWS.value
        elif system == "linux":
            return Platform.LINUX.value
        else:
            raise ValueError(f"Unsupported platform: {system}")
    
    def detect_version(self) -> str:
        """Detect the OS version."""
        system = platform.system().lower()
        
        if system == "windows":
            return self._detect_windows_version()
        elif system == "linux":
            return self._detect_linux_version()
        else:
            return platform.release()
    
    def detect_architecture(self) -> str:
        """Detect system architecture."""
        machine = platform.machine().lower()
        
        if machine in ["x86_64", "amd64"]:
            return Architecture.X64.value
        elif machine in ["i386", "i686", "x86"]:
            return Architecture.X86.value
        elif machine in ["arm64", "aarch64"]:
            return Architecture.ARM64.value
        else:
            # Default to x64 for unknown architectures
            return Architecture.X64.value
    
    def get_system_info(self) -> SystemInfo:
        """Get comprehensive system information."""
        if self._cached_system_info:
            return self._cached_system_info
        
        # Detect OS information
        platform_str = self.detect_platform()
        version = self.detect_version()
        architecture_str = self.detect_architecture()
        
        # Create OS info
        os_info = OSInfo(
            platform=Platform(platform_str),
            version=version,
            build=self._get_build_info(),
            architecture=Architecture(architecture_str),
            edition=self._get_edition_info(),
            service_pack=self._get_service_pack_info()
        )
        
        # Get system information
        hostname = socket.gethostname()
        domain = self._get_domain_info()
        total_memory = self._get_total_memory()
        cpu_count = self._get_cpu_count()
        uptime = self._get_uptime()
        
        system_info = SystemInfo(
            os_info=os_info,
            hostname=hostname,
            domain=domain,
            total_memory=total_memory,
            cpu_count=cpu_count,
            uptime=uptime
        )
        
        self._cached_system_info = system_info
        return system_info
    
    def _detect_windows_version(self) -> str:
        """Detect Windows version with detailed information."""
        try:
            import winreg
            
            # Get version from registry
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                               r"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")
            
            try:
                # Try to get Windows 10/11 version
                current_build = winreg.QueryValueEx(key, "CurrentBuild")[0]
                current_build_number = int(current_build)
                
                # Determine Windows version based on build number
                if current_build_number >= 22000:
                    return "11"
                elif current_build_number >= 10240:
                    return "10"
                else:
                    # Fallback to product name
                    product_name = winreg.QueryValueEx(key, "ProductName")[0]
                    if "Windows 8.1" in product_name:
                        return "8.1"
                    elif "Windows 8" in product_name:
                        return "8"
                    elif "Windows 7" in product_name:
                        return "7"
                    else:
                        return "Unknown"
                        
            finally:
                winreg.CloseKey(key)
                
        except (ImportError, OSError, ValueError):
            # Fallback to platform module
            return platform.release()
    
    def _detect_linux_version(self) -> str:
        """Detect Linux distribution and version."""
        try:
            # Try to read /etc/os-release first (modern standard)
            with open("/etc/os-release", "r") as f:
                os_release = {}
                for line in f:
                    if "=" in line:
                        key, value = line.strip().split("=", 1)
                        os_release[key] = value.strip('"')
                
                # Get distribution name and version
                name = os_release.get("NAME", "").lower()
                version = os_release.get("VERSION_ID", "")
                
                if "ubuntu" in name:
                    return f"Ubuntu {version}"
                elif "centos" in name:
                    return f"CentOS {version}"
                elif "red hat" in name or "rhel" in name:
                    return f"RHEL {version}"
                elif "debian" in name:
                    return f"Debian {version}"
                else:
                    return f"{os_release.get('PRETTY_NAME', 'Unknown Linux')}"
                    
        except FileNotFoundError:
            pass
        
        try:
            # Fallback to /etc/redhat-release
            with open("/etc/redhat-release", "r") as f:
                return f.read().strip()
        except FileNotFoundError:
            pass
        
        try:
            # Fallback to lsb_release command
            result = subprocess.run(["lsb_release", "-d"], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return result.stdout.split(":", 1)[1].strip()
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            pass
        
        # Final fallback
        return f"Linux {platform.release()}"
    
    def _get_build_info(self) -> Optional[str]:
        """Get OS build information."""
        system = platform.system().lower()
        
        if system == "windows":
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                   r"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")
                try:
                    build = winreg.QueryValueEx(key, "CurrentBuild")[0]
                    ubr = winreg.QueryValueEx(key, "UBR")[0]
                    return f"{build}.{ubr}"
                except OSError:
                    return winreg.QueryValueEx(key, "CurrentBuild")[0]
                finally:
                    winreg.CloseKey(key)
            except (ImportError, OSError):
                return None
        
        elif system == "linux":
            try:
                with open("/proc/version", "r") as f:
                    version_info = f.read().strip()
                    # Extract kernel version
                    parts = version_info.split()
                    if len(parts) >= 3:
                        return parts[2]
            except FileNotFoundError:
                pass
        
        return None
    
    def _get_edition_info(self) -> Optional[str]:
        """Get OS edition information."""
        system = platform.system().lower()
        
        if system == "windows":
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                   r"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")
                try:
                    return winreg.QueryValueEx(key, "EditionID")[0]
                finally:
                    winreg.CloseKey(key)
            except (ImportError, OSError):
                return None
        
        return None
    
    def _get_service_pack_info(self) -> Optional[str]:
        """Get service pack information (Windows only)."""
        if platform.system().lower() == "windows":
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                   r"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")
                try:
                    csd_version = winreg.QueryValueEx(key, "CSDVersion")[0]
                    return csd_version if csd_version else None
                except OSError:
                    return None
                finally:
                    winreg.CloseKey(key)
            except ImportError:
                return None
        
        return None
    
    def _get_domain_info(self) -> Optional[str]:
        """Get domain information."""
        system = platform.system().lower()
        
        if system == "windows":
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                   r"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters")
                try:
                    domain = winreg.QueryValueEx(key, "Domain")[0]
                    return domain if domain else None
                except OSError:
                    return None
                finally:
                    winreg.CloseKey(key)
            except ImportError:
                return None
        
        elif system == "linux":
            try:
                with open("/etc/resolv.conf", "r") as f:
                    for line in f:
                        if line.startswith("domain "):
                            return line.split()[1]
                        elif line.startswith("search "):
                            return line.split()[1]
            except FileNotFoundError:
                pass
        
        return None
    
    def _get_total_memory(self) -> Optional[int]:
        """Get total system memory in bytes."""
        try:
            import psutil
            return psutil.virtual_memory().total
        except ImportError:
            pass
        
        system = platform.system().lower()
        
        if system == "linux":
            try:
                with open("/proc/meminfo", "r") as f:
                    for line in f:
                        if line.startswith("MemTotal:"):
                            # Convert from KB to bytes
                            kb = int(line.split()[1])
                            return kb * 1024
            except (FileNotFoundError, ValueError):
                pass
        
        return None
    
    def _get_cpu_count(self) -> Optional[int]:
        """Get number of CPU cores."""
        try:
            import psutil
            return psutil.cpu_count(logical=True)
        except ImportError:
            pass
        
        try:
            import os
            return os.cpu_count()
        except AttributeError:
            pass
        
        return None
    
    def _get_uptime(self) -> Optional[int]:
        """Get system uptime in seconds."""
        try:
            import psutil
            import time
            return int(time.time() - psutil.boot_time())
        except ImportError:
            pass
        
        system = platform.system().lower()
        
        if system == "linux":
            try:
                with open("/proc/uptime", "r") as f:
                    uptime_seconds = float(f.read().split()[0])
                    return int(uptime_seconds)
            except (FileNotFoundError, ValueError):
                pass
        
        return None
    
    def is_supported_platform(self) -> bool:
        """Check if current platform is supported."""
        try:
            platform_str = self.detect_platform()
            version = self.detect_version()
            
            if platform_str == Platform.WINDOWS.value:
                # Support Windows 10 and 11
                return version in ["10", "11"]
            
            elif platform_str == Platform.LINUX.value:
                # Support Ubuntu 20.04+, CentOS 7+
                if "Ubuntu" in version:
                    version_num = version.split()[1]
                    major, minor = map(int, version_num.split(".")[:2])
                    return major > 20 or (major == 20 and minor >= 4)
                
                elif "CentOS" in version:
                    version_num = version.split()[1]
                    major = int(version_num.split(".")[0])
                    return major >= 7
                
                # Accept other Linux distributions with warning
                return True
            
            return False
            
        except Exception:
            return False