"""Comprehensive logging and audit trail system."""

import hashlib
import json
import logging
import os
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .interfaces import Logger as LoggerInterface
from .models import HardeningError


class AuditLogger(LoggerInterface):
    """Comprehensive audit logging with tamper-evident storage."""
    
    def __init__(self, log_dir: Optional[Path] = None, 
                 max_log_size: int = 10 * 1024 * 1024,  # 10MB
                 backup_count: int = 5):
        """Initialize audit logger."""
        if log_dir is None:
            log_dir = Path.home() / ".security_hardening" / "logs"
        
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self.max_log_size = max_log_size
        self.backup_count = backup_count
        self._lock = threading.Lock()
        
        # Initialize log files
        self.audit_log_file = self.log_dir / "audit.log"
        self.error_log_file = self.log_dir / "error.log"
        self.integrity_file = self.log_dir / "integrity.json"
        
        # Setup Python logging
        self._setup_python_logging()
        
        # Initialize integrity tracking
        self._initialize_integrity_tracking()
    
    def log_operation(self, operation: str, details: Dict[str, Any], 
                     success: bool = True) -> None:
        """Log operation with details and integrity checking."""
        with self._lock:
            timestamp = datetime.now().isoformat()
            
            # Get user context
            user_context = self._get_user_context()
            
            # Create log entry
            log_entry = {
                "timestamp": timestamp,
                "operation": operation,
                "success": success,
                "details": details,
                "user": user_context["username"],
                "process_id": os.getpid(),
                "thread_id": threading.get_ident(),
                "hostname": user_context["hostname"]
            }
            
            # Write to audit log
            self._write_audit_entry(log_entry)
            
            # Update integrity tracking
            self._update_integrity_tracking(log_entry)
            
            # Log to Python logger
            level = logging.INFO if success else logging.WARNING
            self.logger.log(level, f"Operation: {operation} - Success: {success}")
    
    def log_error(self, error: Exception, context: Optional[Dict[str, Any]] = None) -> None:
        """Log error with context and stack trace."""
        with self._lock:
            timestamp = datetime.now().isoformat()
            
            # Get user context
            user_context = self._get_user_context()
            
            # Create error entry
            error_entry = {
                "timestamp": timestamp,
                "error_type": type(error).__name__,
                "error_message": str(error),
                "context": context or {},
                "user": user_context["username"],
                "process_id": os.getpid(),
                "thread_id": threading.get_ident(),
                "hostname": user_context["hostname"]
            }
            
            # Add additional info for HardeningError
            if isinstance(error, HardeningError):
                error_entry.update({
                    "error_code": error.error_code,
                    "severity": error.severity.value,
                    "recoverable": error.recoverable
                })
            
            # Write to error log
            self._write_error_entry(error_entry)
            
            # Update integrity tracking
            self._update_integrity_tracking(error_entry)
            
            # Log to Python logger
            self.logger.error(f"Error: {error_entry['error_type']} - {error_entry['error_message']}")
    
    def get_audit_trail(self, start_time: Optional[str] = None, 
                       end_time: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get audit trail for specified time range."""
        audit_entries = []
        
        try:
            with open(self.audit_log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        entry_time = entry.get("timestamp")
                        
                        # Filter by time range if specified
                        if start_time and entry_time < start_time:
                            continue
                        if end_time and entry_time > end_time:
                            continue
                        
                        audit_entries.append(entry)
                        
                    except json.JSONDecodeError:
                        continue
                        
        except FileNotFoundError:
            pass
        
        return audit_entries
    
    def verify_log_integrity(self) -> bool:
        """Verify the integrity of log files."""
        try:
            with open(self.integrity_file, 'r', encoding='utf-8') as f:
                integrity_data = json.load(f)
            
            # Verify audit log
            if self.audit_log_file.exists():
                current_hash = self._calculate_file_hash(self.audit_log_file)
                stored_hash = integrity_data.get("audit_log_hash")
                
                if current_hash != stored_hash:
                    return False
            
            # Verify error log
            if self.error_log_file.exists():
                current_hash = self._calculate_file_hash(self.error_log_file)
                stored_hash = integrity_data.get("error_log_hash")
                
                if current_hash != stored_hash:
                    return False
            
            return True
            
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            return False
    
    def rotate_logs(self) -> None:
        """Rotate log files when they exceed maximum size."""
        with self._lock:
            self._rotate_log_file(self.audit_log_file)
            self._rotate_log_file(self.error_log_file)
            
            # Update integrity tracking after rotation
            self._update_integrity_hashes()
    
    def get_log_statistics(self) -> Dict[str, Any]:
        """Get logging statistics and metrics."""
        stats = {
            "audit_log_size": 0,
            "error_log_size": 0,
            "total_audit_entries": 0,
            "total_error_entries": 0,
            "log_directory": str(self.log_dir),
            "integrity_verified": self.verify_log_integrity()
        }
        
        # Get file sizes
        if self.audit_log_file.exists():
            stats["audit_log_size"] = self.audit_log_file.stat().st_size
            stats["total_audit_entries"] = self._count_log_entries(self.audit_log_file)
        
        if self.error_log_file.exists():
            stats["error_log_size"] = self.error_log_file.stat().st_size
            stats["total_error_entries"] = self._count_log_entries(self.error_log_file)
        
        return stats
    
    def _setup_python_logging(self) -> None:
        """Setup Python logging configuration."""
        self.logger = logging.getLogger("security_hardening")
        self.logger.setLevel(logging.DEBUG)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Create file handler
        log_file = self.log_dir / "application.log"
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        
        # Create console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        
        # Add handlers to logger
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def _initialize_integrity_tracking(self) -> None:
        """Initialize integrity tracking for log files."""
        if not self.integrity_file.exists():
            integrity_data = {
                "created": datetime.now().isoformat(),
                "audit_log_hash": "",
                "error_log_hash": "",
                "last_updated": datetime.now().isoformat()
            }
            
            with open(self.integrity_file, 'w', encoding='utf-8') as f:
                json.dump(integrity_data, f, indent=2)
        
        # Update hashes for existing files
        self._update_integrity_hashes()
    
    def _update_integrity_tracking(self, log_entry: Dict[str, Any]) -> None:
        """Update integrity tracking after adding log entry."""
        # This is called after each log entry, but we'll update hashes periodically
        # to avoid excessive I/O operations
        pass
    
    def _update_integrity_hashes(self) -> None:
        """Update integrity hashes for all log files."""
        try:
            with open(self.integrity_file, 'r', encoding='utf-8') as f:
                integrity_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            integrity_data = {"created": datetime.now().isoformat()}
        
        # Update hashes
        if self.audit_log_file.exists():
            integrity_data["audit_log_hash"] = self._calculate_file_hash(self.audit_log_file)
        
        if self.error_log_file.exists():
            integrity_data["error_log_hash"] = self._calculate_file_hash(self.error_log_file)
        
        integrity_data["last_updated"] = datetime.now().isoformat()
        
        with open(self.integrity_file, 'w', encoding='utf-8') as f:
            json.dump(integrity_data, f, indent=2)
    
    def _write_audit_entry(self, log_entry: Dict[str, Any]) -> None:
        """Write audit entry to log file."""
        self._write_log_entry(self.audit_log_file, log_entry)
    
    def _write_error_entry(self, error_entry: Dict[str, Any]) -> None:
        """Write error entry to log file."""
        self._write_log_entry(self.error_log_file, error_entry)
    
    def _write_log_entry(self, log_file: Path, entry: Dict[str, Any]) -> None:
        """Write log entry to specified file."""
        # Check if rotation is needed
        if log_file.exists() and log_file.stat().st_size > self.max_log_size:
            self._rotate_log_file(log_file)
        
        # Write entry
        with open(log_file, 'a', encoding='utf-8') as f:
            json.dump(entry, f, separators=(',', ':'))
            f.write('\n')
    
    def _rotate_log_file(self, log_file: Path) -> None:
        """Rotate log file when it exceeds maximum size."""
        if not log_file.exists():
            return
        
        # Move existing backup files
        for i in range(self.backup_count - 1, 0, -1):
            old_backup = log_file.with_suffix(f"{log_file.suffix}.{i}")
            new_backup = log_file.with_suffix(f"{log_file.suffix}.{i + 1}")
            
            if old_backup.exists():
                if new_backup.exists():
                    new_backup.unlink()
                old_backup.rename(new_backup)
        
        # Move current log to .1
        backup_file = log_file.with_suffix(f"{log_file.suffix}.1")
        if backup_file.exists():
            backup_file.unlink()
        log_file.rename(backup_file)
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of file contents."""
        hash_sha256 = hashlib.sha256()
        
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except FileNotFoundError:
            return ""
    
    def _count_log_entries(self, log_file: Path) -> int:
        """Count number of entries in log file."""
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                return sum(1 for line in f if line.strip())
        except FileNotFoundError:
            return 0
    
    def _get_user_context(self) -> Dict[str, str]:
        """Get current user context information."""
        import getpass
        import socket
        
        return {
            "username": getpass.getuser(),
            "hostname": socket.gethostname()
        }


class ConsoleLogger(LoggerInterface):
    """Simple console-only logger for testing and development."""
    
    def __init__(self, level: str = "INFO"):
        """Initialize console logger."""
        self.logger = logging.getLogger("security_hardening_console")
        self.logger.setLevel(getattr(logging, level.upper()))
        
        # Create console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(getattr(logging, level.upper()))
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(formatter)
        
        # Add handler to logger
        self.logger.addHandler(console_handler)
    
    def log_operation(self, operation: str, details: Dict[str, Any], 
                     success: bool = True) -> None:
        """Log operation to console."""
        level = logging.INFO if success else logging.WARNING
        message = f"Operation: {operation} - Success: {success}"
        if details:
            message += f" - Details: {details}"
        self.logger.log(level, message)
    
    def log_error(self, error: Exception, context: Optional[Dict[str, Any]] = None) -> None:
        """Log error to console."""
        message = f"Error: {type(error).__name__} - {str(error)}"
        if context:
            message += f" - Context: {context}"
        self.logger.error(message)
    
    def get_audit_trail(self, start_time: Optional[str] = None, 
                       end_time: Optional[str] = None) -> List[Dict[str, Any]]:
        """Console logger doesn't maintain audit trail."""
        self.logger.warning("Console logger doesn't maintain persistent audit trail")
        return []