"""Abstract interfaces for the security hardening tool."""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional

from .models import (
    AssessmentResult, BackupData, HardeningResult, OSInfo, Parameter,
    RestoreResult, SystemInfo, ValidationResult, HardeningLevel, OperationResult,
    RollbackResult
)


class OSDetector(ABC):
    """Abstract interface for OS detection."""
    
    @abstractmethod
    def detect_platform(self) -> str:
        """Detect the operating system platform."""
        pass
    
    @abstractmethod
    def detect_version(self) -> str:
        """Detect the OS version."""
        pass
    
    @abstractmethod
    def detect_architecture(self) -> str:
        """Detect system architecture."""
        pass
    
    @abstractmethod
    def get_system_info(self) -> SystemInfo:
        """Get comprehensive system information."""
        pass


class HardeningModule(ABC):
    """Abstract base class for platform-specific hardening modules."""
    
    @abstractmethod
    def get_supported_parameters(self) -> List[Parameter]:
        """Get list of parameters supported by this module."""
        pass
    
    @abstractmethod
    def assess_current_state(self, parameters: List[Parameter]) -> List[AssessmentResult]:
        """Assess current state of specified parameters."""
        pass
    
    @abstractmethod
    def apply_hardening(self, parameters: List[Parameter]) -> List[HardeningResult]:
        """Apply hardening configurations for specified parameters."""
        pass
    
    @abstractmethod
    def validate_configuration(self, parameters: List[Parameter]) -> List[ValidationResult]:
        """Validate parameter configurations before applying."""
        pass
    
    @abstractmethod
    def create_backup(self, parameters: List[Parameter]) -> BackupData:
        """Create backup of current parameter values."""
        pass
    
    @abstractmethod
    def restore_backup(self, backup: BackupData) -> List[RestoreResult]:
        """Restore parameters from backup data."""
        pass
    
    @abstractmethod
    def get_platform_info(self) -> OSInfo:
        """Get platform-specific information."""
        pass


class ConfigurationManager(ABC):
    """Abstract interface for configuration management."""
    
    @abstractmethod
    def load_hardening_level(self, level: HardeningLevel) -> List[Parameter]:
        """Load parameters for specified hardening level."""
        pass
    
    @abstractmethod
    def validate_parameters(self, parameters: List[Parameter]) -> List[ValidationResult]:
        """Validate parameter configurations."""
        pass
    
    @abstractmethod
    def merge_custom_parameters(self, base_params: List[Parameter], 
                              custom_params: Dict[str, any]) -> List[Parameter]:
        """Merge custom parameter overrides with base configuration."""
        pass


class BackupManager(ABC):
    """Abstract interface for backup management."""
    
    @abstractmethod
    def create_backup(self, backup_data: BackupData) -> str:
        """Create and store backup data. Returns backup ID."""
        pass
    
    @abstractmethod
    def list_backups(self) -> List[BackupData]:
        """List all available backups."""
        pass
    
    @abstractmethod
    def get_backup(self, backup_id: str) -> Optional[BackupData]:
        """Retrieve specific backup by ID."""
        pass
    
    @abstractmethod
    def delete_backup(self, backup_id: str) -> bool:
        """Delete backup by ID."""
        pass
    
    @abstractmethod
    def verify_backup_integrity(self, backup_id: str) -> bool:
        """Verify backup data integrity."""
        pass
    
    def execute_rollback(self, backup_id: str, hardening_module, 
                        parameter_ids: Optional[List[str]] = None) -> RollbackResult:
        """Execute rollback with selective parameter restoration and validation."""
        pass
    
    def get_rollback_preview(self, backup_id: str, 
                           parameter_ids: Optional[List[str]] = None) -> Dict[str, any]:
        """Get preview of what would be restored in a rollback operation."""
        pass
    
    def validate_rollback_compatibility(self, backup_id: str, current_os_info: OSInfo) -> Dict[str, any]:
        """Validate if a backup is compatible with the current system for rollback."""
        pass


class ReportEngine(ABC):
    """Abstract interface for report generation."""
    
    @abstractmethod
    def generate_assessment_report(self, results: List[AssessmentResult], 
                                 output_path: str) -> OperationResult:
        """Generate assessment report."""
        pass
    
    @abstractmethod
    def generate_hardening_report(self, results: List[HardeningResult], 
                                output_path: str) -> OperationResult:
        """Generate hardening operation report."""
        pass
    
    @abstractmethod
    def generate_compliance_report(self, results: List[AssessmentResult], 
                                 framework: str, output_path: str) -> OperationResult:
        """Generate compliance framework report."""
        pass


class Logger(ABC):
    """Abstract interface for logging system."""
    
    @abstractmethod
    def log_operation(self, operation: str, details: Dict[str, any], 
                     success: bool = True) -> None:
        """Log operation with details."""
        pass
    
    @abstractmethod
    def log_error(self, error: Exception, context: Optional[Dict[str, any]] = None) -> None:
        """Log error with context."""
        pass
    
    @abstractmethod
    def get_audit_trail(self, start_time: Optional[str] = None, 
                       end_time: Optional[str] = None) -> List[Dict[str, any]]:
        """Get audit trail for specified time range."""
        pass


class ErrorHandler(ABC):
    """Abstract interface for error handling."""
    
    @abstractmethod
    def handle_error(self, error: Exception) -> OperationResult:
        """Handle and categorize errors."""
        pass
    
    @abstractmethod
    def suggest_remediation(self, error: Exception) -> List[str]:
        """Suggest remediation steps for errors."""
        pass
    
    @abstractmethod
    def attempt_recovery(self, error: Exception) -> bool:
        """Attempt automatic error recovery."""
        pass