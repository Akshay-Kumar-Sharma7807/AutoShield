"""Core data models for the security hardening tool."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union


class Platform(Enum):
    """Supported operating system platforms."""
    WINDOWS = "windows"
    LINUX = "linux"


class Architecture(Enum):
    """Supported system architectures."""
    X64 = "x64"
    X86 = "x86"
    ARM64 = "arm64"


class Severity(Enum):
    """Security finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class HardeningLevel(Enum):
    """Available hardening levels."""
    BASIC = "basic"
    MODERATE = "moderate"
    STRICT = "strict"


class OperationMode(Enum):
    """Tool operation modes."""
    ASSESS = "assess"
    REMEDIATE = "remediate"
    ROLLBACK = "rollback"


@dataclass
class OSInfo:
    """Operating system information."""
    platform: Platform
    version: str
    build: Optional[str] = None
    architecture: Architecture = Architecture.X64
    edition: Optional[str] = None
    service_pack: Optional[str] = None


@dataclass
class SystemInfo:
    """Complete system information."""
    os_info: OSInfo
    hostname: str
    domain: Optional[str] = None
    total_memory: Optional[int] = None
    cpu_count: Optional[int] = None
    uptime: Optional[int] = None


@dataclass
class ValidationRule:
    """Parameter validation rule."""
    rule_type: str  # "range", "enum", "regex", "custom"
    rule_value: Any
    error_message: str


@dataclass
class Parameter:
    """Security parameter definition."""
    id: str
    name: str
    category: str
    description: str
    current_value: Any = None
    target_value: Any = None
    severity: Severity = Severity.MEDIUM
    compliance_frameworks: List[str] = field(default_factory=list)
    validation_rules: List[ValidationRule] = field(default_factory=list)
    backup_required: bool = True
    platform_specific: bool = False
    requires_reboot: bool = False


@dataclass
class AssessmentResult:
    """Result of security parameter assessment."""
    parameter_id: str
    current_value: Any
    expected_value: Any
    compliant: bool
    severity: Severity
    risk_description: str
    remediation_steps: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'parameter_id': self.parameter_id,
            'current_value': self.current_value,
            'expected_value': self.expected_value,
            'compliant': self.compliant,
            'severity': self.severity.value,
            'risk_description': self.risk_description,
            'remediation_steps': self.remediation_steps,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class HardeningResult:
    """Result of hardening operation."""
    parameter_id: str
    previous_value: Any
    applied_value: Any
    success: bool
    error_message: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    backup_created: bool = False
    requires_reboot: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'parameter_id': self.parameter_id,
            'previous_value': self.previous_value,
            'applied_value': self.applied_value,
            'success': self.success,
            'error_message': self.error_message,
            'timestamp': self.timestamp.isoformat(),
            'backup_created': self.backup_created,
            'requires_reboot': self.requires_reboot
        }


@dataclass
class ParameterBackup:
    """Backup data for a single parameter."""
    parameter_id: str
    original_value: Any
    restore_method: str
    restore_data: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class BackupData:
    """Complete backup information."""
    backup_id: str
    timestamp: datetime
    os_info: OSInfo
    parameters: List[ParameterBackup]
    checksum: str
    description: Optional[str] = None
    hardening_level: Optional[HardeningLevel] = None


@dataclass
class RestoreResult:
    """Result of backup restoration."""
    parameter_id: str
    success: bool
    error_message: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class RollbackResult:
    """Result of complete rollback operation."""
    backup_id: str
    restored_parameters: List[RestoreResult]
    success: bool
    timestamp: datetime = field(default_factory=datetime.now)
    errors: List[str] = field(default_factory=list)


@dataclass
class ValidationResult:
    """Result of parameter validation."""
    parameter_id: str
    valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'parameter_id': self.parameter_id,
            'valid': self.valid,
            'errors': self.errors,
            'warnings': self.warnings
        }


@dataclass
class OperationResult:
    """Generic operation result."""
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class HardeningError(Exception):
    """Base exception for hardening operations."""
    
    def __init__(self, message: str, error_code: str = "UNKNOWN", 
                 severity: Severity = Severity.MEDIUM, recoverable: bool = True):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.severity = severity
        self.recoverable = recoverable


class SystemError(HardeningError):
    """System-level errors (privileges, resources, etc.)."""
    pass


class ConfigurationError(HardeningError):
    """Configuration-related errors."""
    pass


class ValidationError(HardeningError):
    """Parameter validation errors."""
    pass


class BackupError(HardeningError):
    """Backup/restore operation errors."""
    pass


class NetworkError(HardeningError):
    """Network connectivity errors."""
    pass