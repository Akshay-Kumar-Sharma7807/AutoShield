"""Core hardening engine that orchestrates all operations."""

import logging
from typing import Callable, Dict, List, Optional, Tuple

from .assessment_engine import AssessmentEngine
from .remediation_engine import RemediationEngine
from .interfaces import (
    BackupManager, ConfigurationManager, ErrorHandler, HardeningModule,
    Logger, OSDetector, ReportEngine
)
from .models import (
    AssessmentResult, BackupData, HardeningLevel, HardeningResult,
    OperationMode, OperationResult, OSInfo, Parameter, RollbackResult,
    SystemInfo, ValidationResult
)


class HardeningEngine:
    """Main engine that orchestrates security hardening operations."""
    
    def __init__(self, os_detector: OSDetector, config_manager: ConfigurationManager,
                 backup_manager: BackupManager, report_engine: ReportEngine,
                 logger: Logger, error_handler: ErrorHandler):
        """Initialize the hardening engine with required components."""
        self.os_detector = os_detector
        self.config_manager = config_manager
        self.backup_manager = backup_manager
        self.report_engine = report_engine
        self.logger = logger
        self.error_handler = error_handler
        self.hardening_modules: Dict[str, HardeningModule] = {}
        self._system_info: Optional[SystemInfo] = None
        
        # Initialize specialized engines
        self.assessment_engine = AssessmentEngine(config_manager, logger)
        self.remediation_engine = RemediationEngine(config_manager, backup_manager, logger)
    
    def register_hardening_module(self, platform: str, module: HardeningModule) -> None:
        """Register a hardening module for a specific platform."""
        try:
            # Validate that the module implements the required interface
            if not hasattr(module, 'get_supported_parameters'):
                raise ValueError(f"Module for {platform} does not implement required interface")
            
            self.hardening_modules[platform] = module
            self.logger.log_operation("module_registered", {"platform": platform})
            
        except Exception as e:
            self.logger.log_error(e, {"operation": "module_registration", "platform": platform})
            raise
    
    def detect_os(self) -> OSInfo:
        """Detect and return operating system information."""
        try:
            system_info = self.os_detector.get_system_info()
            self._system_info = system_info
            
            self.logger.log_operation("os_detected", {
                "platform": system_info.os_info.platform.value,
                "version": system_info.os_info.version,
                "architecture": system_info.os_info.architecture.value
            })
            
            return system_info.os_info
        except Exception as e:
            self.logger.log_error(e, {"operation": "os_detection"})
            raise
    
    def load_hardening_module(self, os_info: OSInfo) -> HardeningModule:
        """Load appropriate hardening module for the detected OS."""
        platform_key = os_info.platform.value
        
        if platform_key not in self.hardening_modules:
            raise ValueError(f"No hardening module registered for platform: {platform_key}")
        
        module = self.hardening_modules[platform_key]
        
        # Validate module is still functional
        try:
            # Test basic functionality
            module.get_supported_parameters()
            self.logger.log_operation("module_loaded", {"platform": platform_key})
        except Exception as e:
            self.logger.log_error(e, {"operation": "module_validation", "platform": platform_key})
            raise ValueError(f"Hardening module for {platform_key} is not functional: {e}")
        
        return module
    
    def is_module_registered(self, platform: str) -> bool:
        """Check if a hardening module is registered for the specified platform."""
        return platform in self.hardening_modules
    
    def get_registered_platforms(self) -> List[str]:
        """Get list of platforms with registered hardening modules."""
        return list(self.hardening_modules.keys())
    
    def execute_assessment(self, level: HardeningLevel, 
                         custom_parameters: Optional[Dict[str, any]] = None) -> List[AssessmentResult]:
        """Execute security assessment for specified hardening level."""
        try:
            # Detect OS if not already done
            if not self._system_info:
                os_info = self.detect_os()
            else:
                os_info = self._system_info.os_info
            
            # Check if module is available
            if not self.is_module_registered(os_info.platform.value):
                raise ValueError(f"No hardening module available for {os_info.platform.value}. "
                               f"Please run with appropriate privileges.")
            
            # Load hardening module
            module = self.load_hardening_module(os_info)
            
            # Use assessment engine for comprehensive evaluation
            results = self.assessment_engine.assess_system_state(
                module, level, custom_parameters
            )
            
            return results
            
        except Exception as e:
            self.logger.log_error(e, {"operation": "assessment", "level": level.value})
            error_result = self.error_handler.handle_error(e)
            if not error_result.success:
                raise
            return []
    
    def execute_hardening(self, level: HardeningLevel, 
                         custom_parameters: Optional[Dict[str, any]] = None,
                         create_backup: bool = True,
                         continue_on_error: bool = True,
                         progress_callback: Optional[Callable] = None) -> Tuple[List[HardeningResult], str]:
        """Execute hardening for specified level and parameters."""
        try:
            # Detect OS if not already done
            if not self._system_info:
                os_info = self.detect_os()
            else:
                os_info = self._system_info.os_info
            
            # Load hardening module
            module = self.load_hardening_module(os_info)
            
            # Use remediation engine for comprehensive hardening with progress tracking
            results, backup_id = self.remediation_engine.execute_remediation(
                module, level, custom_parameters, create_backup, 
                continue_on_error, progress_callback
            )
            
            return results, backup_id
            
        except Exception as e:
            self.logger.log_error(e, {"operation": "hardening", "level": level.value})
            error_result = self.error_handler.handle_error(e)
            if not error_result.success:
                raise
            return [], None
    
    def execute_rollback(self, backup_id: str) -> RollbackResult:
        """Execute rollback to specified backup point."""
        try:
            # Get backup data
            backup_data = self.backup_manager.get_backup(backup_id)
            if not backup_data:
                raise ValueError(f"Backup not found: {backup_id}")
            
            # Verify backup integrity
            if not self.backup_manager.verify_backup_integrity(backup_id):
                raise ValueError(f"Backup integrity check failed: {backup_id}")
            
            # Load appropriate hardening module
            module = self.load_hardening_module(backup_data.os_info)
            
            # Execute restore
            restore_results = module.restore_backup(backup_data)
            
            # Create rollback result
            rollback_result = RollbackResult(
                backup_id=backup_id,
                restored_parameters=restore_results,
                success=all(r.success for r in restore_results),
                errors=[r.error_message for r in restore_results if r.error_message]
            )
            
            self.logger.log_operation("rollback_completed", {
                "backup_id": backup_id,
                "parameters_count": len(restore_results),
                "success_count": len([r for r in restore_results if r.success]),
                "overall_success": rollback_result.success
            })
            
            return rollback_result
            
        except Exception as e:
            self.logger.log_error(e, {"operation": "rollback", "backup_id": backup_id})
            error_result = self.error_handler.handle_error(e)
            if not error_result.success:
                raise
            return RollbackResult(backup_id=backup_id, restored_parameters=[], success=False)
    
    def generate_report(self, results: List[any], report_type: str, 
                       output_path: str) -> OperationResult:
        """Generate report for assessment or hardening results."""
        try:
            if report_type == "assessment" and all(isinstance(r, AssessmentResult) for r in results):
                return self.report_engine.generate_assessment_report(results, output_path)
            elif report_type == "hardening" and all(isinstance(r, HardeningResult) for r in results):
                return self.report_engine.generate_hardening_report(results, output_path)
            else:
                raise ValueError(f"Invalid report type or results: {report_type}")
                
        except Exception as e:
            self.logger.log_error(e, {"operation": "report_generation", "type": report_type})
            return self.error_handler.handle_error(e)
    
    def get_system_info(self) -> SystemInfo:
        """Get current system information."""
        if not self._system_info:
            self._system_info = self.os_detector.get_system_info()
        return self._system_info
    
    def list_backups(self) -> List[BackupData]:
        """List all available backups."""
        return self.backup_manager.list_backups()
    
    def get_supported_parameters(self, platform: Optional[str] = None) -> List[Parameter]:
        """Get supported parameters for specified platform or current system."""
        if not platform:
            if not self._system_info:
                os_info = self.detect_os()
            else:
                os_info = self._system_info.os_info
            platform = os_info.platform.value
        
        if platform not in self.hardening_modules:
            raise ValueError(f"No module registered for platform: {platform}")
        
        module = self.hardening_modules[platform]
        return module.get_supported_parameters()
    
    def execute_selective_assessment(self, parameters: List[Parameter]) -> List[AssessmentResult]:
        """Execute assessment for specific parameters."""
        try:
            # Detect OS if not already done
            if not self._system_info:
                os_info = self.detect_os()
            else:
                os_info = self._system_info.os_info
            
            # Load hardening module
            module = self.load_hardening_module(os_info)
            
            # Use assessment engine for specific parameters
            results = self.assessment_engine.assess_specific_parameters(module, parameters)
            
            return results
            
        except Exception as e:
            self.logger.log_error(e, {"operation": "selective_assessment"})
            error_result = self.error_handler.handle_error(e)
            if not error_result.success:
                raise
            return []
    
    def execute_selective_hardening(self, parameters: List[Parameter],
                                  create_backup: bool = True,
                                  continue_on_error: bool = True,
                                  progress_callback: Optional[Callable] = None) -> Tuple[List[HardeningResult], str]:
        """Execute hardening for specific parameters."""
        try:
            # Detect OS if not already done
            if not self._system_info:
                os_info = self.detect_os()
            else:
                os_info = self._system_info.os_info
            
            # Load hardening module
            module = self.load_hardening_module(os_info)
            
            # Use remediation engine for selective hardening
            results, backup_id = self.remediation_engine.execute_selective_remediation(
                module, parameters, create_backup, continue_on_error, progress_callback
            )
            
            return results, backup_id
            
        except Exception as e:
            self.logger.log_error(e, {"operation": "selective_hardening"})
            error_result = self.error_handler.handle_error(e)
            if not error_result.success:
                raise
            return [], None
    
    def retry_failed_hardening(self, failed_results: List[HardeningResult],
                             progress_callback: Optional[Callable] = None) -> List[HardeningResult]:
        """Retry hardening for previously failed parameters."""
        try:
            # Detect OS if not already done
            if not self._system_info:
                os_info = self.detect_os()
            else:
                os_info = self._system_info.os_info
            
            # Load hardening module
            module = self.load_hardening_module(os_info)
            
            # Use remediation engine for retry
            results = self.remediation_engine.retry_failed_remediation(
                module, failed_results, progress_callback
            )
            
            return results
            
        except Exception as e:
            self.logger.log_error(e, {"operation": "retry_failed_hardening"})
            error_result = self.error_handler.handle_error(e)
            if not error_result.success:
                raise
            return []
    
    def get_assessment_summary(self, results: List[AssessmentResult]) -> Dict[str, any]:
        """Get comprehensive assessment summary."""
        return self.assessment_engine.get_assessment_summary(results)
    
    def get_remediation_summary(self, results: List[HardeningResult]) -> Dict[str, any]:
        """Get comprehensive remediation summary."""
        return self.remediation_engine.get_remediation_summary(results)
    
    def compare_assessments(self, current_results: List[AssessmentResult],
                          baseline_results: List[AssessmentResult]) -> Dict[str, any]:
        """Compare current assessment results with baseline."""
        return self.assessment_engine.compare_with_baseline(current_results, baseline_results)