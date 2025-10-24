"""Remediation engine for applying security hardening configurations."""

import logging
import time
from datetime import datetime
from typing import Callable, Dict, List, Optional, Tuple

from .interfaces import BackupManager, ConfigurationManager, HardeningModule, Logger
from .models import (
    BackupData, HardeningLevel, HardeningResult, OperationResult, Parameter,
    Severity, ValidationResult, HardeningError, SystemError
)


class ProgressTracker:
    """Tracks progress of remediation operations."""
    
    def __init__(self, total_items: int, progress_callback: Optional[Callable] = None):
        """
        Initialize progress tracker.
        
        Args:
            total_items: Total number of items to process
            progress_callback: Optional callback function for progress updates
        """
        self.total_items = total_items
        self.completed_items = 0
        self.failed_items = 0
        self.skipped_items = 0
        self.start_time = datetime.now()
        self.progress_callback = progress_callback
        self.current_item = None
        
    def update_progress(self, item_id: str, status: str, message: str = ""):
        """
        Update progress for current item.
        
        Args:
            item_id: ID of the item being processed
            status: Status of the item (processing, completed, failed, skipped)
            message: Optional status message
        """
        self.current_item = item_id
        
        if status == "completed":
            self.completed_items += 1
        elif status == "failed":
            self.failed_items += 1
        elif status == "skipped":
            self.skipped_items += 1
        
        progress_data = {
            "current_item": item_id,
            "status": status,
            "message": message,
            "completed": self.completed_items,
            "failed": self.failed_items,
            "skipped": self.skipped_items,
            "total": self.total_items,
            "percentage": self.get_percentage(),
            "elapsed_time": self.get_elapsed_time(),
            "estimated_remaining": self.get_estimated_remaining_time()
        }
        
        if self.progress_callback:
            self.progress_callback(progress_data)
    
    def get_percentage(self) -> float:
        """Get completion percentage."""
        if self.total_items == 0:
            return 100.0
        processed = self.completed_items + self.failed_items + self.skipped_items
        return round((processed / self.total_items) * 100, 2)
    
    def get_elapsed_time(self) -> float:
        """Get elapsed time in seconds."""
        return (datetime.now() - self.start_time).total_seconds()
    
    def get_estimated_remaining_time(self) -> Optional[float]:
        """Get estimated remaining time in seconds."""
        processed = self.completed_items + self.failed_items + self.skipped_items
        if processed == 0:
            return None
        
        elapsed = self.get_elapsed_time()
        remaining_items = self.total_items - processed
        avg_time_per_item = elapsed / processed
        
        return remaining_items * avg_time_per_item
    
    def is_complete(self) -> bool:
        """Check if all items have been processed."""
        processed = self.completed_items + self.failed_items + self.skipped_items
        return processed >= self.total_items


class RemediationEngine:
    """Engine for applying security hardening configurations with progress tracking."""
    
    def __init__(self, config_manager: ConfigurationManager, 
                 backup_manager: BackupManager, logger: Logger):
        """Initialize the remediation engine."""
        self.config_manager = config_manager
        self.backup_manager = backup_manager
        self.logger = logger
        self.max_retries = 3
        self.retry_delay = 1.0  # seconds
        
    def execute_remediation(self, hardening_module: HardeningModule,
                          hardening_level: HardeningLevel,
                          custom_parameters: Optional[Dict[str, any]] = None,
                          create_backup: bool = True,
                          continue_on_error: bool = True,
                          progress_callback: Optional[Callable] = None) -> Tuple[List[HardeningResult], str]:
        """
        Execute comprehensive remediation with progress tracking.
        
        Args:
            hardening_module: Platform-specific hardening module
            hardening_level: Target hardening level
            custom_parameters: Optional custom parameter overrides
            create_backup: Whether to create backup before remediation
            continue_on_error: Whether to continue processing after errors
            progress_callback: Optional callback for progress updates
            
        Returns:
            Tuple of (remediation results, backup_id if created)
        """
        backup_id = None
        
        try:
            self.logger.log_operation("remediation_started", {
                "hardening_level": hardening_level.value,
                "create_backup": create_backup,
                "continue_on_error": continue_on_error,
                "has_custom_params": custom_parameters is not None
            })
            
            # Load and validate parameters
            parameters = self._load_and_validate_parameters(hardening_level, custom_parameters)
            
            # Initialize progress tracker
            progress_tracker = ProgressTracker(len(parameters), progress_callback)
            
            # Create backup if requested
            if create_backup:
                backup_id = self._create_remediation_backup(hardening_module, parameters, progress_tracker)
            
            # Execute remediation with progress tracking
            results = self._execute_remediation_with_tracking(
                hardening_module, parameters, progress_tracker, continue_on_error
            )
            
            # Log completion statistics
            success_count = len([r for r in results if r.success])
            failure_count = len([r for r in results if not r.success])
            
            self.logger.log_operation("remediation_completed", {
                "total_parameters": len(parameters),
                "successful": success_count,
                "failed": failure_count,
                "backup_id": backup_id,
                "completion_percentage": progress_tracker.get_percentage(),
                "total_time_seconds": progress_tracker.get_elapsed_time()
            })
            
            return results, backup_id
            
        except Exception as e:
            self.logger.log_error(e, {
                "operation": "execute_remediation",
                "backup_id": backup_id
            })
            raise
    
    def execute_selective_remediation(self, hardening_module: HardeningModule,
                                    parameters: List[Parameter],
                                    create_backup: bool = True,
                                    continue_on_error: bool = True,
                                    progress_callback: Optional[Callable] = None) -> Tuple[List[HardeningResult], str]:
        """
        Execute remediation for specific parameters.
        
        Args:
            hardening_module: Platform-specific hardening module
            parameters: Specific parameters to remediate
            create_backup: Whether to create backup before remediation
            continue_on_error: Whether to continue processing after errors
            progress_callback: Optional callback for progress updates
            
        Returns:
            Tuple of (remediation results, backup_id if created)
        """
        backup_id = None
        
        try:
            self.logger.log_operation("selective_remediation_started", {
                "parameter_count": len(parameters),
                "parameter_ids": [p.id for p in parameters],
                "create_backup": create_backup
            })
            
            # Validate parameters
            validation_results = self.config_manager.validate_parameters(parameters)
            invalid_params = [r for r in validation_results if not r.valid]
            
            if invalid_params:
                self.logger.log_operation("validation_warnings", {
                    "invalid_params": [r.parameter_id for r in invalid_params]
                })
            
            # Filter valid parameters
            valid_parameters = [p for p in parameters 
                              if p.id not in [r.parameter_id for r in invalid_params]]
            
            if not valid_parameters:
                raise HardeningError("No valid parameters to remediate", "NO_VALID_PARAMETERS")
            
            # Initialize progress tracker
            progress_tracker = ProgressTracker(len(valid_parameters), progress_callback)
            
            # Create backup if requested
            if create_backup:
                backup_id = self._create_remediation_backup(hardening_module, valid_parameters, progress_tracker)
            
            # Execute remediation
            results = self._execute_remediation_with_tracking(
                hardening_module, valid_parameters, progress_tracker, continue_on_error
            )
            
            self.logger.log_operation("selective_remediation_completed", {
                "processed_parameters": len(results),
                "backup_id": backup_id
            })
            
            return results, backup_id
            
        except Exception as e:
            self.logger.log_error(e, {"operation": "execute_selective_remediation"})
            raise
    
    def retry_failed_remediation(self, hardening_module: HardeningModule,
                               failed_results: List[HardeningResult],
                               progress_callback: Optional[Callable] = None) -> List[HardeningResult]:
        """
        Retry remediation for previously failed parameters.
        
        Args:
            hardening_module: Platform-specific hardening module
            failed_results: Previous failed remediation results
            progress_callback: Optional callback for progress updates
            
        Returns:
            List of retry remediation results
        """
        try:
            self.logger.log_operation("retry_remediation_started", {
                "failed_count": len(failed_results),
                "failed_parameter_ids": [r.parameter_id for r in failed_results]
            })
            
            # Get supported parameters to reconstruct Parameter objects
            supported_params = hardening_module.get_supported_parameters()
            param_lookup = {p.id: p for p in supported_params}
            
            # Reconstruct parameters for failed results
            retry_parameters = []
            for result in failed_results:
                if result.parameter_id in param_lookup:
                    param = param_lookup[result.parameter_id]
                    # Update target value from the failed result
                    param.target_value = result.applied_value
                    retry_parameters.append(param)
            
            if not retry_parameters:
                self.logger.log_operation("no_retry_parameters", {})
                return []
            
            # Initialize progress tracker
            progress_tracker = ProgressTracker(len(retry_parameters), progress_callback)
            
            # Execute retry with enhanced error handling
            results = self._execute_remediation_with_tracking(
                hardening_module, retry_parameters, progress_tracker, 
                continue_on_error=True, is_retry=True
            )
            
            retry_success_count = len([r for r in results if r.success])
            self.logger.log_operation("retry_remediation_completed", {
                "retry_attempts": len(results),
                "retry_successes": retry_success_count
            })
            
            return results
            
        except Exception as e:
            self.logger.log_error(e, {"operation": "retry_failed_remediation"})
            raise
    
    def _load_and_validate_parameters(self, hardening_level: HardeningLevel,
                                    custom_parameters: Optional[Dict[str, any]] = None) -> List[Parameter]:
        """Load and validate parameters for remediation."""
        # Load parameters for hardening level
        parameters = self.config_manager.load_hardening_level(hardening_level)
        
        # Merge custom parameters if provided
        if custom_parameters:
            parameters = self.config_manager.merge_custom_parameters(
                parameters, custom_parameters
            )
        
        # Validate parameters
        validation_results = self.config_manager.validate_parameters(parameters)
        invalid_params = [r for r in validation_results if not r.valid]
        
        if invalid_params:
            error_details = []
            for invalid in invalid_params:
                error_details.append(f"{invalid.parameter_id}: {', '.join(invalid.errors)}")
            
            error_msg = f"Invalid parameters detected: {'; '.join(error_details)}"
            self.logger.log_error(Exception(error_msg), {"invalid_params": invalid_params})
            raise HardeningError(error_msg, "INVALID_PARAMETERS")
        
        return parameters
    
    def _create_remediation_backup(self, hardening_module: HardeningModule,
                                 parameters: List[Parameter],
                                 progress_tracker: ProgressTracker) -> str:
        """Create backup before remediation."""
        try:
            progress_tracker.update_progress("backup", "processing", "Creating system backup...")
            
            backup_data = hardening_module.create_backup(parameters)
            backup_id = self.backup_manager.create_backup(backup_data)
            
            progress_tracker.update_progress("backup", "completed", f"Backup created: {backup_id}")
            
            self.logger.log_operation("remediation_backup_created", {
                "backup_id": backup_id,
                "parameter_count": len(parameters)
            })
            
            return backup_id
            
        except Exception as e:
            progress_tracker.update_progress("backup", "failed", f"Backup failed: {str(e)}")
            self.logger.log_error(e, {"operation": "create_remediation_backup"})
            raise HardeningError(f"Failed to create backup: {str(e)}", "BACKUP_FAILED")
    
    def _execute_remediation_with_tracking(self, hardening_module: HardeningModule,
                                         parameters: List[Parameter],
                                         progress_tracker: ProgressTracker,
                                         continue_on_error: bool = True,
                                         is_retry: bool = False) -> List[HardeningResult]:
        """Execute remediation with detailed progress tracking and error handling."""
        results = []
        critical_errors = []
        
        for i, parameter in enumerate(parameters):
            try:
                progress_tracker.update_progress(
                    parameter.id, "processing", 
                    f"Applying {parameter.name} ({i+1}/{len(parameters)})"
                )
                
                # Apply single parameter with retry logic
                result = self._apply_parameter_with_retry(
                    hardening_module, parameter, is_retry
                )
                
                results.append(result)
                
                if result.success:
                    progress_tracker.update_progress(
                        parameter.id, "completed", 
                        f"Successfully applied {parameter.name}"
                    )
                else:
                    progress_tracker.update_progress(
                        parameter.id, "failed", 
                        f"Failed to apply {parameter.name}: {result.error_message}"
                    )
                    
                    # Check if this is a critical error that should stop processing
                    if not continue_on_error and result.error_message:
                        if "permission" in result.error_message.lower() or "access" in result.error_message.lower():
                            critical_errors.append(f"Critical permission error for {parameter.id}")
                            break
                
                # Small delay between operations to prevent system overload
                time.sleep(0.1)
                
            except Exception as e:
                error_msg = f"Unexpected error processing {parameter.id}: {str(e)}"
                
                result = HardeningResult(
                    parameter_id=parameter.id,
                    previous_value=parameter.current_value,
                    applied_value=parameter.target_value,
                    success=False,
                    error_message=error_msg
                )
                
                results.append(result)
                progress_tracker.update_progress(parameter.id, "failed", error_msg)
                
                self.logger.log_error(e, {
                    "parameter_id": parameter.id,
                    "operation": "apply_parameter"
                })
                
                if not continue_on_error:
                    critical_errors.append(error_msg)
                    break
        
        # Handle critical errors
        if critical_errors and not continue_on_error:
            error_summary = "; ".join(critical_errors)
            self.logger.log_error(Exception(error_summary), {
                "operation": "remediation_stopped",
                "processed_count": len(results)
            })
            raise SystemError(f"Remediation stopped due to critical errors: {error_summary}")
        
        return results
    
    def _apply_parameter_with_retry(self, hardening_module: HardeningModule,
                                  parameter: Parameter, is_retry: bool = False) -> HardeningResult:
        """Apply single parameter with retry logic."""
        last_error = None
        retry_count = self.max_retries if not is_retry else 1  # Reduce retries for retry operations
        
        for attempt in range(retry_count):
            try:
                # Apply the parameter
                results = hardening_module.apply_hardening([parameter])
                
                if results and len(results) > 0:
                    result = results[0]
                    
                    if result.success:
                        return result
                    else:
                        last_error = result.error_message
                        
                        # Don't retry certain types of errors
                        if last_error and any(keyword in last_error.lower() 
                                            for keyword in ["not found", "invalid", "unsupported"]):
                            break
                
                # Wait before retry (except on last attempt)
                if attempt < retry_count - 1:
                    time.sleep(self.retry_delay * (attempt + 1))  # Exponential backoff
                    
            except Exception as e:
                last_error = str(e)
                
                # Log retry attempts
                if attempt < retry_count - 1:
                    self.logger.log_operation("parameter_retry", {
                        "parameter_id": parameter.id,
                        "attempt": attempt + 1,
                        "error": last_error
                    })
        
        # All retries failed
        return HardeningResult(
            parameter_id=parameter.id,
            previous_value=parameter.current_value,
            applied_value=parameter.target_value,
            success=False,
            error_message=f"Failed after {retry_count} attempts: {last_error}"
        )
    
    def get_remediation_summary(self, results: List[HardeningResult]) -> Dict[str, any]:
        """
        Generate comprehensive remediation summary.
        
        Args:
            results: Remediation results
            
        Returns:
            Dictionary containing remediation summary
        """
        if not results:
            return {
                "total_parameters": 0,
                "successful": 0,
                "failed": 0,
                "success_rate": 0.0,
                "failed_parameters": [],
                "reboot_required": False
            }
        
        successful = [r for r in results if r.success]
        failed = [r for r in results if not r.success]
        reboot_required = any(r.requires_reboot for r in successful)
        
        # Categorize failures by error type
        failure_categories = {}
        for result in failed:
            if result.error_message:
                # Simple categorization based on error message keywords
                if "permission" in result.error_message.lower():
                    category = "permission_errors"
                elif "not found" in result.error_message.lower():
                    category = "resource_not_found"
                elif "invalid" in result.error_message.lower():
                    category = "invalid_configuration"
                else:
                    category = "other_errors"
                
                if category not in failure_categories:
                    failure_categories[category] = []
                failure_categories[category].append(result.parameter_id)
        
        return {
            "remediation_timestamp": datetime.now().isoformat(),
            "total_parameters": len(results),
            "successful": len(successful),
            "failed": len(failed),
            "success_rate": round((len(successful) / len(results)) * 100, 2),
            "failed_parameters": [r.parameter_id for r in failed],
            "failure_categories": failure_categories,
            "reboot_required": reboot_required,
            "parameters_requiring_reboot": [r.parameter_id for r in successful if r.requires_reboot],
            "recommendations": self._generate_remediation_recommendations(results)
        }
    
    def _generate_remediation_recommendations(self, results: List[HardeningResult]) -> List[str]:
        """Generate recommendations based on remediation results."""
        recommendations = []
        
        failed_results = [r for r in results if not r.success]
        successful_results = [r for r in results if r.success]
        
        # Reboot recommendation
        if any(r.requires_reboot for r in successful_results):
            recommendations.append("System reboot required to complete security hardening")
        
        # Failure analysis recommendations
        if failed_results:
            permission_failures = [r for r in failed_results 
                                 if r.error_message and "permission" in r.error_message.lower()]
            
            if permission_failures:
                recommendations.append("Run tool with elevated privileges to resolve permission errors")
            
            if len(failed_results) > len(results) * 0.5:
                recommendations.append("High failure rate detected - review system compatibility and prerequisites")
            
            recommendations.append(f"Review and manually address {len(failed_results)} failed parameters")
        
        # Success recommendations
        success_rate = len(successful_results) / len(results) * 100 if results else 0
        
        if success_rate >= 95:
            recommendations.append("Excellent remediation success rate - system is well-hardened")
        elif success_rate >= 80:
            recommendations.append("Good remediation success rate - address remaining issues")
        else:
            recommendations.append("Consider investigating system issues affecting remediation success")
        
        return recommendations