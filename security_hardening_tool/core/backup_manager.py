"""Backup and rollback management implementation."""

import hashlib
import json
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from .interfaces import BackupManager as BackupManagerInterface
from .models import (
    BackupData, BackupError, HardeningLevel, OSInfo, ParameterBackup,
    RestoreResult, RollbackResult
)


class BackupManager(BackupManagerInterface):
    """Concrete implementation of backup management with secure storage and integrity verification."""
    
    def __init__(self, backup_directory: str = None):
        """Initialize backup manager with storage directory."""
        if backup_directory is None:
            # Default to .backups directory in current working directory
            backup_directory = os.path.join(os.getcwd(), ".backups")
        
        self.backup_directory = Path(backup_directory)
        self.backup_directory.mkdir(parents=True, exist_ok=True)
        
        # Create metadata directory for backup indexes
        self.metadata_directory = self.backup_directory / "metadata"
        self.metadata_directory.mkdir(exist_ok=True)
        
        # Initialize backup index file
        self.index_file = self.metadata_directory / "backup_index.json"
        self._initialize_index()
    
    def _initialize_index(self) -> None:
        """Initialize backup index file if it doesn't exist."""
        if not self.index_file.exists():
            index_data = {
                "version": "1.0",
                "created": datetime.now().isoformat(),
                "backups": {}
            }
            with open(self.index_file, 'w') as f:
                json.dump(index_data, f, indent=2)
    
    def _load_index(self) -> Dict:
        """Load backup index from file."""
        try:
            with open(self.index_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            raise BackupError(f"Failed to load backup index: {str(e)}", "INDEX_LOAD_ERROR")
    
    def _save_index(self, index_data: Dict) -> None:
        """Save backup index to file."""
        try:
            with open(self.index_file, 'w') as f:
                json.dump(index_data, f, indent=2)
        except Exception as e:
            raise BackupError(f"Failed to save backup index: {str(e)}", "INDEX_SAVE_ERROR")
    
    def _calculate_checksum(self, data: str) -> str:
        """Calculate SHA-256 checksum for data integrity verification."""
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
    
    def _serialize_backup_data(self, backup_data: BackupData) -> str:
        """Serialize backup data to JSON string."""
        # Convert dataclass to dictionary for JSON serialization
        backup_dict = {
            "backup_id": backup_data.backup_id,
            "timestamp": backup_data.timestamp.isoformat(),
            "os_info": {
                "platform": backup_data.os_info.platform.value,
                "version": backup_data.os_info.version,
                "build": backup_data.os_info.build,
                "architecture": backup_data.os_info.architecture.value,
                "edition": backup_data.os_info.edition,
                "service_pack": backup_data.os_info.service_pack
            },
            "parameters": [
                {
                    "parameter_id": param.parameter_id,
                    "original_value": param.original_value,
                    "restore_method": param.restore_method,
                    "restore_data": param.restore_data,
                    "timestamp": param.timestamp.isoformat()
                }
                for param in backup_data.parameters
            ],
            "checksum": backup_data.checksum,
            "description": backup_data.description,
            "hardening_level": backup_data.hardening_level.value if backup_data.hardening_level else None
        }
        
        return json.dumps(backup_dict, indent=2, sort_keys=True)
    
    def _deserialize_backup_data(self, json_data: str) -> BackupData:
        """Deserialize JSON string to BackupData object."""
        try:
            data = json.loads(json_data)
            
            # Reconstruct OSInfo
            from .models import Platform, Architecture
            os_info = OSInfo(
                platform=Platform(data["os_info"]["platform"]),
                version=data["os_info"]["version"],
                build=data["os_info"]["build"],
                architecture=Architecture(data["os_info"]["architecture"]),
                edition=data["os_info"]["edition"],
                service_pack=data["os_info"]["service_pack"]
            )
            
            # Reconstruct ParameterBackup objects
            parameters = [
                ParameterBackup(
                    parameter_id=param["parameter_id"],
                    original_value=param["original_value"],
                    restore_method=param["restore_method"],
                    restore_data=param["restore_data"],
                    timestamp=datetime.fromisoformat(param["timestamp"])
                )
                for param in data["parameters"]
            ]
            
            # Reconstruct BackupData
            return BackupData(
                backup_id=data["backup_id"],
                timestamp=datetime.fromisoformat(data["timestamp"]),
                os_info=os_info,
                parameters=parameters,
                checksum=data["checksum"],
                description=data["description"],
                hardening_level=HardeningLevel(data["hardening_level"]) if data["hardening_level"] else None
            )
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            raise BackupError(f"Failed to deserialize backup data: {str(e)}", "DESERIALIZATION_ERROR")
    
    def create_backup(self, backup_data: BackupData) -> str:
        """Create and store backup data with integrity verification."""
        try:
            # Generate unique backup ID if not provided
            if not backup_data.backup_id:
                backup_data.backup_id = str(uuid.uuid4())
            
            # Serialize backup data
            serialized_data = self._serialize_backup_data(backup_data)
            
            # Calculate and update checksum
            backup_data.checksum = self._calculate_checksum(serialized_data)
            
            # Re-serialize with updated checksum
            serialized_data = self._serialize_backup_data(backup_data)
            
            # Create backup file
            backup_file = self.backup_directory / f"{backup_data.backup_id}.json"
            with open(backup_file, 'w') as f:
                f.write(serialized_data)
            
            # Update backup index
            index_data = self._load_index()
            index_data["backups"][backup_data.backup_id] = {
                "timestamp": backup_data.timestamp.isoformat(),
                "description": backup_data.description,
                "hardening_level": backup_data.hardening_level.value if backup_data.hardening_level else None,
                "parameter_count": len(backup_data.parameters),
                "os_platform": backup_data.os_info.platform.value,
                "os_version": backup_data.os_info.version,
                "file_path": str(backup_file.relative_to(self.backup_directory))
            }
            self._save_index(index_data)
            
            return backup_data.backup_id
            
        except Exception as e:
            raise BackupError(f"Failed to create backup: {str(e)}", "BACKUP_CREATION_ERROR")
    
    def list_backups(self) -> List[BackupData]:
        """List all available backups with metadata."""
        try:
            index_data = self._load_index()
            backups = []
            
            for backup_id, metadata in index_data["backups"].items():
                backup_file = self.backup_directory / metadata["file_path"]
                if backup_file.exists():
                    try:
                        with open(backup_file, 'r') as f:
                            backup_data = self._deserialize_backup_data(f.read())
                        backups.append(backup_data)
                    except Exception as e:
                        # Log corrupted backup but continue
                        print(f"Warning: Corrupted backup {backup_id}: {str(e)}")
                        continue
            
            # Sort by timestamp (newest first)
            backups.sort(key=lambda x: x.timestamp, reverse=True)
            return backups
            
        except Exception as e:
            raise BackupError(f"Failed to list backups: {str(e)}", "BACKUP_LIST_ERROR")
    
    def get_backup(self, backup_id: str) -> Optional[BackupData]:
        """Retrieve specific backup by ID with integrity verification."""
        try:
            index_data = self._load_index()
            
            if backup_id not in index_data["backups"]:
                return None
            
            metadata = index_data["backups"][backup_id]
            backup_file = self.backup_directory / metadata["file_path"]
            
            if not backup_file.exists():
                raise BackupError(f"Backup file not found: {backup_file}", "BACKUP_FILE_NOT_FOUND")
            
            with open(backup_file, 'r') as f:
                backup_data = self._deserialize_backup_data(f.read())
            
            # Verify integrity
            if not self.verify_backup_integrity(backup_id):
                raise BackupError(f"Backup integrity verification failed: {backup_id}", "INTEGRITY_VERIFICATION_FAILED")
            
            return backup_data
            
        except BackupError:
            raise
        except Exception as e:
            raise BackupError(f"Failed to retrieve backup {backup_id}: {str(e)}", "BACKUP_RETRIEVAL_ERROR")
    
    def delete_backup(self, backup_id: str) -> bool:
        """Delete backup by ID."""
        try:
            index_data = self._load_index()
            
            if backup_id not in index_data["backups"]:
                return False
            
            metadata = index_data["backups"][backup_id]
            backup_file = self.backup_directory / metadata["file_path"]
            
            # Remove backup file
            if backup_file.exists():
                backup_file.unlink()
            
            # Remove from index
            del index_data["backups"][backup_id]
            self._save_index(index_data)
            
            return True
            
        except Exception as e:
            raise BackupError(f"Failed to delete backup {backup_id}: {str(e)}", "BACKUP_DELETION_ERROR")
    
    def verify_backup_integrity(self, backup_id: str) -> bool:
        """Verify backup data integrity using SHA-256 checksum."""
        try:
            index_data = self._load_index()
            
            if backup_id not in index_data["backups"]:
                return False
            
            metadata = index_data["backups"][backup_id]
            backup_file = self.backup_directory / metadata["file_path"]
            
            if not backup_file.exists():
                return False
            
            with open(backup_file, 'r') as f:
                file_content = f.read()
            
            # Parse backup data to get stored checksum
            backup_data = self._deserialize_backup_data(file_content)
            stored_checksum = backup_data.checksum
            
            # Create a copy without checksum for verification
            backup_data_copy = BackupData(
                backup_id=backup_data.backup_id,
                timestamp=backup_data.timestamp,
                os_info=backup_data.os_info,
                parameters=backup_data.parameters,
                checksum="",  # Empty for calculation
                description=backup_data.description,
                hardening_level=backup_data.hardening_level
            )
            
            # Calculate checksum of data without the checksum field
            serialized_without_checksum = self._serialize_backup_data(backup_data_copy)
            calculated_checksum = self._calculate_checksum(serialized_without_checksum)
            
            return stored_checksum == calculated_checksum
            
        except Exception as e:
            print(f"Error verifying backup integrity: {str(e)}")
            return False
    
    def cleanup_old_backups(self, max_backups: int = 10) -> List[str]:
        """Clean up old backups, keeping only the most recent ones."""
        try:
            backups = self.list_backups()
            
            if len(backups) <= max_backups:
                return []
            
            # Sort by timestamp and keep only the newest
            backups.sort(key=lambda x: x.timestamp, reverse=True)
            backups_to_delete = backups[max_backups:]
            
            deleted_ids = []
            for backup in backups_to_delete:
                if self.delete_backup(backup.backup_id):
                    deleted_ids.append(backup.backup_id)
            
            return deleted_ids
            
        except Exception as e:
            raise BackupError(f"Failed to cleanup old backups: {str(e)}", "BACKUP_CLEANUP_ERROR")
    
    def execute_rollback(self, backup_id: str, hardening_module, 
                        parameter_ids: Optional[List[str]] = None) -> RollbackResult:
        """Execute rollback with selective parameter restoration and validation."""
        try:
            # Get backup data
            backup_data = self.get_backup(backup_id)
            if not backup_data:
                raise BackupError(f"Backup not found: {backup_id}", "BACKUP_NOT_FOUND")
            
            # Verify backup integrity
            if not self.verify_backup_integrity(backup_id):
                raise BackupError(f"Backup integrity verification failed: {backup_id}", "INTEGRITY_VERIFICATION_FAILED")
            
            # Filter parameters if selective rollback requested
            parameters_to_restore = backup_data.parameters
            if parameter_ids:
                parameters_to_restore = [
                    param for param in backup_data.parameters 
                    if param.parameter_id in parameter_ids
                ]
                
                # Check if all requested parameters exist
                found_ids = {param.parameter_id for param in parameters_to_restore}
                missing_ids = set(parameter_ids) - found_ids
                if missing_ids:
                    raise BackupError(f"Parameters not found in backup: {missing_ids}", "PARAMETERS_NOT_FOUND")
            
            # Create filtered backup data for restoration
            filtered_backup = BackupData(
                backup_id=backup_data.backup_id,
                timestamp=backup_data.timestamp,
                os_info=backup_data.os_info,
                parameters=parameters_to_restore,
                checksum=backup_data.checksum,
                description=backup_data.description,
                hardening_level=backup_data.hardening_level
            )
            
            # Execute restore through hardening module
            restore_results = hardening_module.restore_backup(filtered_backup)
            
            # Validate restoration success
            validation_results = self._validate_rollback_results(
                parameters_to_restore, restore_results, hardening_module
            )
            
            # Create comprehensive rollback result
            rollback_result = RollbackResult(
                backup_id=backup_id,
                restored_parameters=restore_results,
                success=all(r.success for r in restore_results),
                errors=[r.error_message for r in restore_results if r.error_message]
            )
            
            # Add validation errors if any
            validation_errors = [
                f"Validation failed for {result.parameter_id}: {', '.join(result.errors)}"
                for result in validation_results if not result.valid
            ]
            rollback_result.errors.extend(validation_errors)
            
            # Update overall success based on validation
            if validation_errors:
                rollback_result.success = False
            
            return rollback_result
            
        except BackupError:
            raise
        except Exception as e:
            raise BackupError(f"Failed to execute rollback: {str(e)}", "ROLLBACK_EXECUTION_ERROR")
    
    def _validate_rollback_results(self, expected_parameters: List[ParameterBackup], 
                                 restore_results: List[RestoreResult],
                                 hardening_module) -> List:
        """Validate that rollback was successful by checking current values."""
        from .models import ValidationResult
        
        validation_results = []
        
        # Create a map of restore results for quick lookup
        restore_map = {result.parameter_id: result for result in restore_results}
        
        for param_backup in expected_parameters:
            param_id = param_backup.parameter_id
            validation_result = ValidationResult(parameter_id=param_id, valid=True)
            
            # Check if parameter was restored
            if param_id not in restore_map:
                validation_result.valid = False
                validation_result.errors.append("Parameter was not restored")
                validation_results.append(validation_result)
                continue
            
            restore_result = restore_map[param_id]
            
            # Check if restoration was successful
            if not restore_result.success:
                validation_result.valid = False
                validation_result.errors.append(f"Restoration failed: {restore_result.error_message}")
                validation_results.append(validation_result)
                continue
            
            # Additional validation could be added here to verify the actual system state
            # matches the expected restored value, but this would require access to
            # the current parameter values through the hardening module
            
            validation_results.append(validation_result)
        
        return validation_results
    
    def get_rollback_preview(self, backup_id: str, 
                           parameter_ids: Optional[List[str]] = None) -> Dict[str, any]:
        """Get preview of what would be restored in a rollback operation."""
        try:
            backup_data = self.get_backup(backup_id)
            if not backup_data:
                raise BackupError(f"Backup not found: {backup_id}", "BACKUP_NOT_FOUND")
            
            # Filter parameters if selective rollback requested
            parameters_to_restore = backup_data.parameters
            if parameter_ids:
                parameters_to_restore = [
                    param for param in backup_data.parameters 
                    if param.parameter_id in parameter_ids
                ]
            
            preview = {
                "backup_id": backup_id,
                "backup_timestamp": backup_data.timestamp.isoformat(),
                "backup_description": backup_data.description,
                "hardening_level": backup_data.hardening_level.value if backup_data.hardening_level else None,
                "os_info": {
                    "platform": backup_data.os_info.platform.value,
                    "version": backup_data.os_info.version,
                    "architecture": backup_data.os_info.architecture.value
                },
                "parameters_to_restore": [
                    {
                        "parameter_id": param.parameter_id,
                        "original_value": param.original_value,
                        "restore_method": param.restore_method,
                        "timestamp": param.timestamp.isoformat()
                    }
                    for param in parameters_to_restore
                ],
                "total_parameters": len(parameters_to_restore)
            }
            
            return preview
            
        except BackupError:
            raise
        except Exception as e:
            raise BackupError(f"Failed to generate rollback preview: {str(e)}", "ROLLBACK_PREVIEW_ERROR")
    
    def validate_rollback_compatibility(self, backup_id: str, current_os_info: OSInfo) -> Dict[str, any]:
        """Validate if a backup is compatible with the current system for rollback."""
        try:
            backup_data = self.get_backup(backup_id)
            if not backup_data:
                raise BackupError(f"Backup not found: {backup_id}", "BACKUP_NOT_FOUND")
            
            compatibility = {
                "compatible": True,
                "warnings": [],
                "errors": []
            }
            
            # Check platform compatibility
            if backup_data.os_info.platform != current_os_info.platform:
                compatibility["compatible"] = False
                compatibility["errors"].append(
                    f"Platform mismatch: backup is for {backup_data.os_info.platform.value}, "
                    f"current system is {current_os_info.platform.value}"
                )
            
            # Check version compatibility (warnings for different versions)
            if backup_data.os_info.version != current_os_info.version:
                compatibility["warnings"].append(
                    f"Version difference: backup is for {backup_data.os_info.version}, "
                    f"current system is {current_os_info.version}"
                )
            
            # Check architecture compatibility
            if backup_data.os_info.architecture != current_os_info.architecture:
                compatibility["warnings"].append(
                    f"Architecture difference: backup is for {backup_data.os_info.architecture.value}, "
                    f"current system is {current_os_info.architecture.value}"
                )
            
            return compatibility
            
        except BackupError:
            raise
        except Exception as e:
            raise BackupError(f"Failed to validate rollback compatibility: {str(e)}", "COMPATIBILITY_CHECK_ERROR")