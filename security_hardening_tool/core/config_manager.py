"""Configuration management and parameter validation."""

import json
import re
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .interfaces import ConfigurationManager as ConfigurationManagerInterface
from .models import (
    HardeningLevel, Parameter, Platform, Severity, ValidationResult, ValidationRule
)


class ConfigurationManager(ConfigurationManagerInterface):
    """Manages hardening configurations and parameter validation."""
    
    def __init__(self, config_dir: Optional[Path] = None):
        """Initialize configuration manager."""
        if config_dir is None:
            config_dir = Path(__file__).parent.parent / "config"
        
        self.config_dir = Path(config_dir)
        self._parameter_cache: Dict[str, List[Parameter]] = {}
        self._validation_cache: Dict[str, List[ValidationResult]] = {}
    
    def load_hardening_level(self, level: HardeningLevel, 
                           platform: Optional[Platform] = None) -> List[Parameter]:
        """Load parameters for specified hardening level."""
        cache_key = f"{level.value}_{platform.value if platform else 'all'}"
        
        if cache_key in self._parameter_cache:
            return self._parameter_cache[cache_key].copy()
        
        parameters = []
        
        # Load base parameters for the level
        base_config_file = self.config_dir / f"{level.value}_parameters.yaml"
        if base_config_file.exists():
            parameters.extend(self._load_parameters_from_file(base_config_file))
        
        # Load platform-specific parameters if specified
        if platform:
            platform_config_file = self.config_dir / f"{platform.value}_{level.value}_parameters.yaml"
            if platform_config_file.exists():
                platform_params = self._load_parameters_from_file(platform_config_file)
                parameters.extend(platform_params)
        
        # Cache the results
        self._parameter_cache[cache_key] = parameters.copy()
        
        return parameters
    
    def validate_parameters(self, parameters: List[Parameter]) -> List[ValidationResult]:
        """Validate parameter configurations."""
        results = []
        
        for param in parameters:
            result = self._validate_single_parameter(param)
            results.append(result)
        
        return results
    
    def merge_custom_parameters(self, base_params: List[Parameter], 
                              custom_params: Dict[str, Any]) -> List[Parameter]:
        """Merge custom parameter overrides with base configuration."""
        # Create a dictionary for quick lookup
        param_dict = {param.id: param for param in base_params}
        
        # Apply custom overrides
        for param_id, custom_value in custom_params.items():
            if param_id in param_dict:
                # Update existing parameter
                param_dict[param_id].target_value = custom_value
            else:
                # Create new custom parameter
                custom_param = Parameter(
                    id=param_id,
                    name=f"Custom: {param_id}",
                    category="custom",
                    description=f"Custom parameter: {param_id}",
                    target_value=custom_value,
                    severity=Severity.MEDIUM
                )
                param_dict[param_id] = custom_param
        
        return list(param_dict.values())
    
    def get_parameter_by_id(self, parameter_id: str, 
                          level: Optional[HardeningLevel] = None) -> Optional[Parameter]:
        """Get specific parameter by ID."""
        if level:
            parameters = self.load_hardening_level(level)
            for param in parameters:
                if param.id == parameter_id:
                    return param
        
        # Search in all levels if not found
        for hardening_level in HardeningLevel:
            parameters = self.load_hardening_level(hardening_level)
            for param in parameters:
                if param.id == parameter_id:
                    return param
        
        return None
    
    def get_parameters_by_category(self, category: str, 
                                 level: Optional[HardeningLevel] = None) -> List[Parameter]:
        """Get parameters by category."""
        if level:
            parameters = self.load_hardening_level(level)
        else:
            # Get all parameters from all levels
            parameters = []
            for hardening_level in HardeningLevel:
                parameters.extend(self.load_hardening_level(hardening_level))
        
        return [param for param in parameters if param.category == category]
    
    def get_parameters_by_severity(self, severity: Severity, 
                                 level: Optional[HardeningLevel] = None) -> List[Parameter]:
        """Get parameters by severity level."""
        if level:
            parameters = self.load_hardening_level(level)
        else:
            # Get all parameters from all levels
            parameters = []
            for hardening_level in HardeningLevel:
                parameters.extend(self.load_hardening_level(hardening_level))
        
        return [param for param in parameters if param.severity == severity]
    
    def _load_parameters_from_file(self, config_file: Path) -> List[Parameter]:
        """Load parameters from configuration file."""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                if config_file.suffix.lower() == '.yaml' or config_file.suffix.lower() == '.yml':
                    config_data = yaml.safe_load(f)
                elif config_file.suffix.lower() == '.json':
                    config_data = json.load(f)
                else:
                    raise ValueError(f"Unsupported config file format: {config_file.suffix}")
            
            parameters = []
            
            for param_data in config_data.get('parameters', []):
                # Create validation rules
                validation_rules = []
                for rule_data in param_data.get('validation_rules', []):
                    rule = ValidationRule(
                        rule_type=rule_data['rule_type'],
                        rule_value=rule_data['rule_value'],
                        error_message=rule_data.get('error_message', 'Validation failed')
                    )
                    validation_rules.append(rule)
                
                # Create parameter
                parameter = Parameter(
                    id=param_data['id'],
                    name=param_data['name'],
                    category=param_data['category'],
                    description=param_data['description'],
                    target_value=param_data.get('target_value'),
                    severity=Severity(param_data.get('severity', 'medium')),
                    compliance_frameworks=param_data.get('compliance_frameworks', []),
                    validation_rules=validation_rules,
                    backup_required=param_data.get('backup_required', True),
                    platform_specific=param_data.get('platform_specific', False),
                    requires_reboot=param_data.get('requires_reboot', False)
                )
                
                parameters.append(parameter)
            
            return parameters
            
        except Exception as e:
            raise ValueError(f"Failed to load configuration from {config_file}: {str(e)}")
    
    def _validate_single_parameter(self, parameter: Parameter) -> ValidationResult:
        """Validate a single parameter."""
        errors = []
        warnings = []
        
        # Check if parameter has a target value
        if parameter.target_value is None:
            errors.append(f"Parameter {parameter.id} has no target value")
        
        # Apply validation rules
        for rule in parameter.validation_rules:
            try:
                if not self._apply_validation_rule(parameter.target_value, rule):
                    errors.append(rule.error_message)
            except Exception as e:
                errors.append(f"Validation rule error for {parameter.id}: {str(e)}")
        
        # Check for common issues
        if parameter.requires_reboot:
            warnings.append(f"Parameter {parameter.id} requires system reboot")
        
        return ValidationResult(
            parameter_id=parameter.id,
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )
    
    def _apply_validation_rule(self, value: Any, rule: ValidationRule) -> bool:
        """Apply a single validation rule to a value."""
        if value is None:
            return rule.rule_type == "optional"
        
        if rule.rule_type == "range":
            if isinstance(rule.rule_value, dict):
                min_val = rule.rule_value.get('min')
                max_val = rule.rule_value.get('max')
                
                if min_val is not None and value < min_val:
                    return False
                if max_val is not None and value > max_val:
                    return False
                
                return True
            
        elif rule.rule_type == "enum":
            if isinstance(rule.rule_value, list):
                return value in rule.rule_value
            
        elif rule.rule_type == "regex":
            if isinstance(value, str) and isinstance(rule.rule_value, str):
                pattern = re.compile(rule.rule_value)
                return bool(pattern.match(value))
            
        elif rule.rule_type == "type":
            expected_type = rule.rule_value
            if expected_type == "string":
                return isinstance(value, str)
            elif expected_type == "integer":
                return isinstance(value, int)
            elif expected_type == "boolean":
                return isinstance(value, bool)
            elif expected_type == "float":
                return isinstance(value, (int, float))
            
        elif rule.rule_type == "length":
            if isinstance(rule.rule_value, dict):
                min_len = rule.rule_value.get('min', 0)
                max_len = rule.rule_value.get('max', float('inf'))
                
                if hasattr(value, '__len__'):
                    length = len(value)
                    return min_len <= length <= max_len
            
        elif rule.rule_type == "custom":
            # Custom validation logic can be implemented here
            # For now, assume custom rules always pass
            return True
        
        elif rule.rule_type == "optional":
            # Optional parameters always pass validation
            return True
        
        # Unknown rule type - assume it passes
        return True
    
    def create_default_config_files(self) -> None:
        """Create default configuration files if they don't exist."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Create basic level configuration
        basic_config = {
            "parameters": [
                {
                    "id": "password_min_length",
                    "name": "Minimum Password Length",
                    "category": "authentication",
                    "description": "Minimum required password length",
                    "target_value": 12,
                    "severity": "high",
                    "compliance_frameworks": ["CIS", "NIST"],
                    "validation_rules": [
                        {
                            "rule_type": "range",
                            "rule_value": {"min": 8, "max": 128},
                            "error_message": "Password length must be between 8 and 128 characters"
                        }
                    ],
                    "backup_required": True,
                    "requires_reboot": False
                }
            ]
        }
        
        basic_config_file = self.config_dir / "basic_parameters.yaml"
        if not basic_config_file.exists():
            with open(basic_config_file, 'w', encoding='utf-8') as f:
                yaml.dump(basic_config, f, default_flow_style=False)
        
        # Create moderate and strict configurations (similar structure)
        for level in ["moderate", "strict"]:
            config_file = self.config_dir / f"{level}_parameters.yaml"
            if not config_file.exists():
                with open(config_file, 'w', encoding='utf-8') as f:
                    yaml.dump({"parameters": []}, f, default_flow_style=False)
    
    def export_configuration(self, parameters: List[Parameter], 
                           output_file: Path, format: str = "yaml") -> None:
        """Export parameters to configuration file."""
        config_data = {"parameters": []}
        
        for param in parameters:
            param_data = {
                "id": param.id,
                "name": param.name,
                "category": param.category,
                "description": param.description,
                "target_value": param.target_value,
                "severity": param.severity.value,
                "compliance_frameworks": param.compliance_frameworks,
                "validation_rules": [
                    {
                        "rule_type": rule.rule_type,
                        "rule_value": rule.rule_value,
                        "error_message": rule.error_message
                    }
                    for rule in param.validation_rules
                ],
                "backup_required": param.backup_required,
                "platform_specific": param.platform_specific,
                "requires_reboot": param.requires_reboot
            }
            config_data["parameters"].append(param_data)
        
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            if format.lower() == "yaml":
                yaml.dump(config_data, f, default_flow_style=False)
            elif format.lower() == "json":
                json.dump(config_data, f, indent=2)
            else:
                raise ValueError(f"Unsupported export format: {format}")
    
    def import_configuration(self, config_file: Path) -> List[Parameter]:
        """Import parameters from configuration file."""
        return self._load_parameters_from_file(config_file)