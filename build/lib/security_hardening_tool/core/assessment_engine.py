"""Security assessment engine for evaluating system compliance."""

import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from .interfaces import ConfigurationManager, HardeningModule, Logger
from .models import (
    AssessmentResult, HardeningLevel, OperationResult, Parameter, 
    Severity, ValidationResult, HardeningError
)


class AssessmentEngine:
    """Engine for performing comprehensive security assessments."""
    
    def __init__(self, config_manager: ConfigurationManager, logger: Logger):
        """Initialize the assessment engine."""
        self.config_manager = config_manager
        self.logger = logger
        self._severity_weights = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0
        }
    
    def assess_system_state(self, hardening_module: HardeningModule, 
                           hardening_level: HardeningLevel,
                           custom_parameters: Optional[Dict[str, any]] = None) -> List[AssessmentResult]:
        """
        Perform comprehensive assessment of current system state.
        
        Args:
            hardening_module: Platform-specific hardening module
            hardening_level: Target hardening level for comparison
            custom_parameters: Optional custom parameter overrides
            
        Returns:
            List of assessment results with compliance status and severity
        """
        try:
            self.logger.log_operation("assessment_started", {
                "hardening_level": hardening_level.value,
                "has_custom_params": custom_parameters is not None
            })
            
            # Load target parameters for the hardening level
            target_parameters = self.config_manager.load_hardening_level(hardening_level)
            
            # Merge custom parameters if provided
            if custom_parameters:
                target_parameters = self.config_manager.merge_custom_parameters(
                    target_parameters, custom_parameters
                )
            
            # Validate parameters before assessment
            validation_results = self.config_manager.validate_parameters(target_parameters)
            invalid_params = [r for r in validation_results if not r.valid]
            
            if invalid_params:
                error_msg = f"Invalid target parameters: {[r.parameter_id for r in invalid_params]}"
                self.logger.log_error(Exception(error_msg), {"invalid_params": invalid_params})
                raise HardeningError(error_msg, "INVALID_PARAMETERS")
            
            # Perform assessment using hardening module
            assessment_results = hardening_module.assess_current_state(target_parameters)
            
            # Enhance results with additional analysis
            enhanced_results = self._enhance_assessment_results(assessment_results, target_parameters)
            
            # Log assessment completion
            compliance_stats = self._calculate_compliance_statistics(enhanced_results)
            self.logger.log_operation("assessment_completed", {
                "total_parameters": len(enhanced_results),
                "compliant_count": compliance_stats["compliant_count"],
                "non_compliant_count": compliance_stats["non_compliant_count"],
                "compliance_percentage": compliance_stats["compliance_percentage"],
                "severity_breakdown": compliance_stats["severity_breakdown"]
            })
            
            return enhanced_results
            
        except Exception as e:
            self.logger.log_error(e, {"operation": "assess_system_state"})
            raise
    
    def assess_specific_parameters(self, hardening_module: HardeningModule,
                                 parameters: List[Parameter]) -> List[AssessmentResult]:
        """
        Assess specific parameters against their target values.
        
        Args:
            hardening_module: Platform-specific hardening module
            parameters: List of parameters to assess
            
        Returns:
            List of assessment results for specified parameters
        """
        try:
            self.logger.log_operation("specific_assessment_started", {
                "parameter_count": len(parameters),
                "parameter_ids": [p.id for p in parameters]
            })
            
            # Validate parameters
            validation_results = self.config_manager.validate_parameters(parameters)
            invalid_params = [r for r in validation_results if not r.valid]
            
            if invalid_params:
                self.logger.log_operation("validation_warnings", {
                    "invalid_params": [r.parameter_id for r in invalid_params]
                })
            
            # Filter out invalid parameters for assessment
            valid_parameters = [p for p in parameters 
                              if p.id not in [r.parameter_id for r in invalid_params]]
            
            # Perform assessment
            assessment_results = hardening_module.assess_current_state(valid_parameters)
            
            # Enhance results
            enhanced_results = self._enhance_assessment_results(assessment_results, valid_parameters)
            
            self.logger.log_operation("specific_assessment_completed", {
                "assessed_parameters": len(enhanced_results)
            })
            
            return enhanced_results
            
        except Exception as e:
            self.logger.log_error(e, {"operation": "assess_specific_parameters"})
            raise
    
    def compare_with_baseline(self, current_results: List[AssessmentResult],
                            baseline_results: List[AssessmentResult]) -> Dict[str, any]:
        """
        Compare current assessment results with a baseline.
        
        Args:
            current_results: Current assessment results
            baseline_results: Baseline assessment results for comparison
            
        Returns:
            Dictionary containing comparison analysis
        """
        try:
            # Create lookup dictionaries
            current_lookup = {r.parameter_id: r for r in current_results}
            baseline_lookup = {r.parameter_id: r for r in baseline_results}
            
            # Find common parameters
            common_params = set(current_lookup.keys()) & set(baseline_lookup.keys())
            
            # Analyze changes
            improvements = []
            regressions = []
            unchanged = []
            
            for param_id in common_params:
                current = current_lookup[param_id]
                baseline = baseline_lookup[param_id]
                
                if current.compliant and not baseline.compliant:
                    improvements.append({
                        "parameter_id": param_id,
                        "severity": current.severity.value,
                        "description": f"Parameter now compliant: {current.current_value}"
                    })
                elif not current.compliant and baseline.compliant:
                    regressions.append({
                        "parameter_id": param_id,
                        "severity": current.severity.value,
                        "description": f"Parameter no longer compliant: {current.current_value}"
                    })
                else:
                    unchanged.append(param_id)
            
            # Calculate overall compliance change
            current_compliance = len([r for r in current_results if r.compliant]) / len(current_results) * 100
            baseline_compliance = len([r for r in baseline_results if r.compliant]) / len(baseline_results) * 100
            compliance_change = current_compliance - baseline_compliance
            
            comparison_result = {
                "baseline_date": min([r.timestamp for r in baseline_results]) if baseline_results else None,
                "current_date": min([r.timestamp for r in current_results]) if current_results else None,
                "total_parameters": len(common_params),
                "improvements": improvements,
                "regressions": regressions,
                "unchanged_count": len(unchanged),
                "compliance_change_percentage": round(compliance_change, 2),
                "current_compliance_percentage": round(current_compliance, 2),
                "baseline_compliance_percentage": round(baseline_compliance, 2)
            }
            
            self.logger.log_operation("baseline_comparison_completed", comparison_result)
            
            return comparison_result
            
        except Exception as e:
            self.logger.log_error(e, {"operation": "compare_with_baseline"})
            raise
    
    def _enhance_assessment_results(self, results: List[AssessmentResult], 
                                  parameters: List[Parameter]) -> List[AssessmentResult]:
        """
        Enhance assessment results with additional analysis and categorization.
        
        Args:
            results: Raw assessment results from hardening module
            parameters: Original parameter definitions
            
        Returns:
            Enhanced assessment results with improved categorization
        """
        parameter_lookup = {p.id: p for p in parameters}
        enhanced_results = []
        
        for result in results:
            # Get original parameter definition
            param = parameter_lookup.get(result.parameter_id)
            if not param:
                continue
            
            # Enhance severity based on compliance frameworks and risk
            enhanced_severity = self._calculate_enhanced_severity(result, param)
            
            # Generate detailed risk description
            risk_description = self._generate_risk_description(result, param)
            
            # Generate remediation steps
            remediation_steps = self._generate_remediation_steps(result, param)
            
            # Create enhanced result
            enhanced_result = AssessmentResult(
                parameter_id=result.parameter_id,
                current_value=result.current_value,
                expected_value=result.expected_value,
                compliant=result.compliant,
                severity=enhanced_severity,
                risk_description=risk_description,
                remediation_steps=remediation_steps,
                timestamp=result.timestamp
            )
            
            enhanced_results.append(enhanced_result)
        
        return enhanced_results
    
    def _calculate_enhanced_severity(self, result: AssessmentResult, 
                                   parameter: Parameter) -> Severity:
        """
        Calculate enhanced severity based on multiple factors.
        
        Args:
            result: Assessment result
            parameter: Parameter definition
            
        Returns:
            Enhanced severity level
        """
        base_severity = parameter.severity
        
        # Increase severity for non-compliant critical security controls
        if not result.compliant:
            # Check if parameter is in critical compliance frameworks
            critical_frameworks = ["CIS", "NIST", "ISO27001"]
            has_critical_framework = any(fw in parameter.compliance_frameworks 
                                       for fw in critical_frameworks)
            
            if has_critical_framework and base_severity == Severity.MEDIUM:
                return Severity.HIGH
            elif has_critical_framework and base_severity == Severity.HIGH:
                return Severity.CRITICAL
        
        return base_severity
    
    def _generate_risk_description(self, result: AssessmentResult, 
                                 parameter: Parameter) -> str:
        """
        Generate detailed risk description for assessment result.
        
        Args:
            result: Assessment result
            parameter: Parameter definition
            
        Returns:
            Detailed risk description
        """
        if result.compliant:
            return f"Parameter '{parameter.name}' is compliant with security requirements."
        
        risk_templates = {
            Severity.CRITICAL: "CRITICAL SECURITY RISK: {desc} Current value '{current}' does not meet security requirements (expected: '{expected}'). This configuration poses immediate security threats.",
            Severity.HIGH: "HIGH SECURITY RISK: {desc} Current value '{current}' deviates from security baseline (expected: '{expected}'). This may expose the system to significant security vulnerabilities.",
            Severity.MEDIUM: "MEDIUM SECURITY RISK: {desc} Current value '{current}' does not align with recommended security settings (expected: '{expected}'). This could potentially be exploited.",
            Severity.LOW: "LOW SECURITY RISK: {desc} Current value '{current}' differs from security recommendations (expected: '{expected}'). Consider updating for improved security posture.",
            Severity.INFO: "INFORMATIONAL: {desc} Current value '{current}' noted for compliance tracking (expected: '{expected}')."
        }
        
        template = risk_templates.get(result.severity, risk_templates[Severity.MEDIUM])
        
        return template.format(
            desc=parameter.description,
            current=result.current_value,
            expected=result.expected_value
        )
    
    def _generate_remediation_steps(self, result: AssessmentResult, 
                                  parameter: Parameter) -> List[str]:
        """
        Generate specific remediation steps for non-compliant parameters.
        
        Args:
            result: Assessment result
            parameter: Parameter definition
            
        Returns:
            List of remediation steps
        """
        if result.compliant:
            return ["No action required - parameter is compliant"]
        
        steps = [
            f"Update '{parameter.name}' from '{result.current_value}' to '{result.expected_value}'",
            f"Verify the change takes effect (may require service restart or reboot)",
            "Test system functionality after applying the change",
            "Document the change in your security configuration management system"
        ]
        
        # Add platform-specific steps based on parameter category
        if "registry" in parameter.category.lower():
            steps.insert(1, "Create registry backup before making changes")
        elif "service" in parameter.category.lower():
            steps.insert(1, "Check service dependencies before modifying service state")
        elif "firewall" in parameter.category.lower():
            steps.insert(1, "Ensure firewall changes don't block critical network access")
        elif "ssh" in parameter.category.lower():
            steps.insert(1, "Test SSH configuration before applying to avoid lockout")
        
        # Add reboot warning if required
        if parameter.requires_reboot:
            steps.append("IMPORTANT: System reboot required for this change to take effect")
        
        return steps
    
    def _calculate_compliance_statistics(self, results: List[AssessmentResult]) -> Dict[str, any]:
        """
        Calculate comprehensive compliance statistics.
        
        Args:
            results: Assessment results
            
        Returns:
            Dictionary containing compliance statistics
        """
        if not results:
            return {
                "compliant_count": 0,
                "non_compliant_count": 0,
                "compliance_percentage": 0.0,
                "severity_breakdown": {}
            }
        
        compliant_count = len([r for r in results if r.compliant])
        non_compliant_count = len(results) - compliant_count
        compliance_percentage = (compliant_count / len(results)) * 100
        
        # Calculate severity breakdown for non-compliant items
        severity_breakdown = {}
        for severity in Severity:
            count = len([r for r in results if not r.compliant and r.severity == severity])
            if count > 0:
                severity_breakdown[severity.value] = count
        
        return {
            "compliant_count": compliant_count,
            "non_compliant_count": non_compliant_count,
            "compliance_percentage": round(compliance_percentage, 2),
            "severity_breakdown": severity_breakdown
        }
    
    def get_assessment_summary(self, results: List[AssessmentResult]) -> Dict[str, any]:
        """
        Generate comprehensive assessment summary.
        
        Args:
            results: Assessment results
            
        Returns:
            Dictionary containing assessment summary
        """
        stats = self._calculate_compliance_statistics(results)
        
        # Calculate risk score based on severity weights
        total_risk_score = sum(
            self._severity_weights[r.severity] for r in results if not r.compliant
        )
        
        # Categorize by parameter categories
        category_breakdown = {}
        for result in results:
            # Extract category from parameter_id (assuming format like "category.parameter")
            category = result.parameter_id.split('.')[0] if '.' in result.parameter_id else "general"
            
            if category not in category_breakdown:
                category_breakdown[category] = {"total": 0, "compliant": 0, "non_compliant": 0}
            
            category_breakdown[category]["total"] += 1
            if result.compliant:
                category_breakdown[category]["compliant"] += 1
            else:
                category_breakdown[category]["non_compliant"] += 1
        
        # Add compliance percentage to each category
        for category_data in category_breakdown.values():
            if category_data["total"] > 0:
                category_data["compliance_percentage"] = round(
                    (category_data["compliant"] / category_data["total"]) * 100, 2
                )
        
        return {
            "assessment_timestamp": datetime.now().isoformat(),
            "total_parameters_assessed": len(results),
            "overall_compliance_percentage": stats["compliance_percentage"],
            "compliant_parameters": stats["compliant_count"],
            "non_compliant_parameters": stats["non_compliant_count"],
            "total_risk_score": total_risk_score,
            "severity_breakdown": stats["severity_breakdown"],
            "category_breakdown": category_breakdown,
            "recommendations": self._generate_summary_recommendations(results)
        }
    
    def _generate_summary_recommendations(self, results: List[AssessmentResult]) -> List[str]:
        """
        Generate high-level recommendations based on assessment results.
        
        Args:
            results: Assessment results
            
        Returns:
            List of summary recommendations
        """
        recommendations = []
        
        # Count issues by severity
        critical_count = len([r for r in results if not r.compliant and r.severity == Severity.CRITICAL])
        high_count = len([r for r in results if not r.compliant and r.severity == Severity.HIGH])
        medium_count = len([r for r in results if not r.compliant and r.severity == Severity.MEDIUM])
        
        if critical_count > 0:
            recommendations.append(f"URGENT: Address {critical_count} critical security issues immediately")
        
        if high_count > 0:
            recommendations.append(f"HIGH PRIORITY: Remediate {high_count} high-severity security gaps")
        
        if medium_count > 0:
            recommendations.append(f"MEDIUM PRIORITY: Review and address {medium_count} medium-severity findings")
        
        # Overall compliance recommendation
        compliance_pct = len([r for r in results if r.compliant]) / len(results) * 100 if results else 0
        
        if compliance_pct < 50:
            recommendations.append("System requires comprehensive security hardening")
        elif compliance_pct < 80:
            recommendations.append("System needs significant security improvements")
        elif compliance_pct < 95:
            recommendations.append("System is mostly secure but has room for improvement")
        else:
            recommendations.append("System demonstrates strong security posture")
        
        return recommendations