"""Compliance framework mappings and utilities."""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

from .models import AssessmentResult, Severity


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""
    CIS = "CIS"
    NIST = "NIST"
    ISO27001 = "ISO27001"
    PCI_DSS = "PCI_DSS"
    SOX = "SOX"


@dataclass
class FrameworkControl:
    """Represents a control within a compliance framework."""
    control_id: str
    title: str
    description: str
    category: str
    severity: Severity
    parameter_mappings: List[str]  # List of parameter IDs that map to this control


@dataclass
class ComplianceGap:
    """Represents a compliance gap for a specific control."""
    control_id: str
    control_title: str
    current_compliance: float  # Percentage (0-100)
    missing_parameters: List[str]
    recommendations: List[str]
    priority: Severity


class ComplianceFrameworkMapper:
    """Maps security parameters to compliance framework controls."""
    
    def __init__(self):
        """Initialize the compliance framework mapper."""
        self.frameworks = self._initialize_frameworks()
    
    def _initialize_frameworks(self) -> Dict[ComplianceFramework, Dict[str, FrameworkControl]]:
        """Initialize all supported compliance frameworks."""
        return {
            ComplianceFramework.CIS: self._initialize_cis_controls(),
            ComplianceFramework.NIST: self._initialize_nist_controls(),
            ComplianceFramework.ISO27001: self._initialize_iso27001_controls(),
            ComplianceFramework.PCI_DSS: self._initialize_pci_dss_controls(),
            ComplianceFramework.SOX: self._initialize_sox_controls(),
        }
    
    def _initialize_cis_controls(self) -> Dict[str, FrameworkControl]:
        """Initialize CIS Benchmark controls."""
        return {
            "CIS-1.1": FrameworkControl(
                control_id="CIS-1.1",
                title="Inventory and Control of Hardware Assets",
                description="Actively manage all hardware devices on the network",
                category="Asset Management",
                severity=Severity.HIGH,
                parameter_mappings=["system_inventory", "hardware_audit"]
            ),
            "CIS-2.1": FrameworkControl(
                control_id="CIS-2.1",
                title="Inventory and Control of Software Assets",
                description="Actively manage all software on the network",
                category="Asset Management",
                severity=Severity.HIGH,
                parameter_mappings=["software_inventory", "unauthorized_software"]
            ),
            "CIS-3.1": FrameworkControl(
                control_id="CIS-3.1",
                title="Continuous Vulnerability Management",
                description="Continuously acquire, assess, and take action on new information",
                category="Vulnerability Management",
                severity=Severity.CRITICAL,
                parameter_mappings=["vulnerability_scanning", "patch_management"]
            ),
            "CIS-4.1": FrameworkControl(
                control_id="CIS-4.1",
                title="Controlled Use of Administrative Privileges",
                description="Control and monitor accounts with administrative privileges",
                category="Access Control",
                severity=Severity.CRITICAL,
                parameter_mappings=["admin_accounts", "privilege_escalation", "uac_settings"]
            ),
            "CIS-5.1": FrameworkControl(
                control_id="CIS-5.1",
                title="Secure Configuration for Hardware and Software",
                description="Establish and maintain secure configurations",
                category="Configuration Management",
                severity=Severity.HIGH,
                parameter_mappings=[
                    "password_policy", "account_lockout", "security_options",
                    "firewall_settings", "audit_policies", "service_hardening"
                ]
            ),
            "CIS-6.1": FrameworkControl(
                control_id="CIS-6.1",
                title="Maintenance, Monitoring, and Analysis of Audit Logs",
                description="Collect, manage, and analyze audit logs",
                category="Logging and Monitoring",
                severity=Severity.HIGH,
                parameter_mappings=["audit_logging", "log_retention", "log_monitoring"]
            ),
        }
    
    def _initialize_nist_controls(self) -> Dict[str, FrameworkControl]:
        """Initialize NIST Cybersecurity Framework controls."""
        return {
            "AC-2": FrameworkControl(
                control_id="AC-2",
                title="Account Management",
                description="Manage information system accounts",
                category="Access Control",
                severity=Severity.HIGH,
                parameter_mappings=["account_management", "user_accounts", "admin_accounts"]
            ),
            "AC-3": FrameworkControl(
                control_id="AC-3",
                title="Access Enforcement",
                description="Enforce approved authorizations for logical access",
                category="Access Control",
                severity=Severity.HIGH,
                parameter_mappings=["access_control", "user_rights", "privilege_escalation"]
            ),
            "AC-6": FrameworkControl(
                control_id="AC-6",
                title="Least Privilege",
                description="Employ the principle of least privilege",
                category="Access Control",
                severity=Severity.CRITICAL,
                parameter_mappings=["least_privilege", "admin_accounts", "service_accounts"]
            ),
            "AC-7": FrameworkControl(
                control_id="AC-7",
                title="Unsuccessful Logon Attempts",
                description="Enforce a limit on consecutive invalid logon attempts",
                category="Access Control",
                severity=Severity.MEDIUM,
                parameter_mappings=["account_lockout", "lockout_threshold", "lockout_duration"]
            ),
            "AU-2": FrameworkControl(
                control_id="AU-2",
                title="Audit Events",
                description="Determine auditable events and audit within the system",
                category="Audit and Accountability",
                severity=Severity.HIGH,
                parameter_mappings=["audit_events", "audit_policies", "system_auditing"]
            ),
            "AU-3": FrameworkControl(
                control_id="AU-3",
                title="Content of Audit Records",
                description="Generate audit records with specific content",
                category="Audit and Accountability",
                severity=Severity.MEDIUM,
                parameter_mappings=["audit_content", "audit_detail", "log_format"]
            ),
            "CM-2": FrameworkControl(
                control_id="CM-2",
                title="Baseline Configuration",
                description="Develop and maintain baseline configurations",
                category="Configuration Management",
                severity=Severity.HIGH,
                parameter_mappings=["baseline_config", "system_hardening", "security_baseline"]
            ),
            "CM-6": FrameworkControl(
                control_id="CM-6",
                title="Configuration Settings",
                description="Establish and document configuration settings",
                category="Configuration Management",
                severity=Severity.MEDIUM,
                parameter_mappings=["config_settings", "security_options", "system_settings"]
            ),
            "CM-7": FrameworkControl(
                control_id="CM-7",
                title="Least Functionality",
                description="Configure systems to provide only essential capabilities",
                category="Configuration Management",
                severity=Severity.HIGH,
                parameter_mappings=["service_hardening", "unnecessary_services", "feature_disabling"]
            ),
            "IA-2": FrameworkControl(
                control_id="IA-2",
                title="Identification and Authentication",
                description="Uniquely identify and authenticate organizational users",
                category="Identification and Authentication",
                severity=Severity.HIGH,
                parameter_mappings=["authentication", "user_identification", "login_security"]
            ),
            "IA-5": FrameworkControl(
                control_id="IA-5",
                title="Authenticator Management",
                description="Manage information system authenticators",
                category="Identification and Authentication",
                severity=Severity.HIGH,
                parameter_mappings=["password_policy", "password_complexity", "password_history"]
            ),
            "SC-7": FrameworkControl(
                control_id="SC-7",
                title="Boundary Protection",
                description="Monitor and control communications at external boundaries",
                category="System and Communications Protection",
                severity=Severity.HIGH,
                parameter_mappings=["firewall_settings", "network_security", "boundary_protection"]
            ),
        }
    
    def _initialize_iso27001_controls(self) -> Dict[str, FrameworkControl]:
        """Initialize ISO 27001 controls."""
        return {
            "A.9.1.1": FrameworkControl(
                control_id="A.9.1.1",
                title="Access control policy",
                description="An access control policy shall be established",
                category="Access Control",
                severity=Severity.HIGH,
                parameter_mappings=["access_policy", "access_control", "user_access"]
            ),
            "A.9.1.2": FrameworkControl(
                control_id="A.9.1.2",
                title="Access to networks and network services",
                description="Users shall only be provided with access to networks and network services",
                category="Access Control",
                severity=Severity.HIGH,
                parameter_mappings=["network_access", "service_access", "remote_access"]
            ),
            "A.9.2.1": FrameworkControl(
                control_id="A.9.2.1",
                title="User registration and de-registration",
                description="A formal user registration and de-registration process",
                category="Access Control",
                severity=Severity.MEDIUM,
                parameter_mappings=["user_registration", "account_management", "user_lifecycle"]
            ),
            "A.9.2.2": FrameworkControl(
                control_id="A.9.2.2",
                title="User access provisioning",
                description="A formal user access provisioning process",
                category="Access Control",
                severity=Severity.MEDIUM,
                parameter_mappings=["access_provisioning", "user_permissions", "role_assignment"]
            ),
            "A.9.4.2": FrameworkControl(
                control_id="A.9.4.2",
                title="Secure log-on procedures",
                description="Where required by the access control policy",
                category="Access Control",
                severity=Severity.MEDIUM,
                parameter_mappings=["login_procedures", "authentication", "secure_logon"]
            ),
            "A.10.1.1": FrameworkControl(
                control_id="A.10.1.1",
                title="Policy on the use of cryptographic controls",
                description="A policy on the use of cryptographic controls",
                category="Cryptography",
                severity=Severity.HIGH,
                parameter_mappings=["encryption_policy", "cryptographic_controls", "data_encryption"]
            ),
            "A.12.1.1": FrameworkControl(
                control_id="A.12.1.1",
                title="Documented operating procedures",
                description="Operating procedures shall be documented and made available",
                category="Operations Security",
                severity=Severity.MEDIUM,
                parameter_mappings=["operating_procedures", "documentation", "process_documentation"]
            ),
            "A.12.2.1": FrameworkControl(
                control_id="A.12.2.1",
                title="Controls against malware",
                description="Detection, prevention and recovery controls to protect against malware",
                category="Operations Security",
                severity=Severity.HIGH,
                parameter_mappings=["antimalware", "malware_protection", "endpoint_protection"]
            ),
            "A.12.6.1": FrameworkControl(
                control_id="A.12.6.1",
                title="Management of technical vulnerabilities",
                description="Information about technical vulnerabilities",
                category="Operations Security",
                severity=Severity.HIGH,
                parameter_mappings=["vulnerability_management", "patch_management", "security_updates"]
            ),
        }
    
    def _initialize_pci_dss_controls(self) -> Dict[str, FrameworkControl]:
        """Initialize PCI DSS controls."""
        return {
            "PCI-1.1": FrameworkControl(
                control_id="PCI-1.1",
                title="Firewall Configuration Standards",
                description="Establish and implement firewall and router configuration standards",
                category="Network Security",
                severity=Severity.CRITICAL,
                parameter_mappings=["firewall_config", "network_security", "firewall_rules"]
            ),
            "PCI-2.1": FrameworkControl(
                control_id="PCI-2.1",
                title="Default Passwords and Security Parameters",
                description="Always change vendor-supplied defaults and remove or disable unnecessary default accounts",
                category="Secure Configuration",
                severity=Severity.CRITICAL,
                parameter_mappings=["default_passwords", "default_accounts", "vendor_defaults"]
            ),
            "PCI-7.1": FrameworkControl(
                control_id="PCI-7.1",
                title="Limit Access to System Components",
                description="Limit access to system components and cardholder data by business need-to-know",
                category="Access Control",
                severity=Severity.HIGH,
                parameter_mappings=["access_restriction", "need_to_know", "data_access"]
            ),
            "PCI-8.1": FrameworkControl(
                control_id="PCI-8.1",
                title="User Identification and Authentication",
                description="Define and implement policies and procedures to ensure proper user identification",
                category="Identity Management",
                severity=Severity.HIGH,
                parameter_mappings=["user_identification", "authentication_policy", "identity_management"]
            ),
        }
    
    def _initialize_sox_controls(self) -> Dict[str, FrameworkControl]:
        """Initialize SOX controls."""
        return {
            "SOX-302": FrameworkControl(
                control_id="SOX-302",
                title="Corporate Responsibility for Financial Reports",
                description="Corporate responsibility for financial reports and controls",
                category="Financial Reporting",
                severity=Severity.HIGH,
                parameter_mappings=["financial_controls", "audit_logging", "access_controls"]
            ),
            "SOX-404": FrameworkControl(
                control_id="SOX-404",
                title="Management Assessment of Internal Controls",
                description="Management assessment of internal controls over financial reporting",
                category="Internal Controls",
                severity=Severity.HIGH,
                parameter_mappings=["internal_controls", "financial_systems", "control_assessment"]
            ),
        } 
   
    def get_framework_controls(self, framework: ComplianceFramework) -> Dict[str, FrameworkControl]:
        """Get all controls for a specific framework."""
        return self.frameworks.get(framework, {})
    
    def map_parameter_to_controls(self, parameter_id: str, framework: ComplianceFramework) -> List[FrameworkControl]:
        """Map a parameter ID to relevant framework controls."""
        controls = []
        framework_controls = self.get_framework_controls(framework)
        
        for control in framework_controls.values():
            if parameter_id in control.parameter_mappings:
                controls.append(control)
        
        return controls
    
    def calculate_framework_compliance(self, results: List[AssessmentResult], 
                                     framework: ComplianceFramework) -> Dict[str, Any]:
        """Calculate compliance percentage for a specific framework."""
        framework_controls = self.get_framework_controls(framework)
        
        if not framework_controls:
            return {"compliance_percentage": 0, "total_controls": 0, "compliant_controls": 0}
        
        # Map results to controls
        control_compliance = {}
        for control_id, control in framework_controls.items():
            control_compliance[control_id] = {
                "control": control,
                "total_parameters": len(control.parameter_mappings),
                "compliant_parameters": 0,
                "assessed_parameters": 0
            }
        
        # Check compliance for each result
        for result in results:
            for control_id, control in framework_controls.items():
                if result.parameter_id in control.parameter_mappings:
                    control_compliance[control_id]["assessed_parameters"] += 1
                    if result.compliant:
                        control_compliance[control_id]["compliant_parameters"] += 1
        
        # Calculate overall compliance
        total_controls = len(framework_controls)
        compliant_controls = 0
        
        for control_id, compliance_data in control_compliance.items():
            if compliance_data["assessed_parameters"] > 0:
                control_compliance_rate = (
                    compliance_data["compliant_parameters"] / 
                    compliance_data["assessed_parameters"]
                )
                # Consider control compliant if 80% or more of its parameters are compliant
                if control_compliance_rate >= 0.8:
                    compliant_controls += 1
        
        compliance_percentage = (compliant_controls / total_controls * 100) if total_controls > 0 else 0
        
        return {
            "compliance_percentage": compliance_percentage,
            "total_controls": total_controls,
            "compliant_controls": compliant_controls,
            "control_details": control_compliance
        }
    
    def identify_compliance_gaps(self, results: List[AssessmentResult], 
                               framework: ComplianceFramework) -> List[ComplianceGap]:
        """Identify compliance gaps for a specific framework."""
        gaps = []
        framework_controls = self.get_framework_controls(framework)
        
        for control_id, control in framework_controls.items():
            # Find results for this control
            control_results = [
                r for r in results 
                if r.parameter_id in control.parameter_mappings
            ]
            
            if not control_results:
                # No assessment data for this control
                gaps.append(ComplianceGap(
                    control_id=control_id,
                    control_title=control.title,
                    current_compliance=0.0,
                    missing_parameters=control.parameter_mappings,
                    recommendations=[f"Assess and implement {control.title}"],
                    priority=control.severity
                ))
                continue
            
            # Calculate compliance for this control
            total_params = len(control_results)
            compliant_params = len([r for r in control_results if r.compliant])
            compliance_rate = (compliant_params / total_params * 100) if total_params > 0 else 0
            
            if compliance_rate < 100:
                non_compliant_params = [r.parameter_id for r in control_results if not r.compliant]
                recommendations = []
                
                for result in control_results:
                    if not result.compliant and result.remediation_steps:
                        recommendations.extend(result.remediation_steps)
                
                gaps.append(ComplianceGap(
                    control_id=control_id,
                    control_title=control.title,
                    current_compliance=compliance_rate,
                    missing_parameters=non_compliant_params,
                    recommendations=recommendations or [f"Review and remediate {control.title}"],
                    priority=control.severity
                ))
        
        # Sort gaps by priority (severity)
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
        gaps.sort(key=lambda x: severity_order.get(x.priority, 4))
        
        return gaps
    
    def get_supported_frameworks(self) -> List[ComplianceFramework]:
        """Get list of all supported compliance frameworks."""
        return list(self.frameworks.keys())
    
    def get_framework_categories(self, framework: ComplianceFramework) -> List[str]:
        """Get all categories for a specific framework."""
        framework_controls = self.get_framework_controls(framework)
        categories = set()
        
        for control in framework_controls.values():
            categories.add(control.category)
        
        return sorted(list(categories))
    
    def get_controls_by_category(self, framework: ComplianceFramework, 
                               category: str) -> List[FrameworkControl]:
        """Get all controls in a specific category for a framework."""
        framework_controls = self.get_framework_controls(framework)
        return [
            control for control in framework_controls.values() 
            if control.category == category
        ]
    
    def generate_compliance_matrix(self, results: List[AssessmentResult], 
                                 framework: ComplianceFramework) -> Dict[str, Any]:
        """Generate a compliance matrix showing parameter to control mappings."""
        framework_controls = self.get_framework_controls(framework)
        matrix = {}
        
        # Create parameter to controls mapping
        for result in results:
            mapped_controls = []
            for control_id, control in framework_controls.items():
                if result.parameter_id in control.parameter_mappings:
                    mapped_controls.append({
                        "control_id": control_id,
                        "control_title": control.title,
                        "category": control.category,
                        "severity": control.severity.value
                    })
            
            matrix[result.parameter_id] = {
                "parameter_id": result.parameter_id,
                "compliant": result.compliant,
                "severity": result.severity.value,
                "mapped_controls": mapped_controls
            }
        
        return matrix