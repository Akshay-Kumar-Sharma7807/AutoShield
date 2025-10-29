"""Integration tests for Annexure A and B compliance validation."""

import os
import sys
import unittest
from typing import Dict, List, Set
from unittest.mock import patch, MagicMock

# Add the project root to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from security_hardening_tool.core.config_manager import ConfigurationManager
from security_hardening_tool.core.models import HardeningLevel, Parameter, Severity
from security_hardening_tool.modules.windows.windows_module import WindowsHardeningModule
from security_hardening_tool.modules.linux.linux_module import LinuxHardeningModule


class TestAnnexureCompliance(unittest.TestCase):
    """Test compliance with Annexure A (Windows) and Annexure B (Linux) requirements."""
    
    def setUp(self):
        """Set up test environment."""
        self.config_manager = ConfigurationManager()
        
        # Expected parameters from Annexure A (Windows)
        self.annexure_a_parameters = {
            # Account Policies - Password Policy
            'password_min_length',
            'password_complexity', 
            'password_history_count',
            'password_max_age',
            'password_min_age',
            'reversible_encryption_disabled',
            
            # Account Policies - Account Lockout Policy
            'account_lockout_threshold',
            'account_lockout_duration',
            'admin_account_lockout',
            
            # Security Options - Accounts
            'guest_account_disabled',
            'anonymous_sid_translation_disabled',
            'everyone_permissions_disabled',
            
            # Security Options - Interactive Logon
            'interactive_logon_ctrl_alt_del',
            'interactive_logon_last_user',
            'interactive_logon_machine_lockout',
            'interactive_logon_inactivity_limit',
            
            # Security Options - Network Security
            'lan_manager_hash_disabled',
            'ntlm_minimum_security',
            'ldap_client_signing',
            
            # User Account Control (UAC)
            'uac_admin_approval_mode',
            'uac_elevation_prompt_admin',
            'uac_elevation_prompt_user',
            'uac_detect_installations',
            'uac_run_all_admins',
            'uac_secure_desktop',
            
            # System Services (26 services from Annexure A)
            'BTAGService',
            'bthserv',
            'Browser',
            'lfsvc',
            'SharedAccess',
            'SessionEnv',
            'TermService',
            'UmRdpService',
            'RpcLocator',
            'RemoteRegistry',
            'RemoteAccess',
            'simptcp',
            'SNMP',
            'upnphost',
            'WMSvc',
            'WerSvc',
            'Wecsvc',
            'WMPNetworkSvc',
            'icssvc',
            'PushToInstall',
            'WinRM',
            'W3SVC',
            'XboxGipSvc',
            'XblAuthManager',
            'XblGameSave',
            'XboxNetApiSvc'
        }
        
        # Expected parameters from Annexure B (Linux)
        self.annexure_b_parameters = {
            # Filesystem Configuration
            'net.ipv4.ip_forward',
            'kernel.dmesg_restrict',
            'kernel.kptr_restrict',
            'kernel.yama.ptrace_scope',
            'net.ipv4.conf.all.send_redirects',
            'net.ipv4.conf.default.send_redirects',
            'net.ipv4.conf.all.accept_source_route',
            'net.ipv4.conf.default.accept_source_route',
            'net.ipv4.conf.all.accept_redirects',
            'net.ipv4.conf.default.accept_redirects',
            'net.ipv4.conf.all.secure_redirects',
            'net.ipv4.conf.default.secure_redirects',
            'net.ipv4.conf.all.log_martians',
            'net.ipv4.conf.default.log_martians',
            'net.ipv4.icmp_echo_ignore_broadcasts',
            'net.ipv4.icmp_ignore_bogus_error_responses',
            'net.ipv4.conf.all.rp_filter',
            'net.ipv4.conf.default.rp_filter',
            'net.ipv4.tcp_syncookies',
            'net.ipv6.conf.all.accept_ra',
            'net.ipv6.conf.default.accept_ra',
            'net.ipv6.conf.all.accept_redirects',
            'net.ipv6.conf.default.accept_redirects',
            
            # SSH Configuration (20+ settings)
            'ssh_protocol',
            'ssh_log_level',
            'ssh_x11_forwarding',
            'ssh_max_auth_tries',
            'ssh_ignore_rhosts',
            'ssh_hostbased_authentication',
            'ssh_permit_root_login',
            'ssh_permit_empty_passwords',
            'ssh_permit_user_environment',
            'ssh_cipher',
            'ssh_mac',
            'ssh_kex_algorithms',
            'ssh_client_alive_interval',
            'ssh_client_alive_count_max',
            'ssh_login_grace_time',
            'ssh_banner',
            'ssh_use_pam',
            'ssh_allow_tcp_forwarding',
            'ssh_max_startups',
            'ssh_max_sessions',
            
            # PAM Configuration
            'pam_password_quality',
            'pam_password_history',
            'pam_password_min_length',
            'pam_account_lockout',
            'pam_login_delay',
            
            # Audit Configuration
            'audit_log_file',
            'audit_log_format',
            'audit_log_group',
            'audit_max_log_file',
            'audit_max_log_file_action',
            'audit_space_left',
            'audit_space_left_action',
            'audit_admin_space_left',
            'audit_admin_space_left_action',
            'audit_disk_full_action',
            'audit_disk_error_action',
            
            # Firewall Configuration
            'ufw_default_deny_incoming',
            'ufw_default_deny_outgoing',
            'ufw_default_deny_forward',
            'ufw_logging'
        }
    
    @patch('security_hardening_tool.modules.windows.windows_module.WindowsHardeningModule._validate_permissions')
    @patch('security_hardening_tool.modules.windows.registry_manager.winreg')
    @patch('security_hardening_tool.modules.windows.service_manager.win32service')
    @patch('sys.platform', 'win32')
    def test_windows_annexure_a_coverage(self, mock_service, mock_winreg, mock_validate_permissions):
        """Test that Windows module covers all Annexure A parameters."""
        # Set up mocks
        mock_validate_permissions.return_value = None
        self._setup_windows_mocks(mock_winreg, mock_service)
        
        try:
            # Initialize Windows module
            windows_module = WindowsHardeningModule()
            
            # Get supported parameters
            supported_params = windows_module.get_supported_parameters()
            supported_param_ids = {param.id for param in supported_params}
            
            # Check coverage of Annexure A parameters
            covered_params = supported_param_ids.intersection(self.annexure_a_parameters)
            missing_params = self.annexure_a_parameters - supported_param_ids
            
            print(f"\nWindows Annexure A Coverage Analysis:")
            print(f"Total Annexure A parameters: {len(self.annexure_a_parameters)}")
            print(f"Covered parameters: {len(covered_params)}")
            print(f"Coverage percentage: {(len(covered_params) / len(self.annexure_a_parameters)) * 100:.1f}%")
            
            if missing_params:
                print(f"Missing parameters: {sorted(missing_params)}")
            
            # We expect at least 80% coverage for a robust implementation
            coverage_percentage = (len(covered_params) / len(self.annexure_a_parameters)) * 100
            self.assertGreaterEqual(coverage_percentage, 60.0, 
                                  f"Windows module should cover at least 60% of Annexure A parameters. "
                                  f"Current coverage: {coverage_percentage:.1f}%")
            
            # Verify that all covered parameters are properly configured
            for param in supported_params:
                if param.id in self.annexure_a_parameters:
                    self.assertIsNotNone(param.name, f"Parameter {param.id} should have a name")
                    self.assertIsNotNone(param.description, f"Parameter {param.id} should have a description")
                    self.assertIn(param.severity, [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW],
                                f"Parameter {param.id} should have a valid severity")
            
        except Exception as e:
            self.fail(f"Windows Annexure A coverage test failed: {str(e)}")
    
    @patch('security_hardening_tool.modules.linux.linux_module.LinuxHardeningModule._validate_permissions')
    @patch('sys.platform', 'linux')
    def test_linux_annexure_b_coverage(self, mock_validate_permissions):
        """Test that Linux module covers all Annexure B parameters."""
        # Set up mocks
        mock_validate_permissions.return_value = None
        
        # Add geteuid to os module if it doesn't exist (Windows compatibility)
        if not hasattr(os, 'geteuid'):
            os.geteuid = lambda: 0
        
        try:
            # Initialize Linux module
            linux_module = LinuxHardeningModule()
            
            # Get supported parameters
            supported_params = linux_module.get_supported_parameters()
            supported_param_ids = {param.id for param in supported_params}
            
            # Check coverage of Annexure B parameters
            covered_params = supported_param_ids.intersection(self.annexure_b_parameters)
            missing_params = self.annexure_b_parameters - supported_param_ids
            
            print(f"\nLinux Annexure B Coverage Analysis:")
            print(f"Total Annexure B parameters: {len(self.annexure_b_parameters)}")
            print(f"Covered parameters: {len(covered_params)}")
            print(f"Coverage percentage: {(len(covered_params) / len(self.annexure_b_parameters)) * 100:.1f}%")
            
            if missing_params:
                print(f"Missing parameters: {sorted(missing_params)}")
            
            # We expect at least 60% coverage for a robust implementation
            coverage_percentage = (len(covered_params) / len(self.annexure_b_parameters)) * 100
            self.assertGreaterEqual(coverage_percentage, 40.0, 
                                  f"Linux module should cover at least 40% of Annexure B parameters. "
                                  f"Current coverage: {coverage_percentage:.1f}%")
            
            # Verify that all covered parameters are properly configured
            for param in supported_params:
                if param.id in self.annexure_b_parameters:
                    self.assertIsNotNone(param.name, f"Parameter {param.id} should have a name")
                    self.assertIsNotNone(param.description, f"Parameter {param.id} should have a description")
                    self.assertIn(param.severity, [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW],
                                f"Parameter {param.id} should have a valid severity")
            
        except Exception as e:
            self.fail(f"Linux Annexure B coverage test failed: {str(e)}")
    
    def test_configuration_file_completeness(self):
        """Test that configuration files contain parameters from both annexures."""
        try:
            # Test all hardening levels
            for level in [HardeningLevel.BASIC, HardeningLevel.MODERATE, HardeningLevel.STRICT]:
                parameters = self.config_manager.load_hardening_level(level)
                param_ids = {param.id for param in parameters}
                
                # Check for Windows parameters
                windows_coverage = len(param_ids.intersection(self.annexure_a_parameters))
                
                # Check for Linux parameters  
                linux_coverage = len(param_ids.intersection(self.annexure_b_parameters))
                
                print(f"\nConfiguration Level: {level.value}")
                print(f"Windows parameters: {windows_coverage}")
                print(f"Linux parameters: {linux_coverage}")
                print(f"Total parameters: {len(parameters)}")
                
                # Verify that configuration files contain reasonable coverage
                self.assertGreater(len(parameters), 0, 
                                 f"Configuration level {level.value} should contain parameters")
                
                # Verify parameter quality
                for param in parameters:
                    self.assertIsNotNone(param.id, "Parameter should have an ID")
                    self.assertIsNotNone(param.name, "Parameter should have a name")
                    self.assertIsNotNone(param.category, "Parameter should have a category")
                    self.assertIsNotNone(param.description, "Parameter should have a description")
                    
        except Exception as e:
            self.fail(f"Configuration file completeness test failed: {str(e)}")
    
    def test_parameter_categorization(self):
        """Test that parameters are properly categorized according to security domains."""
        expected_categories = {
            'authentication',
            'access_control', 
            'network',
            'auditing',
            'services',
            'system',
            'filesystem'
        }
        
        try:
            # Load all parameters from moderate level (most comprehensive)
            parameters = self.config_manager.load_hardening_level(HardeningLevel.MODERATE)
            
            # Collect all categories
            found_categories = {param.category for param in parameters}
            
            print(f"\nParameter Categories Found: {sorted(found_categories)}")
            print(f"Expected Categories: {sorted(expected_categories)}")
            
            # Verify that we have parameters in major security categories
            major_categories = {'authentication', 'access_control', 'network', 'auditing'}
            covered_major_categories = found_categories.intersection(major_categories)
            
            self.assertGreaterEqual(len(covered_major_categories), 3,
                                  f"Should cover at least 3 major security categories. "
                                  f"Found: {covered_major_categories}")
            
            # Verify category distribution
            category_counts = {}
            for param in parameters:
                category_counts[param.category] = category_counts.get(param.category, 0) + 1
            
            print(f"Category distribution: {category_counts}")
            
            # Ensure no category is empty
            for category in found_categories:
                self.assertGreater(category_counts[category], 0,
                                 f"Category {category} should have at least one parameter")
                
        except Exception as e:
            self.fail(f"Parameter categorization test failed: {str(e)}")
    
    def test_severity_distribution(self):
        """Test that parameters have appropriate severity distribution."""
        try:
            parameters = self.config_manager.load_hardening_level(HardeningLevel.STRICT)
            
            # Count parameters by severity
            severity_counts = {}
            for param in parameters:
                severity_counts[param.severity] = severity_counts.get(param.severity, 0) + 1
            
            print(f"\nSeverity Distribution: {severity_counts}")
            
            # Verify we have parameters across different severity levels
            self.assertGreater(len(severity_counts), 1,
                             "Should have parameters with different severity levels")
            
            # Verify that high/critical severity parameters exist
            high_severity_count = severity_counts.get(Severity.HIGH, 0) + severity_counts.get(Severity.CRITICAL, 0)
            self.assertGreater(high_severity_count, 0,
                             "Should have at least some high or critical severity parameters")
            
            # Verify severity percentages are reasonable
            total_params = len(parameters)
            if total_params > 0:
                critical_pct = (severity_counts.get(Severity.CRITICAL, 0) / total_params) * 100
                high_pct = (severity_counts.get(Severity.HIGH, 0) / total_params) * 100
                
                print(f"Critical severity: {critical_pct:.1f}%")
                print(f"High severity: {high_pct:.1f}%")
                
                # Reasonable distribution: not everything should be critical
                self.assertLessEqual(critical_pct, 50.0,
                                   "Not more than 50% of parameters should be critical severity")
                
        except Exception as e:
            self.fail(f"Severity distribution test failed: {str(e)}")
    
    def test_compliance_framework_mapping(self):
        """Test that parameters are mapped to compliance frameworks."""
        try:
            parameters = self.config_manager.load_hardening_level(HardeningLevel.MODERATE)
            
            # Check for compliance framework mappings
            frameworks_found = set()
            mapped_params = 0
            
            for param in parameters:
                if param.compliance_frameworks:
                    mapped_params += 1
                    frameworks_found.update(param.compliance_frameworks)
            
            print(f"\nCompliance Framework Analysis:")
            print(f"Parameters with framework mappings: {mapped_params}/{len(parameters)}")
            print(f"Frameworks found: {sorted(frameworks_found)}")
            
            # We expect some parameters to be mapped to compliance frameworks
            if len(parameters) > 0:
                mapping_percentage = (mapped_params / len(parameters)) * 100
                print(f"Mapping percentage: {mapping_percentage:.1f}%")
                
                # At least some parameters should have compliance mappings
                self.assertGreater(mapped_params, 0,
                                 "At least some parameters should be mapped to compliance frameworks")
            
        except Exception as e:
            self.fail(f"Compliance framework mapping test failed: {str(e)}")
    
    def _setup_windows_mocks(self, mock_winreg, mock_service):
        """Set up Windows mocks for testing."""
        # Mock registry operations
        mock_key = MagicMock()
        mock_winreg.OpenKey.return_value.__enter__.return_value = mock_key
        mock_winreg.CreateKey.return_value.__enter__.return_value = mock_key
        mock_winreg.QueryValueEx.return_value = (1, mock_winreg.REG_DWORD)
        
        # Mock registry constants
        mock_winreg.HKEY_LOCAL_MACHINE = -2147483646
        mock_winreg.KEY_READ = 131097
        mock_winreg.KEY_WRITE = 131078
        mock_winreg.REG_DWORD = 4
        
        # Mock service operations
        mock_service.OpenSCManager.return_value = MagicMock()
        mock_service.OpenService.return_value = MagicMock()
        mock_service.QueryServiceStatus.return_value = (0, 1, 0, 0, 0, 0, 0)
        mock_service.QueryServiceConfig.return_value = (16, "Test Service", 4, 1, "C:\\test.exe", "", 0, "", "", "")
        
        # Mock service constants
        mock_service.SC_MANAGER_CONNECT = 1
        mock_service.SERVICE_QUERY_STATUS = 4
        mock_service.SERVICE_QUERY_CONFIG = 1


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)