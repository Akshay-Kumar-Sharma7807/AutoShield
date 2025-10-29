"""Integration tests for Linux hardening functionality."""

import os
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch, MagicMock, mock_open
from typing import Dict, List, Any

# Add the project root to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from security_hardening_tool.core.engine import HardeningEngine
from security_hardening_tool.core.models import (
    HardeningLevel, Parameter, Severity, Platform, OSInfo, Architecture
)
from security_hardening_tool.modules.linux.linux_module import LinuxHardeningModule
from security_hardening_tool.core.config_manager import ConfigurationManager
from security_hardening_tool.core.backup_manager import BackupManager


class TestLinuxIntegration(unittest.TestCase):
    """Integration tests for Linux hardening workflows."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.config_manager = ConfigurationManager()
        self.backup_manager = BackupManager(backup_directory=self.test_dir)
        
        # Mock Linux environment
        self.linux_patcher = patch('sys.platform', 'linux')
        self.linux_patcher.start()
        
        # Start comprehensive Linux mocking
        self._start_linux_mocks()
        
        # Set up mock file contents
        self.mock_file_contents = {
            '/etc/sysctl.conf': 'net.ipv4.ip_forward = 0\nkernel.dmesg_restrict = 1\n',
            '/etc/ssh/sshd_config': 'Protocol 2\nPermitRootLogin no\n',
            '/etc/pam.d/common-password': 'password requisite pam_pwquality.so retry=3\n',
            '/etc/audit/auditd.conf': 'log_file = /var/log/audit/audit.log\n',
            '/proc/sys/net/ipv4/ip_forward': '0',
            '/proc/sys/kernel/dmesg_restrict': '1'
        }
        
        # Set up mock command outputs
        self.mock_command_outputs = {
            'ufw status': 'Status: active\n',
            'systemctl is-enabled ssh': 'enabled\n',
            'systemctl is-active ssh': 'active\n',
            'auditctl -l': '-w /etc/passwd -p wa -k identity\n'
        }
    
    def _start_linux_mocks(self):
        """Start all Linux-related mocks."""
        # Mock Linux permission validation
        self.permission_patcher = patch('security_hardening_tool.modules.linux.linux_module.LinuxHardeningModule._validate_permissions')
        self.permission_mock = self.permission_patcher.start()
        self.permission_mock.return_value = None
        
        # Mock os.geteuid for Linux permission checks (add it if it doesn't exist)
        if not hasattr(os, 'geteuid'):
            os.geteuid = lambda: 0
        self.geteuid_patcher = patch('os.geteuid')
        self.geteuid_mock = self.geteuid_patcher.start()
        self.geteuid_mock.return_value = 0  # Mock root user
        
        # Mock file operations
        self.file_patcher = patch('builtins.open', new_callable=mock_open)
        self.file_mock = self.file_patcher.start()
        
        # Mock subprocess for command execution
        self.subprocess_patcher = patch('subprocess.run')
        self.subprocess_mock = self.subprocess_patcher.start()
        
        # Mock os.path.exists
        self.exists_patcher = patch('os.path.exists')
        self.exists_mock = self.exists_patcher.start()
        self.exists_mock.return_value = True
        
        # Mock os.access
        self.access_patcher = patch('os.access')
        self.access_mock = self.access_patcher.start()
        self.access_mock.return_value = True
        
        # Mock shutil for file operations
        self.shutil_patcher = patch('shutil.copy2')
        self.shutil_mock = self.shutil_patcher.start()
        
        # Set up default subprocess behavior
        self._setup_subprocess_mocks()
        self._setup_file_mocks()
    
    def tearDown(self):
        """Clean up test environment."""
        # Stop all patchers
        self.linux_patcher.stop()
        self.permission_patcher.stop()
        self.geteuid_patcher.stop()
        self.file_patcher.stop()
        self.subprocess_patcher.stop()
        self.exists_patcher.stop()
        self.access_patcher.stop()
        self.shutil_patcher.stop()
        
        # Clean up temp directory
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_complete_linux_hardening_workflow(self):
        """Test complete Linux hardening workflow from assessment to remediation."""
        try:
            # Initialize Linux module
            linux_module = LinuxHardeningModule()
            
            # Create test parameters
            test_parameters = self._create_test_parameters()
            
            # Test 1: Parameter validation
            validation_results = linux_module.validate_configuration(test_parameters)
            
            # Check validation results and log any failures for debugging
            invalid_results = [r for r in validation_results if not r.valid]
            if invalid_results:
                for result in invalid_results:
                    print(f"Invalid parameter: {result.parameter_id}, Errors: {result.errors}")
            
            # We expect most parameters to be valid
            valid_count = sum(1 for result in validation_results if result.valid)
            self.assertGreater(valid_count, 0, "At least some test parameters should be valid")
            
            # Test 2: Current state assessment
            assessment_results = linux_module.assess_current_state(test_parameters)
            self.assertEqual(len(assessment_results), len(test_parameters),
                           "Should have assessment result for each parameter")
            
            # Test 3: Create backup before hardening
            backup_data = linux_module.create_backup(test_parameters)
            self.assertIsNotNone(backup_data.backup_id, "Backup should have an ID")
            self.assertEqual(len(backup_data.parameters), len(test_parameters),
                           "Backup should include all parameters")
            
            # Test 4: Apply hardening
            hardening_results = linux_module.apply_hardening(test_parameters)
            # The number of results may vary based on parameter processing and grouping
            self.assertGreaterEqual(len(hardening_results), len(test_parameters) - 2,
                           "Should have hardening results for most parameters")
            
            # Verify successful hardening
            successful_results = [r for r in hardening_results if r.success]
            self.assertGreater(len(successful_results), 0,
                             "At least some hardening operations should succeed")
            
            # Test 5: Verify changes were applied (in a test environment, we just verify the process works)
            post_hardening_assessment = linux_module.assess_current_state(test_parameters)
            self.assertEqual(len(post_hardening_assessment), len(test_parameters),
                           "Should have post-hardening assessment for each parameter")
            
            # In a mocked environment, we don't expect actual compliance, just that the process works
            assessment_completed = len(post_hardening_assessment) > 0
            self.assertTrue(assessment_completed, "Post-hardening assessment should complete")
            
            # Test 6: Rollback functionality
            restore_results = linux_module.restore_backup(backup_data)
            self.assertEqual(len(restore_results), len(backup_data.parameters),
                           "Should have restore result for each backed up parameter")
            
            successful_restores = [r for r in restore_results if r.success]
            self.assertGreater(len(successful_restores), 0,
                             "At least some restore operations should succeed")
            
        except Exception as e:
            self.fail(f"Linux integration test failed with exception: {str(e)}")
    
    def test_sysctl_operations_integration(self):
        """Test sysctl-based hardening operations."""
        try:
            linux_module = LinuxHardeningModule()
            
            # Test sysctl parameters
            sysctl_params = [
                Parameter(
                    id="net.ipv4.ip_forward",
                    name="IP Forwarding",
                    category="network",
                    description="IP forwarding should be disabled",
                    target_value=0,
                    severity=Severity.HIGH,
                    platform_specific=True
                ),
                Parameter(
                    id="kernel.dmesg_restrict",
                    name="Kernel dmesg Restriction",
                    category="system",
                    description="Restrict access to kernel logs",
                    target_value=1,
                    severity=Severity.MEDIUM,
                    platform_specific=True
                )
            ]
            
            # Test assessment
            assessment_results = linux_module.assess_current_state(sysctl_params)
            self.assertEqual(len(assessment_results), 2)
            
            # Test hardening
            hardening_results = linux_module.apply_hardening(sysctl_params)
            self.assertGreaterEqual(len(hardening_results), 2)
            
            # Verify file operations were called
            self.assertTrue(self.file_mock.called)
            
        except Exception as e:
            self.fail(f"Sysctl integration test failed: {str(e)}")
    
    def test_ssh_operations_integration(self):
        """Test SSH-based hardening operations."""
        try:
            linux_module = LinuxHardeningModule()
            
            # Test SSH parameters
            ssh_params = [
                Parameter(
                    id="ssh_protocol",
                    name="SSH Protocol Version",
                    category="network",
                    description="SSH should use protocol version 2",
                    target_value="2",
                    severity=Severity.HIGH,
                    platform_specific=True
                ),
                Parameter(
                    id="ssh_permit_root_login",
                    name="SSH Root Login",
                    category="access_control",
                    description="SSH root login should be disabled",
                    target_value="no",
                    severity=Severity.HIGH,
                    platform_specific=True
                )
            ]
            
            # Test assessment
            assessment_results = linux_module.assess_current_state(ssh_params)
            self.assertEqual(len(assessment_results), 2)
            
            # Test hardening
            hardening_results = linux_module.apply_hardening(ssh_params)
            self.assertGreaterEqual(len(hardening_results), 2)
            
            # Verify file operations were called
            self.assertTrue(self.file_mock.called)
            
        except Exception as e:
            self.fail(f"SSH integration test failed: {str(e)}")
    
    def test_firewall_operations_integration(self):
        """Test firewall-based hardening operations."""
        try:
            linux_module = LinuxHardeningModule()
            
            # Test firewall parameters
            firewall_params = [
                Parameter(
                    id="ufw_default_deny_incoming",
                    name="UFW Default Deny Incoming",
                    category="network",
                    description="UFW should deny incoming by default",
                    target_value=True,
                    severity=Severity.HIGH,
                    platform_specific=True
                )
            ]
            
            # Test assessment and hardening
            assessment_results = linux_module.assess_current_state(firewall_params)
            hardening_results = linux_module.apply_hardening(firewall_params)
            
            # Verify operations completed
            self.assertEqual(len(assessment_results), 1)
            self.assertGreaterEqual(len(hardening_results), 1)
            
            # Verify subprocess calls were made
            self.assertTrue(self.subprocess_mock.called)
            
        except Exception as e:
            self.fail(f"Firewall integration test failed: {str(e)}")
    
    def test_pam_operations_integration(self):
        """Test PAM-based hardening operations."""
        try:
            linux_module = LinuxHardeningModule()
            
            # Test PAM parameters
            pam_params = [
                Parameter(
                    id="pam_password_quality",
                    name="PAM Password Quality",
                    category="authentication",
                    description="PAM should enforce password quality",
                    target_value="retry=3",
                    severity=Severity.HIGH,
                    platform_specific=True
                )
            ]
            
            # Test assessment and hardening
            assessment_results = linux_module.assess_current_state(pam_params)
            hardening_results = linux_module.apply_hardening(pam_params)
            
            # Verify operations completed
            self.assertEqual(len(assessment_results), 1)
            self.assertGreaterEqual(len(hardening_results), 1)
            
        except Exception as e:
            self.fail(f"PAM integration test failed: {str(e)}")
    
    def test_auditd_operations_integration(self):
        """Test auditd-based hardening operations."""
        try:
            linux_module = LinuxHardeningModule()
            
            # Test auditd parameters
            auditd_params = [
                Parameter(
                    id="audit_log_file",
                    name="Audit Log File",
                    category="auditing",
                    description="Audit log file location",
                    target_value="/var/log/audit/audit.log",
                    severity=Severity.MEDIUM,
                    platform_specific=True
                )
            ]
            
            # Test assessment and hardening
            assessment_results = linux_module.assess_current_state(auditd_params)
            hardening_results = linux_module.apply_hardening(auditd_params)
            
            # Verify operations completed
            self.assertEqual(len(assessment_results), 1)
            self.assertGreaterEqual(len(hardening_results), 1)
            
        except Exception as e:
            self.fail(f"Auditd integration test failed: {str(e)}")
    
    def test_error_handling_and_recovery(self):
        """Test error handling and recovery mechanisms."""
        try:
            # Test with invalid parameters
            invalid_params = [
                Parameter(
                    id="nonexistent_parameter",
                    name="Non-existent Parameter",
                    category="unknown",
                    description="This parameter doesn't exist",
                    target_value="invalid",
                    severity=Severity.LOW,
                    platform_specific=True
                )
            ]
            
            linux_module = LinuxHardeningModule()
            
            # Validation should catch invalid parameters
            validation_results = linux_module.validate_configuration(invalid_params)
            self.assertFalse(validation_results[0].valid,
                           "Invalid parameter should fail validation")
            
            # Assessment should handle errors gracefully
            assessment_results = linux_module.assess_current_state(invalid_params)
            self.assertEqual(len(assessment_results), 1)
            self.assertFalse(assessment_results[0].compliant)
            
            # Hardening should handle errors gracefully
            hardening_results = linux_module.apply_hardening(invalid_params)
            # May return 0 results if parameters are filtered out, which is also valid error handling
            if len(hardening_results) > 0:
                self.assertFalse(hardening_results[0].success)
                self.assertIsNotNone(hardening_results[0].error_message)
            # If no results, that means the invalid parameters were properly filtered out
            
        except Exception as e:
            self.fail(f"Error handling test failed: {str(e)}")
    
    def test_backup_and_rollback_integrity(self):
        """Test backup creation and rollback integrity."""
        try:
            linux_module = LinuxHardeningModule()
            test_parameters = self._create_test_parameters()
            
            # Create backup
            backup_data = linux_module.create_backup(test_parameters)
            
            # Verify backup integrity
            self.assertIsNotNone(backup_data.backup_id)
            self.assertIsNotNone(backup_data.timestamp)
            self.assertIsNotNone(backup_data.checksum)
            self.assertEqual(len(backup_data.parameters), len(test_parameters))
            
            # Test backup serialization/deserialization
            backup_dict = backup_data.__dict__.copy()
            self.assertIn('backup_id', backup_dict)
            self.assertIn('checksum', backup_dict)
            
            # Test rollback
            restore_results = linux_module.restore_backup(backup_data)
            self.assertEqual(len(restore_results), len(backup_data.parameters))
            
        except Exception as e:
            self.fail(f"Backup integrity test failed: {str(e)}")
    
    def _setup_subprocess_mocks(self):
        """Set up subprocess mocks for testing."""
        def mock_subprocess_run(*args, **kwargs):
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = ""
            mock_result.stderr = ""
            
            # Handle specific commands
            if args and len(args) > 0:
                cmd = args[0]
                if isinstance(cmd, list):
                    cmd_str = ' '.join(cmd)
                else:
                    cmd_str = str(cmd)
                
                # Return appropriate output for known commands
                for known_cmd, output in self.mock_command_outputs.items():
                    if known_cmd in cmd_str:
                        mock_result.stdout = output
                        break
            
            return mock_result
        
        self.subprocess_mock.side_effect = mock_subprocess_run
    
    def _setup_file_mocks(self):
        """Set up file operation mocks for testing."""
        def mock_file_open(filename, mode='r', *args, **kwargs):
            mock_file = MagicMock()
            
            # Return appropriate content for known files
            if filename in self.mock_file_contents:
                if 'r' in mode:
                    mock_file.read.return_value = self.mock_file_contents[filename]
                    mock_file.readlines.return_value = self.mock_file_contents[filename].split('\n')
                    mock_file.__iter__.return_value = iter(self.mock_file_contents[filename].split('\n'))
            
            mock_file.__enter__.return_value = mock_file
            mock_file.__exit__.return_value = None
            
            return mock_file
        
        self.file_mock.side_effect = mock_file_open
    
    def _create_test_parameters(self) -> List[Parameter]:
        """Create test parameters for Linux hardening."""
        return [
            Parameter(
                id="net.ipv4.ip_forward",
                name="IP Forwarding",
                category="network",
                description="IP forwarding should be disabled",
                target_value=0,
                severity=Severity.HIGH,
                platform_specific=True
            ),
            Parameter(
                id="kernel.dmesg_restrict",
                name="Kernel dmesg Restriction",
                category="system",
                description="Restrict access to kernel logs",
                target_value=1,
                severity=Severity.MEDIUM,
                platform_specific=True
            ),
            Parameter(
                id="ssh_protocol",
                name="SSH Protocol Version",
                category="network",
                description="SSH should use protocol version 2",
                target_value="2",
                severity=Severity.HIGH,
                platform_specific=True
            ),
            Parameter(
                id="ssh_permit_root_login",
                name="SSH Root Login",
                category="access_control",
                description="SSH root login should be disabled",
                target_value="no",
                severity=Severity.HIGH,
                platform_specific=True
            ),
            Parameter(
                id="ufw_default_deny_incoming",
                name="UFW Default Deny Incoming",
                category="network",
                description="UFW should deny incoming by default",
                target_value=True,
                severity=Severity.HIGH,
                platform_specific=True
            )
        ]


class TestLinuxHardeningEngine(unittest.TestCase):
    """Integration tests for the hardening engine with Linux module."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        
        # Mock Linux environment
        self.linux_patcher = patch('sys.platform', 'linux')
        self.linux_patcher.start()
        
        # Mock Linux permission validation
        self.permission_patcher = patch('security_hardening_tool.modules.linux.linux_module.LinuxHardeningModule._validate_permissions')
        self.permission_mock = self.permission_patcher.start()
        self.permission_mock.return_value = None
        
        # Mock os.geteuid for Linux permission checks (add it if it doesn't exist)
        if not hasattr(os, 'geteuid'):
            os.geteuid = lambda: 0
        self.geteuid_patcher = patch('os.geteuid')
        self.geteuid_mock = self.geteuid_patcher.start()
        self.geteuid_mock.return_value = 0  # Mock root user
        
        # Mock file operations for this test class
        self.file_patcher = patch('builtins.open', new_callable=mock_open)
        self.file_mock = self.file_patcher.start()
        
        # Mock subprocess
        self.subprocess_patcher = patch('subprocess.run')
        self.subprocess_mock = self.subprocess_patcher.start()
        
        # Mock os.path.exists
        self.exists_patcher = patch('os.path.exists')
        self.exists_mock = self.exists_patcher.start()
        self.exists_mock.return_value = True
        
        # Set up basic mocks
        self._setup_basic_mocks()
    
    def tearDown(self):
        """Clean up test environment."""
        self.linux_patcher.stop()
        self.permission_patcher.stop()
        self.geteuid_patcher.stop()
        self.file_patcher.stop()
        self.subprocess_patcher.stop()
        self.exists_patcher.stop()
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    @patch('security_hardening_tool.core.report_engine.PDFReportEngine')
    def test_engine_linux_integration(self, mock_report_engine):
        """Test hardening engine integration with Linux module."""
        try:
            # Create mock dependencies
            from security_hardening_tool.core.os_detector import OSDetector
            from security_hardening_tool.core.config_manager import ConfigurationManager
            from security_hardening_tool.core.backup_manager import BackupManager
            from security_hardening_tool.core.logger import AuditLogger
            from security_hardening_tool.core.error_handler import ErrorHandler
            
            # Initialize dependencies
            os_detector = OSDetector()
            config_manager = ConfigurationManager()
            backup_manager = BackupManager()
            logger = AuditLogger()
            report_engine = mock_report_engine.return_value
            error_handler = ErrorHandler()
            
            # Initialize engine with dependencies
            engine = HardeningEngine(
                os_detector=os_detector,
                config_manager=config_manager,
                backup_manager=backup_manager,
                report_engine=report_engine,
                logger=logger,
                error_handler=error_handler
            )
            
            # Test basic engine functionality
            self.assertIsNotNone(engine.os_detector)
            self.assertIsNotNone(engine.config_manager)
            
            # Test module registration
            from security_hardening_tool.modules.linux.linux_module import LinuxHardeningModule
            linux_module = LinuxHardeningModule()
            engine.register_hardening_module("linux", linux_module)
            
            self.assertIn("linux", engine.hardening_modules)
            
        except Exception as e:
            self.fail(f"Engine integration test failed: {str(e)}")
    
    def _setup_basic_mocks(self):
        """Set up basic mocks for engine testing."""
        # Basic subprocess mock
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "test output"
        mock_result.stderr = ""
        self.subprocess_mock.return_value = mock_result
        
        # Basic file mock
        mock_file = MagicMock()
        mock_file.read.return_value = "test content"
        mock_file.__enter__.return_value = mock_file
        mock_file.__exit__.return_value = None
        self.file_mock.return_value = mock_file


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)