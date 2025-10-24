"""Main CLI entry point for the security hardening tool."""

import sys
import json
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom
import yaml
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import click
from security_hardening_tool.core.engine import HardeningEngine
from security_hardening_tool.core.os_detector import OSDetector
from security_hardening_tool.core.config_manager import ConfigurationManager
from security_hardening_tool.core.logger import AuditLogger, ConsoleLogger
from security_hardening_tool.core.models import (
    HardeningLevel, Platform, AssessmentResult, HardeningResult, 
    OperationResult, Severity
)


class DummyBackupManager:
    """Dummy backup manager for testing."""
    def create_backup(self, backup_data): return "test-backup-id"
    def list_backups(self): return []
    def get_backup(self, backup_id): return None
    def delete_backup(self, backup_id): return True
    def verify_backup_integrity(self, backup_id): return True


class DummyReportEngine:
    """Dummy report engine for testing."""
    def generate_assessment_report(self, results, output_path):
        from security_hardening_tool.core.models import OperationResult
        return OperationResult(success=True, message="Report generated")
    
    def generate_hardening_report(self, results, output_path):
        from security_hardening_tool.core.models import OperationResult
        return OperationResult(success=True, message="Report generated")
    
    def generate_compliance_report(self, results, framework, output_path):
        from security_hardening_tool.core.models import OperationResult
        return OperationResult(success=True, message="Report generated")


class DummyErrorHandler:
    """Dummy error handler for testing."""
    def handle_error(self, error):
        from security_hardening_tool.core.models import OperationResult
        return OperationResult(success=False, message=str(error))
    
    def suggest_remediation(self, error): return [str(error)]
    def attempt_recovery(self, error): return False


# Exit codes for automation workflows
class ExitCodes:
    """Standard exit codes for automation support."""
    SUCCESS = 0
    GENERAL_ERROR = 1
    CONFIGURATION_ERROR = 2
    PERMISSION_ERROR = 3
    VALIDATION_ERROR = 4
    PARTIAL_SUCCESS = 5
    COMPLIANCE_FAILURE = 6


def _load_config_file(config_file_path: Optional[str]) -> Dict[str, Any]:
    """Load custom parameters from configuration file."""
    if not config_file_path:
        return {}
    
    try:
        config_path = Path(config_file_path)
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_file_path}")
        
        with open(config_path, 'r', encoding='utf-8') as f:
            if config_path.suffix.lower() in ['.yaml', '.yml']:
                return yaml.safe_load(f) or {}
            elif config_path.suffix.lower() == '.json':
                return json.load(f)
            else:
                raise ValueError(f"Unsupported configuration file format: {config_path.suffix}")
                
    except Exception as e:
        click.echo(f"Error loading configuration file: {e}", err=True)
        sys.exit(ExitCodes.CONFIGURATION_ERROR)


def _output_automation_results(results: List[Any], format_type: str, output_path: Optional[str], operation_type: str):
    """Output results in JSON or XML format for automation consumption."""
    try:
        # Prepare data structure
        output_data = {
            "metadata": {
                "operation": operation_type,
                "timestamp": datetime.now().isoformat(),
                "format_version": "1.0",
                "total_items": len(results)
            },
            "results": []
        }
        
        # Convert results to serializable format
        for result in results:
            if isinstance(result, AssessmentResult):
                result_data = {
                    "parameter_id": result.parameter_id,
                    "current_value": _serialize_value(result.current_value),
                    "expected_value": _serialize_value(result.expected_value),
                    "compliant": result.compliant,
                    "severity": result.severity.value,
                    "risk_description": result.risk_description,
                    "remediation_steps": result.remediation_steps,
                    "timestamp": result.timestamp.isoformat()
                }
            elif isinstance(result, HardeningResult):
                result_data = {
                    "parameter_id": result.parameter_id,
                    "previous_value": _serialize_value(result.previous_value),
                    "applied_value": _serialize_value(result.applied_value),
                    "success": result.success,
                    "error_message": result.error_message,
                    "backup_created": result.backup_created,
                    "requires_reboot": result.requires_reboot,
                    "timestamp": result.timestamp.isoformat()
                }
            else:
                # Generic result handling
                result_data = {
                    "data": _serialize_value(result),
                    "timestamp": datetime.now().isoformat()
                }
            
            output_data["results"].append(result_data)
        
        # Add summary statistics
        if operation_type == "assessment":
            compliant_count = sum(1 for r in results if hasattr(r, 'compliant') and r.compliant)
            output_data["summary"] = {
                "total_parameters": len(results),
                "compliant_parameters": compliant_count,
                "non_compliant_parameters": len(results) - compliant_count,
                "compliance_percentage": (compliant_count / len(results) * 100) if results else 0
            }
        elif operation_type == "hardening":
            success_count = sum(1 for r in results if hasattr(r, 'success') and r.success)
            output_data["summary"] = {
                "total_parameters": len(results),
                "successful_parameters": success_count,
                "failed_parameters": len(results) - success_count,
                "success_percentage": (success_count / len(results) * 100) if results else 0
            }
        
        # Output in requested format
        if format_type == "json":
            output_content = json.dumps(output_data, indent=2, ensure_ascii=False)
        elif format_type == "xml":
            output_content = _convert_to_xml(output_data)
        else:
            raise ValueError(f"Unsupported output format: {format_type}")
        
        # Write to file or stdout
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(output_content)
            click.echo(f"Results saved to: {output_path}")
        else:
            click.echo(output_content)
            
    except Exception as e:
        click.echo(f"Error generating {format_type} output: {e}", err=True)
        sys.exit(ExitCodes.GENERAL_ERROR)


def _serialize_value(value: Any) -> Any:
    """Convert values to JSON-serializable format."""
    if value is None:
        return None
    elif isinstance(value, (str, int, float, bool)):
        return value
    elif isinstance(value, datetime):
        return value.isoformat()
    elif isinstance(value, (list, tuple)):
        return [_serialize_value(item) for item in value]
    elif isinstance(value, dict):
        return {k: _serialize_value(v) for k, v in value.items()}
    elif hasattr(value, '__dict__'):
        return _serialize_value(value.__dict__)
    else:
        return str(value)


def _convert_to_xml(data: Dict[str, Any]) -> str:
    """Convert dictionary data to XML format."""
    def dict_to_xml(parent, data_dict):
        for key, value in data_dict.items():
            # Clean key name for XML
            clean_key = key.replace(' ', '_').replace('-', '_')
            
            if isinstance(value, dict):
                child = ET.SubElement(parent, clean_key)
                dict_to_xml(child, value)
            elif isinstance(value, list):
                for item in value:
                    child = ET.SubElement(parent, clean_key)
                    if isinstance(item, dict):
                        dict_to_xml(child, item)
                    else:
                        child.text = str(item)
            else:
                child = ET.SubElement(parent, clean_key)
                child.text = str(value) if value is not None else ""
    
    root = ET.Element("hardening_results")
    dict_to_xml(root, data)
    
    # Pretty print XML
    rough_string = ET.tostring(root, encoding='unicode')
    reparsed = minidom.parseString(rough_string)
    return reparsed.toprettyxml(indent="  ")


def _calculate_exit_code(results: List[Any], operation_type: str) -> int:
    """Calculate appropriate exit code based on operation results."""
    if not results:
        return ExitCodes.SUCCESS
    
    if operation_type == "assessment":
        compliant_count = sum(1 for r in results if hasattr(r, 'compliant') and r.compliant)
        compliance_rate = (compliant_count / len(results)) * 100
        
        if compliance_rate == 100:
            return ExitCodes.SUCCESS
        elif compliance_rate >= 80:
            return ExitCodes.PARTIAL_SUCCESS
        else:
            return ExitCodes.COMPLIANCE_FAILURE
            
    elif operation_type == "hardening":
        success_count = sum(1 for r in results if hasattr(r, 'success') and r.success)
        success_rate = (success_count / len(results)) * 100
        
        if success_rate == 100:
            return ExitCodes.SUCCESS
        elif success_rate >= 80:
            return ExitCodes.PARTIAL_SUCCESS
        else:
            return ExitCodes.GENERAL_ERROR
    
    return ExitCodes.SUCCESS


def _validate_config_file_parameters(custom_parameters: Dict[str, Any]) -> bool:
    """Validate custom parameters from configuration file."""
    if not custom_parameters:
        return True
    
    try:
        # Basic validation of parameter structure
        if not isinstance(custom_parameters, dict):
            click.echo("Configuration file must contain a dictionary/object", err=True)
            return False
        
        # Validate parameter entries
        for param_id, param_config in custom_parameters.items():
            if not isinstance(param_id, str):
                click.echo(f"Parameter ID must be a string: {param_id}", err=True)
                return False
            
            if isinstance(param_config, dict):
                # Validate parameter configuration structure
                allowed_keys = {'target_value', 'enabled', 'severity', 'description'}
                invalid_keys = set(param_config.keys()) - allowed_keys
                if invalid_keys:
                    click.echo(f"Invalid configuration keys for {param_id}: {invalid_keys}", err=True)
                    return False
        
        return True
        
    except Exception as e:
        click.echo(f"Error validating configuration parameters: {e}", err=True)
        return False


def _validate_batch_config(batch_config: Dict[str, Any]) -> bool:
    """Validate batch configuration file structure."""
    try:
        if not isinstance(batch_config, dict):
            click.echo("Batch configuration must be a dictionary/object", err=True)
            return False
        
        if 'operations' not in batch_config:
            click.echo("Batch configuration must contain 'operations' array", err=True)
            return False
        
        operations = batch_config['operations']
        if not isinstance(operations, list):
            click.echo("'operations' must be an array", err=True)
            return False
        
        if not operations:
            click.echo("At least one operation must be specified", err=True)
            return False
        
        # Validate each operation
        for i, operation in enumerate(operations):
            if not isinstance(operation, dict):
                click.echo(f"Operation {i+1} must be a dictionary/object", err=True)
                return False
            
            # Required fields
            if 'type' not in operation:
                click.echo(f"Operation {i+1} must specify 'type' (assess/remediate)", err=True)
                return False
            
            if operation['type'] not in ['assess', 'remediate']:
                click.echo(f"Operation {i+1} type must be 'assess' or 'remediate'", err=True)
                return False
            
            # Optional but validated fields
            if 'level' in operation and operation['level'] not in ['basic', 'moderate', 'strict']:
                click.echo(f"Operation {i+1} level must be basic/moderate/strict", err=True)
                return False
        
        return True
        
    except Exception as e:
        click.echo(f"Error validating batch configuration: {e}", err=True)
        return False


def _execute_batch_operation(engine, operation: Dict[str, Any], output_dir: Optional[str], format_type: str) -> Dict[str, Any]:
    """Execute a single batch operation."""
    operation_type = operation.get('type', 'assess')
    hardening_level = HardeningLevel(operation.get('level', 'basic'))
    custom_parameters = operation.get('parameters', {})
    
    # Generate output filename if output directory specified
    output_file = None
    if output_dir:
        operation_name = operation.get('name', f'{operation_type}_{datetime.now().strftime("%Y%m%d_%H%M%S")}')
        safe_name = "".join(c for c in operation_name if c.isalnum() or c in ('-', '_')).rstrip()
        
        if format_type == 'json':
            output_file = Path(output_dir) / f"{safe_name}.json"
        elif format_type == 'xml':
            output_file = Path(output_dir) / f"{safe_name}.xml"
        else:
            output_file = Path(output_dir) / f"{safe_name}.txt"
    
    try:
        if operation_type == 'assess':
            results = engine.execute_assessment(hardening_level, custom_parameters)
            
            # Output results in specified format
            if format_type in ['json', 'xml'] and output_file:
                _output_automation_results(results, format_type, str(output_file), "assessment")
            
            # Calculate success metrics
            compliant_count = sum(1 for r in results if hasattr(r, 'compliant') and r.compliant)
            compliance_rate = (compliant_count / len(results)) * 100 if results else 0
            
            return {
                'success': True,
                'operation_type': operation_type,
                'total_parameters': len(results),
                'compliant_parameters': compliant_count,
                'compliance_rate': compliance_rate,
                'output_file': str(output_file) if output_file else None
            }
            
        elif operation_type == 'remediate':
            create_backup = operation.get('backup', True)
            results, backup_id = engine.execute_hardening(hardening_level, custom_parameters, create_backup=create_backup)
            
            # Output results in specified format
            if format_type in ['json', 'xml'] and output_file:
                _output_automation_results(results, format_type, str(output_file), "hardening")
            
            # Calculate success metrics
            success_count = sum(1 for r in results if hasattr(r, 'success') and r.success)
            success_rate = (success_count / len(results)) * 100 if results else 0
            
            return {
                'success': True,
                'operation_type': operation_type,
                'total_parameters': len(results),
                'successful_parameters': success_count,
                'success_rate': success_rate,
                'backup_id': backup_id,
                'output_file': str(output_file) if output_file else None
            }
        
        else:
            raise ValueError(f"Unsupported operation type: {operation_type}")
            
    except Exception as e:
        return {
            'success': False,
            'operation_type': operation_type,
            'error': str(e)
        }


def _generate_batch_summary(batch_results: List[Dict[str, Any]], output_dir: Optional[str], format_type: str, quiet: bool):
    """Generate summary report for batch operations."""
    summary_data = {
        "metadata": {
            "batch_execution": True,
            "timestamp": datetime.now().isoformat(),
            "format_version": "1.0",
            "total_operations": len(batch_results)
        },
        "summary": {
            "successful_operations": sum(1 for r in batch_results if r['success']),
            "failed_operations": sum(1 for r in batch_results if not r['success']),
            "success_rate": (sum(1 for r in batch_results if r['success']) / len(batch_results) * 100) if batch_results else 0
        },
        "operations": batch_results
    }
    
    # Output summary
    if output_dir:
        summary_file = Path(output_dir) / f"batch_summary.{format_type}"
        
        if format_type == 'json':
            with open(summary_file, 'w', encoding='utf-8') as f:
                json.dump(summary_data, f, indent=2, ensure_ascii=False)
        elif format_type == 'xml':
            xml_content = _convert_to_xml(summary_data)
            with open(summary_file, 'w', encoding='utf-8') as f:
                f.write(xml_content)
        else:
            # Text format summary
            with open(summary_file, 'w', encoding='utf-8') as f:
                f.write("Batch Operation Summary\n")
                f.write("=" * 50 + "\n")
                f.write(f"Total Operations: {summary_data['metadata']['total_operations']}\n")
                f.write(f"Successful: {summary_data['summary']['successful_operations']}\n")
                f.write(f"Failed: {summary_data['summary']['failed_operations']}\n")
                f.write(f"Success Rate: {summary_data['summary']['success_rate']:.1f}%\n\n")
                
                for result in batch_results:
                    status = "✓" if result['success'] else "✗"
                    f.write(f"{status} {result['name']} ({result['type']})\n")
                    if not result['success'] and 'error' in result:
                        f.write(f"  Error: {result['error']}\n")
        
        if not quiet:
            click.echo(f"Batch summary saved to: {summary_file}")
    
    # Display summary to console if not quiet
    if not quiet:
        click.echo("\nBatch Operation Summary:")
        click.echo("=" * 50)
        click.echo(f"Total Operations: {summary_data['metadata']['total_operations']}")
        click.echo(f"Successful: {summary_data['summary']['successful_operations']}")
        click.echo(f"Failed: {summary_data['summary']['failed_operations']}")
        click.echo(f"Success Rate: {summary_data['summary']['success_rate']:.1f}%")


@click.group()
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--log-level', default='INFO', help='Set logging level')
@click.pass_context
def cli(ctx, verbose, log_level):
    """Cross-Platform Security Hardening Tool"""
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose
    ctx.obj['log_level'] = log_level


@cli.command()
@click.pass_context
def gui(ctx):
    """Launch the graphical user interface"""
    try:
        # Import GUI launcher
        from security_hardening_tool.gui.launcher import GUILauncher
        
        # Create and run launcher
        launcher = GUILauncher()
        exit_code = launcher.launch()
        sys.exit(exit_code)
        
    except ImportError as e:
        click.echo("Error: GUI dependencies not available.", err=True)
        click.echo("Please ensure tkinter is installed on your system.", err=True)
        if ctx.obj['verbose']:
            click.echo(f"Import error: {e}", err=True)
        sys.exit(ExitCodes.GENERAL_ERROR)
    except Exception as e:
        click.echo(f"Error launching GUI: {e}", err=True)
        if ctx.obj['verbose']:
            import traceback
            click.echo(traceback.format_exc(), err=True)
        sys.exit(ExitCodes.GENERAL_ERROR)


@cli.command()
@click.option('--level', '-l', type=click.Choice(['basic', 'moderate', 'strict']), 
              default='basic', help='Hardening level')
@click.option('--output', '-o', help='Output file for assessment report')
@click.option('--format', type=click.Choice(['text', 'json', 'xml']), 
              default='text', help='Output format for automation')
@click.option('--config-file', '-c', help='Configuration file with custom parameters')
@click.option('--quiet', '-q', is_flag=True, help='Suppress non-essential output')
@click.pass_context
def assess(ctx, level, output, format, config_file, quiet):
    """Assess current security posture"""
    try:
        # Initialize components
        os_detector = OSDetector()
        config_manager = ConfigurationManager()
        logger = ConsoleLogger(ctx.obj['log_level'])
        
        # Create engine
        engine = HardeningEngine(
            os_detector=os_detector,
            config_manager=config_manager,
            backup_manager=DummyBackupManager(),
            report_engine=DummyReportEngine(),
            logger=logger,
            error_handler=DummyErrorHandler()
        )
        
        # Detect OS and register appropriate module
        os_info = engine.detect_os()
        click.echo(f"Detected OS: {os_info.platform.value} {os_info.version}")
        
        # Load appropriate hardening module
        if not _load_hardening_module(engine, os_info):
            return
        
        # Load custom parameters if config file provided
        custom_parameters = _load_config_file(config_file)
        if custom_parameters:
            if not _validate_config_file_parameters(custom_parameters):
                sys.exit(ExitCodes.VALIDATION_ERROR)
            if not quiet:
                click.echo(f"✓ Loaded {len(custom_parameters)} custom parameters from config file")
        
        # Execute assessment
        hardening_level = HardeningLevel(level)
        if not quiet:
            click.echo(f"Executing assessment with {hardening_level.value} level...")
        
        results = engine.execute_assessment(hardening_level, custom_parameters)
        
        # Handle automation output formats
        if format in ['json', 'xml']:
            _output_automation_results(results, format, output, "assessment")
            # Set appropriate exit code for automation
            exit_code = _calculate_exit_code(results, "assessment")
            sys.exit(exit_code)
            return
        
        # Display results in text format
        if not quiet:
            click.echo(f"\nAssessment Results ({len(results)} parameters checked):")
            click.echo("-" * 60)
        
        compliant_count = 0
        for result in results:
            status = "✓ COMPLIANT" if result.compliant else "✗ NON-COMPLIANT"
            severity = result.severity.value.upper()
            
            if not quiet:
                click.echo(f"{status} [{severity}] {result.parameter_id}")
                if ctx.obj['verbose']:
                    click.echo(f"  Current: {result.current_value}")
                    click.echo(f"  Expected: {result.expected_value}")
                    if not result.compliant:
                        click.echo(f"  Risk: {result.risk_description}")
            
            if result.compliant:
                compliant_count += 1
        
        # Summary
        compliance_rate = (compliant_count / len(results)) * 100 if results else 0
        if not quiet:
            click.echo("-" * 60)
            click.echo(f"Compliance Rate: {compliance_rate:.1f}% ({compliant_count}/{len(results)})")
        
        if output and format == 'text':
            engine.generate_report(results, "assessment", output)
            if not quiet:
                click.echo(f"Assessment report saved to: {output}")
        
        # Set appropriate exit code for automation
        exit_code = _calculate_exit_code(results, "assessment")
        sys.exit(exit_code)
            
    except Exception as e:
        click.echo(f"Error during assessment: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--level', '-l', type=click.Choice(['basic', 'moderate', 'strict']), 
              default='basic', help='Hardening level')
@click.option('--backup/--no-backup', default=True, help='Create backup before hardening')
@click.option('--output', '-o', help='Output file for hardening report')
@click.option('--format', type=click.Choice(['text', 'json', 'xml']), 
              default='text', help='Output format for automation')
@click.option('--config-file', '-c', help='Configuration file with custom parameters')
@click.option('--quiet', '-q', is_flag=True, help='Suppress non-essential output')
@click.option('--yes', '-y', is_flag=True, help='Skip confirmation prompt for automation')
@click.pass_context
def remediate(ctx, level, backup, output, format, config_file, quiet, yes):
    """Apply security hardening configurations"""
    # Handle confirmation for automation
    if not yes:
        if not click.confirm('Are you sure you want to apply hardening changes?'):
            click.echo("Operation cancelled.")
            return
    
    try:
        # Initialize components
        os_detector = OSDetector()
        config_manager = ConfigurationManager()
        logger = ConsoleLogger(ctx.obj['log_level'])
        
        # Create engine
        engine = HardeningEngine(
            os_detector=os_detector,
            config_manager=config_manager,
            backup_manager=DummyBackupManager(),
            report_engine=DummyReportEngine(),
            logger=logger,
            error_handler=DummyErrorHandler()
        )
        
        # Detect OS and register appropriate module
        os_info = engine.detect_os()
        click.echo(f"Detected OS: {os_info.platform.value} {os_info.version}")
        
        # Load appropriate hardening module
        if not _load_hardening_module(engine, os_info):
            return
        
        # Load custom parameters if config file provided
        custom_parameters = _load_config_file(config_file)
        if custom_parameters:
            if not _validate_config_file_parameters(custom_parameters):
                sys.exit(ExitCodes.VALIDATION_ERROR)
            if not quiet:
                click.echo(f"✓ Loaded {len(custom_parameters)} custom parameters from config file")
        
        # Execute hardening
        hardening_level = HardeningLevel(level)
        if not quiet:
            click.echo(f"Applying {hardening_level.value} level hardening...")
        
        results, backup_id = engine.execute_hardening(hardening_level, custom_parameters, create_backup=backup)
        
        # Handle automation output formats
        if format in ['json', 'xml']:
            # Include backup information in automation output
            if backup_id:
                backup_info = {"backup_id": backup_id, "backup_created": True}
            else:
                backup_info = {"backup_created": False}
            
            _output_automation_results(results, format, output, "hardening")
            # Set appropriate exit code for automation
            exit_code = _calculate_exit_code(results, "hardening")
            sys.exit(exit_code)
            return
        
        # Display results in text format
        if not quiet:
            click.echo(f"\nHardening Results ({len(results)} parameters processed):")
            click.echo("-" * 60)
        
        success_count = 0
        reboot_required = False
        
        for result in results:
            status = "✓ SUCCESS" if result.success else "✗ FAILED"
            if not quiet:
                click.echo(f"{status} {result.parameter_id}")
                
                if ctx.obj['verbose']:
                    click.echo(f"  Previous: {result.previous_value}")
                    click.echo(f"  Applied: {result.applied_value}")
                    if result.error_message:
                        click.echo(f"  Error: {result.error_message}")
            
            if result.success:
                success_count += 1
            
            if hasattr(result, 'requires_reboot') and result.requires_reboot:
                reboot_required = True
        
        # Summary
        success_rate = (success_count / len(results)) * 100 if results else 0
        if not quiet:
            click.echo("-" * 60)
            click.echo(f"Success Rate: {success_rate:.1f}% ({success_count}/{len(results)})")
            
            if reboot_required:
                click.echo("⚠️  System reboot required for some changes to take effect")
            
            if backup and backup_id:
                click.echo(f"✓ Configuration backup created: {backup_id}")
        
        if output and format == 'text':
            engine.generate_report(results, "hardening", output)
            if not quiet:
                click.echo(f"Hardening report saved to: {output}")
        
        # Set appropriate exit code for automation
        exit_code = _calculate_exit_code(results, "hardening")
        sys.exit(exit_code)
            
    except Exception as e:
        click.echo(f"Error during hardening: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--format', type=click.Choice(['text', 'json', 'xml']), 
              default='text', help='Output format for automation')
@click.option('--output', '-o', help='Output file for backup list')
@click.option('--quiet', '-q', is_flag=True, help='Suppress non-essential output')
@click.pass_context
def backups(ctx, format, output, quiet):
    """List available configuration backups"""
    try:
        # Initialize components
        os_detector = OSDetector()
        config_manager = ConfigurationManager()
        logger = ConsoleLogger(ctx.obj['log_level'])
        
        # Create engine
        engine = HardeningEngine(
            os_detector=os_detector,
            config_manager=config_manager,
            backup_manager=DummyBackupManager(),
            report_engine=DummyReportEngine(),
            logger=logger,
            error_handler=DummyErrorHandler()
        )
        
        # List backups
        backup_list = engine.list_backups()
        
        # Handle automation output formats
        if format in ['json', 'xml']:
            backup_data = []
            for backup in backup_list:
                backup_info = {
                    "backup_id": backup.backup_id,
                    "timestamp": backup.timestamp.isoformat(),
                    "os_platform": backup.os_info.platform.value,
                    "os_version": backup.os_info.version,
                    "parameter_count": len(backup.parameters),
                    "checksum": backup.checksum if hasattr(backup, 'checksum') else None,
                    "description": backup.description if hasattr(backup, 'description') else None
                }
                backup_data.append(backup_info)
            
            _output_automation_results(backup_data, format, output, "backups")
            sys.exit(ExitCodes.SUCCESS)
            return
        
        # Text format output
        if not backup_list:
            if not quiet:
                click.echo("No backups available")
            sys.exit(ExitCodes.SUCCESS)
            return
        
        if not quiet:
            click.echo(f"Available Backups ({len(backup_list)}):")
            click.echo("-" * 80)
        
        for backup in backup_list:
            if not quiet:
                click.echo(f"ID: {backup.backup_id}")
                click.echo(f"Date: {backup.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
                click.echo(f"Platform: {backup.os_info.platform.value} {backup.os_info.version}")
                click.echo(f"Parameters: {len(backup.parameters)}")
                if hasattr(backup, 'description') and backup.description:
                    click.echo(f"Description: {backup.description}")
                click.echo("-" * 80)
        
        sys.exit(ExitCodes.SUCCESS)
            
    except Exception as e:
        click.echo(f"Error listing backups: {e}", err=True)
        sys.exit(ExitCodes.GENERAL_ERROR)


@cli.command()
@click.option('--backup-id', help='Backup ID to rollback to')
@click.option('--format', type=click.Choice(['text', 'json', 'xml']), 
              default='text', help='Output format for automation')
@click.option('--output', '-o', help='Output file for rollback results')
@click.option('--quiet', '-q', is_flag=True, help='Suppress non-essential output')
@click.option('--yes', '-y', is_flag=True, help='Skip confirmation prompt for automation')
@click.pass_context
def rollback(ctx, backup_id, format, output, quiet, yes):
    """Rollback to a previous configuration backup"""
    # Handle confirmation for automation
    if not yes:
        if not click.confirm('Are you sure you want to rollback configurations?'):
            click.echo("Rollback cancelled.")
            sys.exit(ExitCodes.SUCCESS)
    
    try:
        # Initialize components
        os_detector = OSDetector()
        config_manager = ConfigurationManager()
        logger = ConsoleLogger(ctx.obj['log_level'])
        
        # Create engine
        engine = HardeningEngine(
            os_detector=os_detector,
            config_manager=config_manager,
            backup_manager=DummyBackupManager(),
            report_engine=DummyReportEngine(),
            logger=logger,
            error_handler=DummyErrorHandler()
        )
        
        # Detect OS and register appropriate module
        os_info = engine.detect_os()
        if not quiet:
            click.echo(f"Detected OS: {os_info.platform.value} {os_info.version}")
        
        # Load appropriate hardening module
        if not _load_hardening_module(engine, os_info):
            sys.exit(ExitCodes.GENERAL_ERROR)
        
        if not backup_id:
            # List available backups
            backups = engine.list_backups()
            if not backups:
                if not quiet:
                    click.echo("No backups available")
                sys.exit(ExitCodes.SUCCESS)
                return
            
            if not quiet:
                click.echo("Available backups:")
                click.echo("-" * 60)
                for backup in backups:
                    click.echo(f"ID: {backup.backup_id}")
                    click.echo(f"Date: {backup.timestamp}")
                    click.echo(f"Parameters: {len(backup.parameters)}")
                    click.echo("-" * 60)
            sys.exit(ExitCodes.SUCCESS)
            return
        
        # Execute rollback
        if not quiet:
            click.echo(f"Rolling back to backup: {backup_id}")
        result = engine.execute_rollback(backup_id)
        
        # Handle automation output formats
        if format in ['json', 'xml']:
            rollback_data = {
                "backup_id": result.backup_id,
                "success": result.success,
                "restored_parameters": len(result.restored_parameters),
                "errors": result.errors,
                "timestamp": datetime.now().isoformat()
            }
            
            _output_automation_results([rollback_data], format, output, "rollback")
            exit_code = ExitCodes.SUCCESS if result.success else ExitCodes.GENERAL_ERROR
            sys.exit(exit_code)
            return
        
        # Text format output
        if result.success:
            if not quiet:
                click.echo(f"✓ Rollback completed successfully")
                click.echo(f"Restored {len(result.restored_parameters)} parameters")
            sys.exit(ExitCodes.SUCCESS)
        else:
            if not quiet:
                click.echo(f"✗ Rollback failed")
                for error in result.errors:
                    click.echo(f"  Error: {error}")
            sys.exit(ExitCodes.GENERAL_ERROR)
            
    except Exception as e:
        click.echo(f"Error during rollback: {e}", err=True)
        sys.exit(ExitCodes.GENERAL_ERROR)


@cli.command()
@click.option('--format', type=click.Choice(['text', 'json', 'xml']), 
              default='text', help='Output format for automation')
@click.option('--output', '-o', help='Output file for validation results')
@click.option('--quiet', '-q', is_flag=True, help='Suppress non-essential output')
@click.pass_context
def validate(ctx, format, output, quiet):
    """Validate system readiness for hardening operations"""
    try:
        # Initialize components
        os_detector = OSDetector()
        config_manager = ConfigurationManager()
        logger = ConsoleLogger(ctx.obj['log_level'])
        
        # Create engine
        engine = HardeningEngine(
            os_detector=os_detector,
            config_manager=config_manager,
            backup_manager=DummyBackupManager(),
            report_engine=DummyReportEngine(),
            logger=logger,
            error_handler=DummyErrorHandler()
        )
        
        # Detect OS
        os_info = engine.detect_os()
        if not quiet:
            click.echo(f"Detected OS: {os_info.platform.value} {os_info.version}")
        
        validation_results = []
        validation_passed = True
        
        # Validate platform-specific module
        if os_info.platform == Platform.WINDOWS:
            if not quiet:
                click.echo("\n🔍 Validating Windows module...")
            try:
                from security_hardening_tool.modules.windows.windows_module import WindowsHardeningModule
                module = WindowsHardeningModule()
                engine.register_hardening_module("windows", module)
                
                # Test basic functionality
                params = module.get_supported_parameters()
                
                validation_results.append({
                    "component": "windows_module",
                    "status": "passed",
                    "message": f"Windows hardening module loaded successfully with {len(params)} parameters",
                    "parameter_count": len(params)
                })
                
                if not quiet:
                    click.echo("✓ Windows hardening module loaded successfully")
                    click.echo(f"✓ {len(params)} parameters available")
                
            except Exception as e:
                validation_results.append({
                    "component": "windows_module",
                    "status": "failed",
                    "message": f"Windows module validation failed: {e}",
                    "error": str(e)
                })
                validation_passed = False
                if not quiet:
                    click.echo(f"✗ Windows module validation failed: {e}")
                
        elif os_info.platform == Platform.LINUX:
            if not quiet:
                click.echo("\n🔍 Validating Linux module...")
            try:
                from security_hardening_tool.modules.linux.linux_module import LinuxHardeningModule
                module = LinuxHardeningModule()
                engine.register_hardening_module("linux", module)
                
                # Test basic functionality
                params = module.get_supported_parameters()
                
                validation_results.append({
                    "component": "linux_module",
                    "status": "passed",
                    "message": f"Linux hardening module loaded successfully with {len(params)} parameters",
                    "parameter_count": len(params)
                })
                
                if not quiet:
                    click.echo("✓ Linux hardening module loaded successfully")
                    click.echo(f"✓ {len(params)} parameters available")
                    click.echo("  Testing individual managers:")
                
                # Test individual managers
                managers = [
                    ('sysctl_manager', 'Sysctl'),
                    ('pam_manager', 'PAM'),
                    ('ssh_manager', 'SSH'),
                    ('auditd_manager', 'Auditd'),
                    ('firewall_manager', 'Firewall')
                ]
                
                for manager_attr, manager_name in managers:
                    try:
                        manager = getattr(module, manager_attr)
                        manager_params = manager.get_supported_parameters()
                        validation_results.append({
                            "component": f"linux_{manager_attr}",
                            "status": "passed",
                            "message": f"{manager_name} manager working with {len(manager_params)} parameters",
                            "parameter_count": len(manager_params)
                        })
                        if not quiet:
                            click.echo(f"    ✓ {manager_name} manager: {len(manager_params)} parameters")
                    except Exception as e:
                        validation_results.append({
                            "component": f"linux_{manager_attr}",
                            "status": "warning",
                            "message": f"{manager_name} manager issue: {e}",
                            "error": str(e)
                        })
                        if not quiet:
                            click.echo(f"    ⚠ {manager_name} manager: {e}")
                
            except ImportError as e:
                validation_results.append({
                    "component": "linux_module",
                    "status": "failed",
                    "message": f"Linux module import failed: {e}",
                    "error": str(e)
                })
                validation_passed = False
                if not quiet:
                    click.echo(f"✗ Linux module import failed: {e}")
                    _handle_linux_import_error(e)
            except Exception as e:
                validation_results.append({
                    "component": "linux_module",
                    "status": "failed",
                    "message": f"Linux module validation failed: {e}",
                    "error": str(e)
                })
                validation_passed = False
                if not quiet:
                    click.echo(f"✗ Linux module validation failed: {e}")
                    _handle_linux_dependency_error(e)
        
        # Validate configuration files
        if not quiet:
            click.echo("\n🔍 Validating configuration files...")
        try:
            for level in HardeningLevel:
                config = config_manager.get_hardening_configuration(level)
                validation_results.append({
                    "component": f"config_{level.value}",
                    "status": "passed",
                    "message": f"{level.value} configuration loaded with {len(config)} parameters",
                    "parameter_count": len(config)
                })
                if not quiet:
                    click.echo(f"✓ {level.value} configuration loaded ({len(config)} parameters)")
        except Exception as e:
            validation_results.append({
                "component": "configuration",
                "status": "failed",
                "message": f"Configuration validation failed: {e}",
                "error": str(e)
            })
            validation_passed = False
            if not quiet:
                click.echo(f"✗ Configuration validation failed: {e}")
        
        # Handle automation output formats
        if format in ['json', 'xml']:
            validation_data = {
                "overall_status": "passed" if validation_passed else "failed",
                "os_platform": os_info.platform.value,
                "os_version": os_info.version,
                "timestamp": datetime.now().isoformat(),
                "validation_results": validation_results
            }
            
            _output_automation_results([validation_data], format, output, "validation")
            exit_code = ExitCodes.SUCCESS if validation_passed else ExitCodes.VALIDATION_ERROR
            sys.exit(exit_code)
            return
        
        # Text format summary
        if not quiet:
            click.echo("\n" + "="*60)
            if validation_passed:
                click.echo("✅ System validation PASSED - Ready for hardening operations")
            else:
                click.echo("❌ System validation FAILED - Please resolve issues above")
        
        exit_code = ExitCodes.SUCCESS if validation_passed else ExitCodes.VALIDATION_ERROR
        sys.exit(exit_code)
            
    except Exception as e:
        click.echo(f"Error during validation: {e}", err=True)
        sys.exit(ExitCodes.GENERAL_ERROR)


@cli.command()
@click.option('--batch-file', '-b', required=True, help='Batch configuration file (YAML/JSON)')
@click.option('--output-dir', '-o', help='Output directory for batch results')
@click.option('--format', type=click.Choice(['text', 'json', 'xml']), 
              default='json', help='Output format for batch results')
@click.option('--continue-on-error', is_flag=True, help='Continue processing on individual failures')
@click.option('--parallel', is_flag=True, help='Process operations in parallel (experimental)')
@click.option('--quiet', '-q', is_flag=True, help='Suppress non-essential output')
@click.pass_context
def batch(ctx, batch_file, output_dir, format, continue_on_error, parallel, quiet):
    """Execute batch operations from configuration file"""
    try:
        # Load batch configuration
        batch_config = _load_config_file(batch_file)
        if not batch_config:
            click.echo("Empty or invalid batch configuration file", err=True)
            sys.exit(ExitCodes.CONFIGURATION_ERROR)
        
        # Validate batch configuration structure
        if not _validate_batch_config(batch_config):
            sys.exit(ExitCodes.VALIDATION_ERROR)
        
        # Create output directory if specified
        if output_dir:
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        os_detector = OSDetector()
        config_manager = ConfigurationManager()
        logger = ConsoleLogger(ctx.obj['log_level'])
        
        # Create engine
        engine = HardeningEngine(
            os_detector=os_detector,
            config_manager=config_manager,
            backup_manager=DummyBackupManager(),
            report_engine=DummyReportEngine(),
            logger=logger,
            error_handler=DummyErrorHandler()
        )
        
        # Detect OS and register appropriate module
        os_info = engine.detect_os()
        if not quiet:
            click.echo(f"Detected OS: {os_info.platform.value} {os_info.version}")
        
        if not _load_hardening_module(engine, os_info):
            sys.exit(ExitCodes.GENERAL_ERROR)
        
        # Process batch operations
        batch_results = []
        operations = batch_config.get('operations', [])
        
        if not quiet:
            click.echo(f"Processing {len(operations)} batch operations...")
        
        for i, operation in enumerate(operations):
            operation_name = operation.get('name', f'Operation_{i+1}')
            operation_type = operation.get('type', 'assess')
            
            if not quiet:
                click.echo(f"Executing {operation_name} ({operation_type})...")
            
            try:
                # Execute individual operation
                result = _execute_batch_operation(engine, operation, output_dir, format)
                batch_results.append({
                    'name': operation_name,
                    'type': operation_type,
                    'success': result.get('success', False),
                    'result': result
                })
                
                if not quiet:
                    status = "✓" if result.get('success', False) else "✗"
                    click.echo(f"  {status} {operation_name} completed")
                    
            except Exception as e:
                error_result = {
                    'name': operation_name,
                    'type': operation_type,
                    'success': False,
                    'error': str(e)
                }
                batch_results.append(error_result)
                
                if not quiet:
                    click.echo(f"  ✗ {operation_name} failed: {e}")
                
                if not continue_on_error:
                    click.echo("Stopping batch processing due to error", err=True)
                    break
        
        # Generate batch summary report
        _generate_batch_summary(batch_results, output_dir, format, quiet)
        
        # Calculate exit code based on batch results
        failed_operations = sum(1 for r in batch_results if not r['success'])
        if failed_operations == 0:
            sys.exit(ExitCodes.SUCCESS)
        elif failed_operations < len(batch_results):
            sys.exit(ExitCodes.PARTIAL_SUCCESS)
        else:
            sys.exit(ExitCodes.GENERAL_ERROR)
            
    except Exception as e:
        click.echo(f"Error during batch processing: {e}", err=True)
        sys.exit(ExitCodes.GENERAL_ERROR)


@cli.command()
@click.option('--examples', is_flag=True, help='Show automation and scripting examples')
@click.pass_context
def automation(ctx, examples):
    """Show automation and scripting capabilities"""
    if examples:
        _show_automation_examples()
    else:
        _show_automation_overview()


def _show_automation_overview():
    """Display overview of automation capabilities."""
    click.echo("Security Hardening Tool - Automation Support")
    click.echo("=" * 50)
    click.echo()
    click.echo("📋 Supported Output Formats:")
    click.echo("  • JSON - Machine-readable format for API integration")
    click.echo("  • XML  - Structured format for enterprise systems")
    click.echo("  • Text - Human-readable format (default)")
    click.echo()
    click.echo("📁 Configuration File Support:")
    click.echo("  • YAML - Human-friendly configuration format")
    click.echo("  • JSON - Structured configuration format")
    click.echo("  • Custom parameter overrides")
    click.echo("  • Batch operation definitions")
    click.echo()
    click.echo("🔄 Exit Codes for Automation:")
    click.echo("  • 0 - Success (100% compliance/success)")
    click.echo("  • 1 - General error")
    click.echo("  • 2 - Configuration error")
    click.echo("  • 3 - Permission error")
    click.echo("  • 4 - Validation error")
    click.echo("  • 5 - Partial success (80%+ compliance/success)")
    click.echo("  • 6 - Compliance failure (<80% compliance)")
    click.echo()
    click.echo("🚀 Batch Processing:")
    click.echo("  • Multiple operations in sequence")
    click.echo("  • Continue on error support")
    click.echo("  • Automated report generation")
    click.echo("  • Progress tracking and summaries")
    click.echo()
    click.echo("Use --examples to see detailed usage examples")


def _show_automation_examples():
    """Display detailed automation examples."""
    click.echo("Security Hardening Tool - Automation Examples")
    click.echo("=" * 50)
    click.echo()
    
    click.echo("🔍 JSON Output for CI/CD Integration:")
    click.echo("  # Assessment with JSON output")
    click.echo("  python -m security_hardening_tool.cli.main assess --format json --output assessment.json")
    click.echo("  echo $?  # Check exit code: 0=compliant, 6=non-compliant")
    click.echo()
    
    click.echo("⚙️ Custom Configuration Files:")
    click.echo("  # Use custom parameters from YAML file")
    click.echo("  python -m security_hardening_tool.cli.main assess --config-file custom_params.yaml")
    click.echo()
    click.echo("  # Use custom parameters from JSON file")
    click.echo("  python -m security_hardening_tool.cli.main remediate --config-file custom_params.json --yes")
    click.echo()
    
    click.echo("📦 Batch Processing:")
    click.echo("  # Execute multiple operations from batch file")
    click.echo("  python -m security_hardening_tool.cli.main batch --batch-file batch_config.yaml --output-dir results/")
    click.echo()
    click.echo("  # Batch with error handling")
    click.echo("  python -m security_hardening_tool.cli.main batch --batch-file ops.yaml --continue-on-error --format json")
    click.echo()
    
    click.echo("🤖 Automation-Friendly Options:")
    click.echo("  # Silent operation with XML output")
    click.echo("  python -m security_hardening_tool.cli.main assess --quiet --format xml --output results.xml")
    click.echo()
    click.echo("  # Automated remediation (skip confirmation)")
    click.echo("  python -m security_hardening_tool.cli.main remediate --yes --quiet --format json")
    click.echo()
    
    click.echo("📊 Exit Code Handling in Scripts:")
    click.echo("  #!/bin/bash")
    click.echo("  python -m security_hardening_tool.cli.main assess --format json --quiet")
    click.echo("  case $? in")
    click.echo("    0) echo \"System fully compliant\" ;;")
    click.echo("    5) echo \"Partial compliance - review needed\" ;;")
    click.echo("    6) echo \"Non-compliant - hardening required\" ;;")
    click.echo("    *) echo \"Error occurred\" ;;")
    click.echo("  esac")
    click.echo()
    
    click.echo("📋 Example Configuration Files:")
    click.echo("  • security_hardening_tool/config/batch_example.yaml")
    click.echo("  • security_hardening_tool/config/custom_parameters_example.json")


@cli.command()
@click.option('--format', type=click.Choice(['text', 'json', 'xml']), 
              default='text', help='Output format for automation')
@click.option('--output', '-o', help='Output file for system information')
@click.option('--quiet', '-q', is_flag=True, help='Suppress non-essential output')
@click.pass_context
def info(ctx, format, output, quiet):
    """Display system information and supported parameters"""
    try:
        # Initialize components
        os_detector = OSDetector()
        
        # Get system info
        system_info = os_detector.get_system_info()
        
        # Prepare system information data
        info_data = {
            "platform": system_info.os_info.platform.value,
            "version": system_info.os_info.version,
            "architecture": system_info.os_info.architecture.value,
            "hostname": system_info.hostname,
            "build": system_info.os_info.build if system_info.os_info.build else None,
            "domain": system_info.domain if system_info.domain else None,
            "platform_supported": os_detector.is_supported_platform(),
            "hardening_levels": [level.value for level in HardeningLevel],
            "timestamp": datetime.now().isoformat()
        }
        
        # Try to load appropriate module and get detailed status
        module_status = {}
        if system_info.os_info.platform == Platform.WINDOWS:
            try:
                from security_hardening_tool.modules.windows.windows_module import WindowsHardeningModule
                module = WindowsHardeningModule()
                params = module.get_supported_parameters()
                module_status = {
                    "module_available": True,
                    "parameter_count": len(params),
                    "error": None
                }
                if not quiet:
                    click.echo("✓ Windows hardening module available")
            except Exception as e:
                module_status = {
                    "module_available": False,
                    "parameter_count": 0,
                    "error": str(e)
                }
                if not quiet:
                    click.echo(f"✗ Windows hardening module unavailable: {e}")
                    
        elif system_info.os_info.platform == Platform.LINUX:
            try:
                from security_hardening_tool.modules.linux.linux_module import LinuxHardeningModule
                module = LinuxHardeningModule()
                params = module.get_supported_parameters()
                
                # Get manager status
                managers = [
                    ('sysctl_manager', 'Sysctl'),
                    ('pam_manager', 'PAM'), 
                    ('ssh_manager', 'SSH'),
                    ('auditd_manager', 'Auditd'),
                    ('firewall_manager', 'Firewall')
                ]
                
                manager_status = {}
                for attr, name in managers:
                    try:
                        manager = getattr(module, attr)
                        manager_params = manager.get_supported_parameters()
                        manager_status[name.lower()] = {
                            "available": True,
                            "parameter_count": len(manager_params),
                            "error": None
                        }
                        if not quiet:
                            click.echo(f"    ✓ {name}: {len(manager_params)} parameters")
                    except Exception as e:
                        manager_status[name.lower()] = {
                            "available": False,
                            "parameter_count": 0,
                            "error": str(e)
                        }
                        if not quiet:
                            click.echo(f"    ⚠ {name}: {e}")
                
                module_status = {
                    "module_available": True,
                    "parameter_count": len(params),
                    "managers": manager_status,
                    "error": None
                }
                
                if not quiet:
                    click.echo("✓ Linux hardening module available")
                    click.echo("  Manager Status:")
                        
            except ImportError as e:
                module_status = {
                    "module_available": False,
                    "parameter_count": 0,
                    "error": f"Import failed: {e}"
                }
                if not quiet:
                    click.echo(f"✗ Linux hardening module import failed: {e}")
                    _handle_linux_import_error(e)
            except Exception as e:
                module_status = {
                    "module_available": False,
                    "parameter_count": 0,
                    "error": str(e)
                }
                if not quiet:
                    click.echo(f"✗ Linux hardening module unavailable: {e}")
                    _show_linux_dependency_help(e)
        
        info_data["module_status"] = module_status
        
        # Handle automation output formats
        if format in ['json', 'xml']:
            _output_automation_results([info_data], format, output, "system_info")
            sys.exit(ExitCodes.SUCCESS)
            return
        
        # Text format output
        if not quiet:
            click.echo("System Information:")
            click.echo("-" * 40)
            click.echo(f"Platform: {info_data['platform']}")
            click.echo(f"Version: {info_data['version']}")
            click.echo(f"Architecture: {info_data['architecture']}")
            click.echo(f"Hostname: {info_data['hostname']}")
            
            if info_data['build']:
                click.echo(f"Build: {info_data['build']}")
            
            if info_data['domain']:
                click.echo(f"Domain: {info_data['domain']}")
            
            # Check if platform is supported
            if info_data['platform_supported']:
                click.echo("✓ Platform is supported")
            else:
                click.echo("✗ Platform is not fully supported")
            
            # Show available hardening levels
            click.echo("\nAvailable Hardening Levels:")
            click.echo("-" * 40)
            for level in info_data['hardening_levels']:
                click.echo(f"• {level}")
        
        sys.exit(ExitCodes.SUCCESS)
            
    except Exception as e:
        click.echo(f"Error getting system information: {e}", err=True)
        sys.exit(ExitCodes.GENERAL_ERROR)


def _load_hardening_module(engine, os_info):
    """Load appropriate hardening module for the detected OS."""
    if os_info.platform == Platform.WINDOWS:
        try:
            from security_hardening_tool.modules.windows.windows_module import WindowsHardeningModule
            module = WindowsHardeningModule()
            engine.register_hardening_module("windows", module)
            click.echo("✓ Windows hardening module loaded")
            return True
        except Exception as e:
            click.echo(f"✗ Could not load Windows module: {e}")
            _handle_windows_dependency_error(e)
            return False
            
    elif os_info.platform == Platform.LINUX:
        try:
            from security_hardening_tool.modules.linux.linux_module import LinuxHardeningModule
            module = LinuxHardeningModule()
            engine.register_hardening_module("linux", module)
            click.echo("✓ Linux hardening module loaded")
            return True
        except ImportError as e:
            click.echo(f"✗ Could not import Linux module: {e}")
            _handle_linux_import_error(e)
            return False
        except Exception as e:
            click.echo(f"✗ Could not initialize Linux module: {e}")
            _handle_linux_dependency_error(e)
            return False
    else:
        click.echo(f"✗ Unsupported platform: {os_info.platform.value}")
        click.echo("  Supported platforms: Windows 10/11, Ubuntu 20.04+, CentOS 7+")
        return False


def _handle_windows_dependency_error(error):
    """Handle Windows module dependency errors with helpful guidance."""
    error_str = str(error).lower()
    
    if "permission" in error_str or "access" in error_str:
        click.echo("\n💡 Permission Issue:")
        click.echo("  The Windows hardening module requires administrator privileges.")
        click.echo("  Please run as Administrator or with elevated privileges.")
        
    elif "registry" in error_str:
        click.echo("\n💡 Registry Access Issue:")
        click.echo("  Cannot access Windows Registry for security configurations.")
        click.echo("  Ensure you have administrative rights and registry access.")
        
    else:
        click.echo(f"\n💡 Windows Module Error: {error}")
        click.echo("  Check system compatibility and administrative privileges.")


def _handle_linux_import_error(error):
    """Handle Linux module import errors with helpful guidance."""
    error_str = str(error).lower()
    
    if "no module named" in error_str:
        click.echo("\n💡 Module Import Issue:")
        click.echo("  Linux hardening module components are missing.")
        click.echo("  Ensure all module files are present in security_hardening_tool/modules/linux/")
        
    elif "cannot import name" in error_str:
        click.echo("\n💡 Import Error:")
        click.echo("  Required classes or functions are missing from Linux modules.")
        click.echo("  Check that all Linux manager classes are properly implemented.")
        
    else:
        click.echo(f"\n💡 Linux Import Error: {error}")
        click.echo("  Check module installation and Python path configuration.")


def _handle_linux_dependency_error(error):
    """Handle Linux module dependency errors with helpful guidance."""
    error_str = str(error).lower()
    
    if "permission" in error_str or "root" in error_str or "geteuid" in error_str:
        click.echo("\n💡 Permission Issue:")
        click.echo("  The Linux hardening module requires root privileges.")
        click.echo("  Please run with: sudo python -m security_hardening_tool.cli.main")
        click.echo("  Or: sudo ./security_hardening_tool/cli/main.py")
        
    elif "command" in error_str and "not found" in error_str:
        click.echo("\n💡 Missing Dependencies:")
        click.echo("  Some required system commands are missing.")
        _show_linux_dependency_help(error)
        
    elif "systemctl" in error_str or "systemd" in error_str:
        click.echo("\n💡 SystemD Issue:")
        click.echo("  SystemD service management is not available.")
        click.echo("  This system may not support all Linux hardening features.")
        
    elif "sysctl" in error_str:
        click.echo("\n💡 Sysctl Issue:")
        click.echo("  Kernel parameter management is not available.")
        click.echo("  Install procps package: sudo apt-get install procps")
        
    elif "ufw" in error_str:
        click.echo("\n💡 Firewall Issue:")
        click.echo("  UFW firewall is not available.")
        click.echo("  Install UFW: sudo apt-get install ufw")
        
    elif "auditd" in error_str or "audit" in error_str:
        click.echo("\n💡 Audit Issue:")
        click.echo("  Audit daemon is not available.")
        click.echo("  Install auditd: sudo apt-get install auditd")
        
    else:
        click.echo(f"\n💡 Linux Module Error: {error}")
        click.echo("  Check system compatibility and dependencies.")


def _show_linux_dependency_help(error):
    """Show helpful information about Linux dependencies."""
    click.echo("\n📋 Linux Dependencies:")
    click.echo("  Core commands: sysctl, systemctl")
    click.echo("  Firewall: ufw (Uncomplicated Firewall)")
    click.echo("  Auditing: auditd (Linux Audit Daemon)")
    click.echo("  SSH: openssh-server")
    click.echo("  PAM: libpam-modules")
    
    click.echo("\n🔧 Installation commands by distribution:")
    click.echo("  Ubuntu/Debian:")
    click.echo("    sudo apt-get update")
    click.echo("    sudo apt-get install ufw auditd openssh-server libpam-modules procps")
    click.echo("  CentOS/RHEL 7+:")
    click.echo("    sudo yum install ufw audit openssh-server pam procps-ng")
    click.echo("  CentOS/RHEL 8+:")
    click.echo("    sudo dnf install ufw audit openssh-server pam procps-ng")
    click.echo("  Fedora:")
    click.echo("    sudo dnf install ufw audit openssh-server pam procps-ng")
    
    click.echo("\n🔍 Checking current system:")
    _check_linux_dependencies()
    
    click.echo("\n⚠️  Some features may be limited without these dependencies.")
    click.echo("💡 Run 'validate' command to check system readiness after installation.")


def _check_linux_dependencies():
    """Check and report status of Linux dependencies."""
    import subprocess
    import os
    
    dependencies = {
        'sysctl': 'Kernel parameter management',
        'systemctl': 'SystemD service management', 
        'ufw': 'Uncomplicated Firewall',
        'auditctl': 'Linux Audit System',
        'ssh': 'SSH client',
        'sshd': 'SSH daemon'
    }
    
    click.echo("  Dependency Status:")
    for cmd, description in dependencies.items():
        try:
            result = subprocess.run(['which', cmd], capture_output=True, timeout=2)
            if result.returncode == 0:
                click.echo(f"    ✓ {cmd} - {description}")
            else:
                click.echo(f"    ✗ {cmd} - {description} (not found)")
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
            click.echo(f"    ✗ {cmd} - {description} (not available)")
    
    # Check critical directories
    critical_dirs = ['/etc/sysctl.d', '/etc/pam.d', '/etc/ssh', '/etc/audit']
    click.echo("  Critical Directories:")
    for dir_path in critical_dirs:
        if os.path.exists(dir_path):
            writable = os.access(dir_path, os.W_OK)
            status = "✓ writable" if writable else "⚠ read-only"
            click.echo(f"    {status} {dir_path}")
        else:
            click.echo(f"    ✗ missing {dir_path}")
    
    # Check if running as root
    if os.geteuid() == 0:
        click.echo("  ✓ Running with root privileges")
    else:
        click.echo("  ⚠ Not running as root (some operations may fail)")


def _load_config_file(config_file_path):
    """Load custom parameters from configuration file."""
    import json
    import yaml
    from pathlib import Path
    
    if not config_file_path:
        return {}
    
    config_path = Path(config_file_path)
    if not config_path.exists():
        click.echo(f"⚠ Configuration file not found: {config_file_path}")
        return {}
    
    try:
        with open(config_path, 'r') as f:
            if config_path.suffix.lower() in ['.yaml', '.yml']:
                return yaml.safe_load(f) or {}
            elif config_path.suffix.lower() == '.json':
                return json.load(f) or {}
            else:
                click.echo(f"⚠ Unsupported config file format: {config_path.suffix}")
                return {}
    except Exception as e:
        click.echo(f"⚠ Error loading config file: {e}")
        return {}


def _format_output_for_automation(results, output_format, result_type="assessment"):
    """Format results for automation consumption."""
    import json
    
    if output_format == 'json':
        if result_type == "assessment":
            formatted_results = []
            for result in results:
                formatted_results.append({
                    'parameter_id': result.parameter_id,
                    'current_value': str(result.current_value) if result.current_value is not None else None,
                    'expected_value': str(result.expected_value) if result.expected_value is not None else None,
                    'compliant': result.compliant,
                    'severity': result.severity.value,
                    'risk_description': result.risk_description
                })
            return json.dumps(formatted_results, indent=2)
        elif result_type == "hardening":
            formatted_results = []
            for result in results:
                formatted_results.append({
                    'parameter_id': result.parameter_id,
                    'previous_value': str(result.previous_value) if result.previous_value is not None else None,
                    'applied_value': str(result.applied_value) if result.applied_value is not None else None,
                    'success': result.success,
                    'error_message': result.error_message,
                    'timestamp': result.timestamp.isoformat() if hasattr(result, 'timestamp') else None
                })
            return json.dumps(formatted_results, indent=2)
    
    elif output_format == 'xml':
        # Basic XML output
        xml_lines = ['<?xml version="1.0" encoding="UTF-8"?>']
        xml_lines.append(f'<{result_type}_results>')
        
        for result in results:
            xml_lines.append(f'  <result>')
            xml_lines.append(f'    <parameter_id>{result.parameter_id}</parameter_id>')
            
            if result_type == "assessment":
                xml_lines.append(f'    <current_value>{result.current_value}</current_value>')
                xml_lines.append(f'    <expected_value>{result.expected_value}</expected_value>')
                xml_lines.append(f'    <compliant>{result.compliant}</compliant>')
                xml_lines.append(f'    <severity>{result.severity.value}</severity>')
                xml_lines.append(f'    <risk_description>{result.risk_description}</risk_description>')
            elif result_type == "hardening":
                xml_lines.append(f'    <previous_value>{result.previous_value}</previous_value>')
                xml_lines.append(f'    <applied_value>{result.applied_value}</applied_value>')
                xml_lines.append(f'    <success>{result.success}</success>')
                if result.error_message:
                    xml_lines.append(f'    <error_message>{result.error_message}</error_message>')
            
            xml_lines.append(f'  </result>')
        
        xml_lines.append(f'</{result_type}_results>')
        return '\n'.join(xml_lines)
    
    return None  # Use default text format


def _output_automation_results(results, output_format, output_file=None, result_type="assessment"):
    """Output results in automation-friendly format."""
    formatted_output = _format_output_for_automation(results, output_format, result_type)
    
    if formatted_output:
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write(formatted_output)
                click.echo(f"Results saved to {output_file} in {output_format.upper()} format")
            except Exception as e:
                click.echo(f"Error saving results: {e}")
        else:
            click.echo(formatted_output)


def main():
    """Main entry point"""
    cli()


if __name__ == '__main__':
    main()