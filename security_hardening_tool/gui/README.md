# Security Hardening Tool - GUI Interface

This directory contains the graphical user interface (GUI) implementation for the Security Hardening Tool.

## Overview

The GUI provides an intuitive, user-friendly interface for system administrators and security professionals to:

- Assess current security posture
- Apply security hardening configurations
- Manage backups and rollback operations
- Generate compliance reports
- View detailed results and progress

## Components

### Main Window (`main_window.py`)
The primary application window with tabbed interface:
- **System Information**: Displays detected OS and system details
- **Security Assessment**: Run security assessments with filtering and detailed views
- **Apply Hardening**: Configure and apply security hardening with real-time progress
- **Rollback**: Manage backups and perform rollback operations

### Widgets (`widgets.py`)
Reusable GUI components:
- `SystemInfoFrame`: System information display
- `HardeningLevelFrame`: Hardening level selection (Basic/Moderate/Strict)
- `ParameterCustomizationFrame`: Custom parameter configuration
- `ProgressFrame`: Operation progress tracking
- `StatusFrame`: Application status bar

### Dialogs (`dialogs.py`)
Specialized dialog windows:
- `AssessmentDetailsDialog`: Detailed assessment results with filtering
- `ParameterDetailsDialog`: Individual parameter information
- `HardeningProgressDialog`: Real-time hardening progress
- `BackupManagerDialog`: Backup management and verification
- `BackupDetailsDialog`: Detailed backup information

### Launcher (`launcher.py`)
GUI application launcher with:
- Dependency checking
- Engine initialization
- Error handling
- Module registration

## Features

### Assessment Workflow
1. Select hardening level (Basic, Moderate, Strict)
2. Optionally load custom parameters
3. Run assessment with real-time progress
4. View results with severity indicators
5. Filter and search results
6. Export detailed reports

### Hardening Workflow
1. Configure hardening level and options
2. Enable/disable backup creation
3. Set error handling preferences
4. Apply hardening with progress tracking
5. View success/failure results
6. Generate compliance reports

### Backup Management
1. View all available backups
2. Verify backup integrity
3. Select backup points for rollback
4. Delete outdated backups
5. View backup details and parameters

## Usage

### Launching the GUI

From command line:
```bash
python -m security_hardening_tool.cli.main gui
```

Or programmatically:
```python
from security_hardening_tool.gui.launcher import GUILauncher

launcher = GUILauncher()
launcher.launch()
```

### Requirements

- Python 3.7+
- tkinter (usually included with Python)
- All core security hardening tool dependencies

### Platform Support

The GUI is designed to work on:
- Windows 10/11
- Linux (Ubuntu 20.04+, CentOS 7+)
- Any platform with tkinter support

## Architecture

The GUI follows a modular architecture:

```
GUI Layer
├── Main Window (Tabbed Interface)
├── Specialized Dialogs
├── Reusable Widgets
└── Launcher

Core Integration
├── Hardening Engine
├── Assessment Engine
├── Backup Manager
├── Report Engine
└── Configuration Manager
```

## Error Handling

The GUI includes comprehensive error handling:
- User-friendly error messages
- Graceful degradation for missing dependencies
- Operation cancellation support
- Progress tracking with error recovery

## Accessibility

The interface includes:
- Clear visual indicators for status
- Severity-based color coding
- Comprehensive tooltips and help text
- Keyboard navigation support
- Resizable windows and components

## Future Enhancements

Potential improvements:
- Dark theme support
- Advanced filtering options
- Scheduled operations
- Multi-system management
- Plugin architecture for custom modules