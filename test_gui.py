#!/usr/bin/env python3
"""Test script for the GUI interface."""

import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_gui_imports():
    """Test that GUI components can be imported."""
    try:
        from security_hardening_tool.gui.main_window import MainWindow
        from security_hardening_tool.gui.widgets import SystemInfoFrame
        from security_hardening_tool.gui.dialogs import AssessmentDetailsDialog
        from security_hardening_tool.gui.launcher import GUILauncher
        print("✅ All GUI components imported successfully")
        return True
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def test_gui_dependencies():
    """Test GUI dependencies."""
    try:
        import tkinter
        print("✅ tkinter is available")
        return True
    except ImportError:
        print("❌ tkinter is not available")
        return False

def test_cli_gui_command():
    """Test that GUI command is available in CLI."""
    try:
        from security_hardening_tool.cli.main import cli
        # Check if gui command is registered
        commands = [cmd.name for cmd in cli.commands.values()]
        if 'gui' in commands:
            print("✅ GUI command is registered in CLI")
            return True
        else:
            print("❌ GUI command not found in CLI")
            return False
    except Exception as e:
        print(f"❌ Error checking CLI: {e}")
        return False

if __name__ == "__main__":
    print("Testing GUI Implementation")
    print("=" * 40)
    
    all_tests_passed = True
    
    # Test imports
    print("\n1. Testing GUI imports...")
    all_tests_passed &= test_gui_imports()
    
    # Test dependencies
    print("\n2. Testing GUI dependencies...")
    all_tests_passed &= test_gui_dependencies()
    
    # Test CLI integration
    print("\n3. Testing CLI integration...")
    all_tests_passed &= test_cli_gui_command()
    
    print("\n" + "=" * 40)
    if all_tests_passed:
        print("✅ All tests passed! GUI implementation is ready.")
        print("\nTo launch the GUI:")
        print("  python -m security_hardening_tool.cli.main gui")
    else:
        print("❌ Some tests failed. Please check the implementation.")
        sys.exit(1)