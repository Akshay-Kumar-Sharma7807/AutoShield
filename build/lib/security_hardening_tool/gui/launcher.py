"""GUI launcher for the security hardening tool."""

import sys
import tkinter as tk
from tkinter import messagebox
import logging
from typing import Optional

from ..core.engine import HardeningEngine
from ..core.os_detector import OSDetector
from ..core.config_manager import ConfigurationManager
from ..core.backup_manager import BackupManager
from ..core.report_engine import PDFReportEngine
from ..core.logger import AuditLogger
from ..core.interfaces import ErrorHandler
from ..core.models import OperationResult
from ..modules.windows.windows_module import WindowsHardeningModule
from ..modules.linux.linux_module import LinuxHardeningModule
from .main_window import MainWindow


class SimpleErrorHandler(ErrorHandler):
    """Simple error handler implementation for GUI."""
    
    def handle_error(self, error: Exception) -> OperationResult:
        """Handle and categorize errors."""
        return OperationResult(success=False, message=str(error))
    
    def suggest_remediation(self, error: Exception) -> list:
        """Suggest remediation steps for errors."""
        return [f"Error occurred: {str(error)}"]
    
    def attempt_recovery(self, error: Exception) -> bool:
        """Attempt automatic error recovery."""
        return False


class GUILauncher:
    """Launcher for the GUI application."""
    
    def __init__(self):
        """Initialize the GUI launcher."""
        self.engine: Optional[HardeningEngine] = None
        self.main_window: Optional[MainWindow] = None
    
    def check_gui_dependencies(self) -> bool:
        """Check if GUI dependencies are available."""
        try:
            import tkinter
            return True
        except ImportError:
            return False
    
    def initialize_engine(self) -> bool:
        """Initialize the hardening engine with all components."""
        try:
            # Initialize core components
            os_detector = OSDetector()
            config_manager = ConfigurationManager()
            backup_manager = BackupManager()
            report_engine = PDFReportEngine()
            logger = AuditLogger()
            error_handler = SimpleErrorHandler()
            
            # Create engine
            self.engine = HardeningEngine(
                os_detector=os_detector,
                config_manager=config_manager,
                backup_manager=backup_manager,
                report_engine=report_engine,
                logger=logger,
                error_handler=error_handler
            )
            
            # Register hardening modules
            try:
                windows_module = WindowsHardeningModule()
                self.engine.register_hardening_module("windows", windows_module)
            except Exception as e:
                logging.warning(f"Failed to register Windows module: {e}")
            
            try:
                linux_module = LinuxHardeningModule()
                self.engine.register_hardening_module("linux", linux_module)
            except Exception as e:
                logging.warning(f"Failed to register Linux module: {e}")
            
            return True
            
        except Exception as e:
            logging.error(f"Failed to initialize engine: {e}")
            return False
    
    def show_error_dialog(self, title: str, message: str):
        """Show error dialog without main window."""
        root = tk.Tk()
        root.withdraw()  # Hide the root window
        messagebox.showerror(title, message)
        root.destroy()
    
    def launch(self) -> int:
        """Launch the GUI application."""
        # Check GUI dependencies
        if not self.check_gui_dependencies():
            print("Error: GUI dependencies not available. Please install tkinter.")
            return 1
        
        # Initialize engine
        if not self.initialize_engine():
            self.show_error_dialog(
                "Initialization Error",
                "Failed to initialize the hardening engine. Please check the logs for details."
            )
            return 1
        
        # Check if any hardening modules are available
        if not self.engine.get_registered_platforms():
            self.show_error_dialog(
                "No Modules Available",
                "No hardening modules are available. The application cannot function without platform-specific modules."
            )
            return 1
        
        try:
            # Create and run main window
            self.main_window = MainWindow(self.engine)
            self.main_window.run()
            return 0
            
        except Exception as e:
            logging.error(f"GUI application error: {e}")
            self.show_error_dialog(
                "Application Error",
                f"An error occurred while running the application:\n{str(e)}"
            )
            return 1
    
    def cleanup(self):
        """Cleanup resources."""
        if self.main_window:
            try:
                self.main_window.root.quit()
            except:
                pass


def main():
    """Main entry point for GUI launcher."""
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create and run launcher
    launcher = GUILauncher()
    
    try:
        exit_code = launcher.launch()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\nApplication interrupted by user.")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)
    finally:
        launcher.cleanup()


if __name__ == "__main__":
    main()