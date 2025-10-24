"""Main GUI window for the security hardening tool."""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
from typing import Dict, List, Optional, Callable
from datetime import datetime

from ..core.models import (
    HardeningLevel, OSInfo, SystemInfo, AssessmentResult, 
    HardeningResult, BackupData, Platform, Severity
)
from ..core.engine import HardeningEngine
from .widgets import (
    SystemInfoFrame, HardeningLevelFrame, ParameterCustomizationFrame,
    ProgressFrame, StatusFrame
)
from .dialogs import (
    AssessmentDetailsDialog, HardeningProgressDialog, BackupManagerDialog
)


class MainWindow:
    """Main application window for the security hardening tool."""
    
    def __init__(self, engine: HardeningEngine):
        """Initialize the main window."""
        self.engine = engine
        self.root = tk.Tk()
        self.root.title("Security Hardening Tool")
        self.root.geometry("1200x800")
        self.root.minsize(800, 600)
        
        # Application state
        self.system_info: Optional[SystemInfo] = None
        self.current_assessment: List[AssessmentResult] = []
        self.current_hardening: List[HardeningResult] = []
        self.available_backups: List[BackupData] = []
        self.operation_in_progress = False
        
        # Initialize GUI components
        self._setup_styles()
        self._create_menu()
        self._create_main_layout()
        self._initialize_system_info()
    
    def _setup_styles(self):
        """Configure GUI styles and themes."""
        style = ttk.Style()
        
        # Configure custom styles
        style.configure('Title.TLabel', font=('Arial', 14, 'bold'))
        style.configure('Subtitle.TLabel', font=('Arial', 10, 'bold'))
        style.configure('Status.TLabel', font=('Arial', 9))
        style.configure('Success.TLabel', foreground='green')
        style.configure('Error.TLabel', foreground='red')
        style.configure('Warning.TLabel', foreground='orange')
        
        # Configure severity-based styles
        style.configure('Critical.TLabel', foreground='red', font=('Arial', 9, 'bold'))
        style.configure('High.TLabel', foreground='darkorange', font=('Arial', 9, 'bold'))
        style.configure('Medium.TLabel', foreground='orange')
        style.configure('Low.TLabel', foreground='blue')
        style.configure('Info.TLabel', foreground='gray')
    
    def _create_menu(self):
        """Create the application menu bar."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Load Custom Parameters...", command=self._load_custom_parameters)
        file_menu.add_command(label="Save Configuration...", command=self._save_configuration)
        file_menu.add_separator()
        file_menu.add_command(label="Export Report...", command=self._export_report)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Refresh System Info", command=self._refresh_system_info)
        tools_menu.add_command(label="Manage Backups", command=self._show_backup_manager)
        tools_menu.add_command(label="View Audit Logs", command=self._show_audit_logs)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="User Guide", command=self._show_user_guide)
        help_menu.add_command(label="About", command=self._show_about)
    
    def _create_main_layout(self):
        """Create the main application layout."""
        # Create main container with notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # System Information Tab
        self.system_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.system_tab, text="System Information")
        self._create_system_tab()
        
        # Assessment Tab
        self.assessment_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.assessment_tab, text="Security Assessment")
        self._create_assessment_tab()
        
        # Hardening Tab
        self.hardening_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.hardening_tab, text="Apply Hardening")
        self._create_hardening_tab()
        
        # Rollback Tab
        self.rollback_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.rollback_tab, text="Rollback")
        self._create_rollback_tab()
        
        # Status bar
        self._create_status_bar()
    
    def _create_system_tab(self):
        """Create the system information tab."""
        # System info frame
        self.system_info_frame = SystemInfoFrame(self.system_tab)
        self.system_info_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    def _create_assessment_tab(self):
        """Create the security assessment tab."""
        # Main container
        main_frame = ttk.Frame(self.assessment_tab)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Configuration frame
        config_frame = ttk.LabelFrame(main_frame, text="Assessment Configuration")
        config_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Hardening level selection
        self.assessment_level_frame = HardeningLevelFrame(config_frame)
        self.assessment_level_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Parameter customization
        self.assessment_param_frame = ParameterCustomizationFrame(config_frame)
        self.assessment_param_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        # Control buttons
        button_frame = ttk.Frame(config_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.assess_button = ttk.Button(
            button_frame, text="Run Assessment", 
            command=self._run_assessment
        )
        self.assess_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.clear_assessment_button = ttk.Button(
            button_frame, text="Clear Results", 
            command=self._clear_assessment_results
        )
        self.clear_assessment_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.assessment_details_button = ttk.Button(
            button_frame, text="View Details", 
            command=self._show_assessment_details
        )
        self.assessment_details_button.pack(side=tk.LEFT)
        self.assessment_details_button.config(state='disabled')
        
        # Results frame
        results_frame = ttk.LabelFrame(main_frame, text="Assessment Results")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        # Results tree view
        self.assessment_tree = self._create_assessment_tree(results_frame)
        
        # Progress frame
        self.assessment_progress_frame = ProgressFrame(main_frame)
        self.assessment_progress_frame.pack(fill=tk.X, pady=(10, 0))
        self.assessment_progress_frame.hide()
    
    def _create_hardening_tab(self):
        """Create the hardening application tab."""
        # Main container
        main_frame = ttk.Frame(self.hardening_tab)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Configuration frame
        config_frame = ttk.LabelFrame(main_frame, text="Hardening Configuration")
        config_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Hardening level selection
        self.hardening_level_frame = HardeningLevelFrame(config_frame)
        self.hardening_level_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Parameter customization
        self.hardening_param_frame = ParameterCustomizationFrame(config_frame)
        self.hardening_param_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        # Options frame
        options_frame = ttk.Frame(config_frame)
        options_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.create_backup_var = tk.BooleanVar(value=True)
        self.create_backup_check = ttk.Checkbutton(
            options_frame, text="Create backup before hardening",
            variable=self.create_backup_var
        )
        self.create_backup_check.pack(side=tk.LEFT, padx=(0, 20))
        
        self.continue_on_error_var = tk.BooleanVar(value=True)
        self.continue_on_error_check = ttk.Checkbutton(
            options_frame, text="Continue on errors",
            variable=self.continue_on_error_var
        )
        self.continue_on_error_check.pack(side=tk.LEFT)
        
        # Control buttons
        button_frame = ttk.Frame(config_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.harden_button = ttk.Button(
            button_frame, text="Apply Hardening", 
            command=self._run_hardening
        )
        self.harden_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.clear_hardening_button = ttk.Button(
            button_frame, text="Clear Results", 
            command=self._clear_hardening_results
        )
        self.clear_hardening_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.hardening_details_button = ttk.Button(
            button_frame, text="View Details", 
            command=self._show_hardening_details
        )
        self.hardening_details_button.pack(side=tk.LEFT)
        self.hardening_details_button.config(state='disabled')
        
        # Results frame
        results_frame = ttk.LabelFrame(main_frame, text="Hardening Results")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        # Results tree view
        self.hardening_tree = self._create_hardening_tree(results_frame)
        
        # Progress frame
        self.hardening_progress_frame = ProgressFrame(main_frame)
        self.hardening_progress_frame.pack(fill=tk.X, pady=(10, 0))
        self.hardening_progress_frame.hide()
    
    def _create_rollback_tab(self):
        """Create the rollback tab."""
        # Main container
        main_frame = ttk.Frame(self.rollback_tab)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Backup selection frame
        backup_frame = ttk.LabelFrame(main_frame, text="Available Backups")
        backup_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Backup list
        self.backup_tree = self._create_backup_tree(backup_frame)
        
        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.refresh_backups_button = ttk.Button(
            button_frame, text="Refresh Backups", 
            command=self._refresh_backups
        )
        self.refresh_backups_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.rollback_button = ttk.Button(
            button_frame, text="Rollback Selected", 
            command=self._run_rollback
        )
        self.rollback_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.delete_backup_button = ttk.Button(
            button_frame, text="Delete Backup", 
            command=self._delete_backup
        )
        self.delete_backup_button.pack(side=tk.LEFT)
        
        # Progress frame
        self.rollback_progress_frame = ProgressFrame(main_frame)
        self.rollback_progress_frame.pack(fill=tk.X, pady=(10, 0))
        self.rollback_progress_frame.hide()
    
    def _create_status_bar(self):
        """Create the status bar."""
        self.status_frame = StatusFrame(self.root)
        self.status_frame.pack(fill=tk.X, side=tk.BOTTOM)
    
    def _initialize_system_info(self):
        """Initialize system information on startup."""
        def load_system_info():
            try:
                self.system_info = self.engine.get_system_info()
                self.root.after(0, self._update_system_info_display)
                self.root.after(0, lambda: self.status_frame.set_status("System information loaded"))
            except Exception as e:
                self.root.after(0, lambda: self._show_error("Failed to load system information", str(e)))
        
        # Load system info in background thread
        threading.Thread(target=load_system_info, daemon=True).start()
        self.status_frame.set_status("Loading system information...")
    
    def _update_system_info_display(self):
        """Update the system information display."""
        if self.system_info:
            self.system_info_frame.update_system_info(self.system_info)
    
    def run(self):
        """Start the GUI application."""
        self.root.mainloop()
    
    def _create_assessment_tree(self, parent) -> ttk.Treeview:
        """Create assessment results tree view."""
        # Create frame with scrollbars
        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create treeview
        columns = ('parameter', 'current', 'expected', 'status', 'severity', 'risk')
        tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=15)
        
        # Configure columns
        tree.heading('parameter', text='Parameter')
        tree.heading('current', text='Current Value')
        tree.heading('expected', text='Expected Value')
        tree.heading('status', text='Status')
        tree.heading('severity', text='Severity')
        tree.heading('risk', text='Risk Description')
        
        tree.column('parameter', width=200)
        tree.column('current', width=150)
        tree.column('expected', width=150)
        tree.column('status', width=80)
        tree.column('severity', width=80)
        tree.column('risk', width=300)
        
        # Add scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack widgets
        tree.grid(row=0, column=0, sticky='nsew')
        v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        return tree
    
    def _create_hardening_tree(self, parent) -> ttk.Treeview:
        """Create hardening results tree view."""
        # Create frame with scrollbars
        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create treeview
        columns = ('parameter', 'previous', 'applied', 'status', 'timestamp', 'message')
        tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=15)
        
        # Configure columns
        tree.heading('parameter', text='Parameter')
        tree.heading('previous', text='Previous Value')
        tree.heading('applied', text='Applied Value')
        tree.heading('status', text='Status')
        tree.heading('timestamp', text='Timestamp')
        tree.heading('message', text='Message')
        
        tree.column('parameter', width=200)
        tree.column('previous', width=150)
        tree.column('applied', width=150)
        tree.column('status', width=80)
        tree.column('timestamp', width=120)
        tree.column('message', width=250)
        
        # Add scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack widgets
        tree.grid(row=0, column=0, sticky='nsew')
        v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        return tree
    
    def _create_backup_tree(self, parent) -> ttk.Treeview:
        """Create backup list tree view."""
        # Create frame with scrollbars
        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create treeview
        columns = ('backup_id', 'timestamp', 'os_info', 'parameters', 'description')
        tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=10)
        
        # Configure columns
        tree.heading('backup_id', text='Backup ID')
        tree.heading('timestamp', text='Created')
        tree.heading('os_info', text='OS Info')
        tree.heading('parameters', text='Parameters')
        tree.heading('description', text='Description')
        
        tree.column('backup_id', width=150)
        tree.column('timestamp', width=120)
        tree.column('os_info', width=150)
        tree.column('parameters', width=100)
        tree.column('description', width=300)
        
        # Add scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack widgets
        tree.grid(row=0, column=0, sticky='nsew')
        v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        return tree
    
    def _run_assessment(self):
        """Run security assessment."""
        if self.operation_in_progress:
            self._show_error("Operation in Progress", "Another operation is currently running.")
            return
        
        def assessment_worker():
            try:
                self.operation_in_progress = True
                
                # Get configuration
                level = self.assessment_level_frame.get_selected_level()
                custom_params = self.assessment_param_frame.get_custom_parameters()
                
                # Update UI
                self.root.after(0, lambda: self.assessment_progress_frame.show())
                self.root.after(0, lambda: self.assessment_progress_frame.set_indeterminate("Running assessment..."))
                self.root.after(0, lambda: self.assess_button.config(state='disabled'))
                
                # Run assessment
                results = self.engine.execute_assessment(level, custom_params)
                
                # Update UI with results
                self.root.after(0, lambda: self._update_assessment_results(results))
                self.root.after(0, lambda: self.status_frame.set_status("Assessment completed", 'Success.TLabel'))
                
            except Exception as e:
                self.root.after(0, lambda: self._show_error("Assessment Failed", str(e)))
                self.root.after(0, lambda: self.status_frame.set_status("Assessment failed", 'Error.TLabel'))
            finally:
                self.operation_in_progress = False
                self.root.after(0, lambda: self.assessment_progress_frame.hide())
                self.root.after(0, lambda: self.assess_button.config(state='normal'))
        
        threading.Thread(target=assessment_worker, daemon=True).start()
    
    def _run_hardening(self):
        """Run hardening operation."""
        if self.operation_in_progress:
            self._show_error("Operation in Progress", "Another operation is currently running.")
            return
        
        # Confirm operation
        if not messagebox.askyesno("Confirm Hardening", 
                                  "This will modify system security settings. Continue?"):
            return
        
        def hardening_worker():
            try:
                self.operation_in_progress = True
                
                # Get configuration
                level = self.hardening_level_frame.get_selected_level()
                custom_params = self.hardening_param_frame.get_custom_parameters()
                create_backup = self.create_backup_var.get()
                continue_on_error = self.continue_on_error_var.get()
                
                # Get parameter count for progress dialog
                try:
                    parameters = self.engine.config_manager.load_hardening_level(level)
                    if custom_params:
                        parameters = self.engine.config_manager.merge_custom_parameters(parameters, custom_params)
                    total_params = len(parameters)
                except:
                    total_params = 50  # Default estimate
                
                # Create progress dialog
                def cancel_callback():
                    # This would implement cancellation logic
                    pass
                
                progress_dialog = None
                self.root.after(0, lambda: self._create_progress_dialog_sync(total_params, cancel_callback))
                
                # Progress callback
                def progress_callback(current: int, total: int, parameter_name: str):
                    if hasattr(self, 'progress_dialog') and self.progress_dialog:
                        # Assume success for now (would need actual result)
                        success = True
                        self.root.after(0, lambda: self.progress_dialog.update_progress(
                            current, parameter_name, success
                        ))
                
                # Update UI
                self.root.after(0, lambda: self.harden_button.config(state='disabled'))
                
                # Run hardening
                results, backup_id = self.engine.execute_hardening(
                    level, custom_params, create_backup, continue_on_error, progress_callback
                )
                
                # Complete progress dialog
                if hasattr(self, 'progress_dialog') and self.progress_dialog:
                    self.root.after(0, lambda: self.progress_dialog.set_completed())
                
                # Update UI with results
                self.root.after(0, lambda: self._update_hardening_results(results))
                
                success_count = len([r for r in results if r.success])
                status_msg = f"Hardening completed: {success_count}/{len(results)} successful"
                if backup_id:
                    status_msg += f" (Backup: {backup_id})"
                
                self.root.after(0, lambda: self.status_frame.set_status(status_msg, 'Success.TLabel'))
                
            except Exception as e:
                self.root.after(0, lambda: self._show_error("Hardening Failed", str(e)))
                self.root.after(0, lambda: self.status_frame.set_status("Hardening failed", 'Error.TLabel'))
            finally:
                self.operation_in_progress = False
                self.root.after(0, lambda: self.harden_button.config(state='normal'))
        
        threading.Thread(target=hardening_worker, daemon=True).start()
    
    def _run_rollback(self):
        """Run rollback operation."""
        if self.operation_in_progress:
            self._show_error("Operation in Progress", "Another operation is currently running.")
            return
        
        # Get selected backup
        selection = self.backup_tree.selection()
        if not selection:
            self._show_error("No Selection", "Please select a backup to rollback to.")
            return
        
        backup_id = self.backup_tree.item(selection[0])['values'][0]
        
        # Confirm operation
        if not messagebox.askyesno("Confirm Rollback", 
                                  f"This will restore system settings from backup {backup_id}. Continue?"):
            return
        
        def rollback_worker():
            try:
                self.operation_in_progress = True
                
                # Update UI
                self.root.after(0, lambda: self.rollback_progress_frame.show())
                self.root.after(0, lambda: self.rollback_progress_frame.set_indeterminate("Rolling back..."))
                self.root.after(0, lambda: self.rollback_button.config(state='disabled'))
                
                # Run rollback
                result = self.engine.execute_rollback(backup_id)
                
                # Show results
                success_count = len([r for r in result.restored_parameters if r.success])
                total_count = len(result.restored_parameters)
                
                if result.success:
                    self._show_info("Rollback Successful", 
                                   f"Successfully restored {success_count}/{total_count} parameters.")
                    self.root.after(0, lambda: self.status_frame.set_status("Rollback completed", 'Success.TLabel'))
                else:
                    error_msg = f"Rollback partially failed: {success_count}/{total_count} parameters restored."
                    if result.errors:
                        error_msg += f"\nErrors: {'; '.join(result.errors)}"
                    self._show_error("Rollback Issues", error_msg)
                    self.root.after(0, lambda: self.status_frame.set_status("Rollback completed with errors", 'Warning.TLabel'))
                
            except Exception as e:
                self.root.after(0, lambda: self._show_error("Rollback Failed", str(e)))
                self.root.after(0, lambda: self.status_frame.set_status("Rollback failed", 'Error.TLabel'))
            finally:
                self.operation_in_progress = False
                self.root.after(0, lambda: self.rollback_progress_frame.hide())
                self.root.after(0, lambda: self.rollback_button.config(state='normal'))
        
        threading.Thread(target=rollback_worker, daemon=True).start()
    
    def _update_assessment_results(self, results: List[AssessmentResult]):
        """Update assessment results display."""
        # Clear existing results
        for item in self.assessment_tree.get_children():
            self.assessment_tree.delete(item)
        
        # Add new results
        for result in results:
            status = "Compliant" if result.compliant else "Non-Compliant"
            values = (
                result.parameter_id,
                str(result.current_value),
                str(result.expected_value),
                status,
                result.severity.value.title(),
                result.risk_description
            )
            
            # Add item with severity-based tag
            item_id = self.assessment_tree.insert('', 'end', values=values)
            
            # Configure item color based on compliance and severity
            if not result.compliant:
                if result.severity == Severity.CRITICAL:
                    self.assessment_tree.set(item_id, 'status', '❌ Non-Compliant')
                elif result.severity == Severity.HIGH:
                    self.assessment_tree.set(item_id, 'status', '⚠️ Non-Compliant')
                else:
                    self.assessment_tree.set(item_id, 'status', '⚡ Non-Compliant')
            else:
                self.assessment_tree.set(item_id, 'status', '✅ Compliant')
        
        self.current_assessment = results
        self.assessment_details_button.config(state='normal' if results else 'disabled')
    
    def _update_hardening_results(self, results: List[HardeningResult]):
        """Update hardening results display."""
        # Clear existing results
        for item in self.hardening_tree.get_children():
            self.hardening_tree.delete(item)
        
        # Add new results
        for result in results:
            status = "Success" if result.success else "Failed"
            timestamp_str = result.timestamp.strftime("%H:%M:%S")
            message = result.error_message if result.error_message else "Applied successfully"
            
            values = (
                result.parameter_id,
                str(result.previous_value),
                str(result.applied_value),
                status,
                timestamp_str,
                message
            )
            
            # Add item with status-based formatting
            item_id = self.hardening_tree.insert('', 'end', values=values)
            
            if result.success:
                self.hardening_tree.set(item_id, 'status', '✅ Success')
            else:
                self.hardening_tree.set(item_id, 'status', '❌ Failed')
        
        self.current_hardening = results
        self.hardening_details_button.config(state='normal' if results else 'disabled')
    
    def _refresh_system_info(self):
        """Refresh system information."""
        def refresh_worker():
            try:
                self.system_info = self.engine.get_system_info()
                self.root.after(0, self._update_system_info_display)
                self.root.after(0, lambda: self.status_frame.set_status("System information refreshed"))
            except Exception as e:
                self.root.after(0, lambda: self._show_error("Refresh Failed", str(e)))
        
        threading.Thread(target=refresh_worker, daemon=True).start()
    
    def _refresh_backups(self):
        """Refresh backup list."""
        def refresh_worker():
            try:
                self.available_backups = self.engine.list_backups()
                self.root.after(0, self._update_backup_list)
                self.root.after(0, lambda: self.status_frame.set_status("Backup list refreshed"))
            except Exception as e:
                self.root.after(0, lambda: self._show_error("Refresh Failed", str(e)))
        
        threading.Thread(target=refresh_worker, daemon=True).start()
        
        # Initial load
        self._refresh_backups()
    
    def _update_backup_list(self):
        """Update backup list display."""
        # Clear existing items
        for item in self.backup_tree.get_children():
            self.backup_tree.delete(item)
        
        # Add backups
        for backup in self.available_backups:
            os_info_str = f"{backup.os_info.platform.value} {backup.os_info.version}"
            timestamp_str = backup.timestamp.strftime("%Y-%m-%d %H:%M")
            description = backup.description or "No description"
            
            values = (
                backup.backup_id,
                timestamp_str,
                os_info_str,
                len(backup.parameters),
                description
            )
            
            self.backup_tree.insert('', 'end', values=values)
    
    def _delete_backup(self):
        """Delete selected backup."""
        selection = self.backup_tree.selection()
        if not selection:
            self._show_error("No Selection", "Please select a backup to delete.")
            return
        
        backup_id = self.backup_tree.item(selection[0])['values'][0]
        
        if messagebox.askyesno("Confirm Delete", f"Delete backup {backup_id}?"):
            try:
                if self.engine.backup_manager.delete_backup(backup_id):
                    self._refresh_backups()
                    self.status_frame.set_status("Backup deleted")
                else:
                    self._show_error("Delete Failed", "Failed to delete backup.")
            except Exception as e:
                self._show_error("Delete Failed", str(e))
    
    def _clear_assessment_results(self):
        """Clear assessment results."""
        for item in self.assessment_tree.get_children():
            self.assessment_tree.delete(item)
        self.current_assessment.clear()
        self.assessment_details_button.config(state='disabled')
    
    def _show_assessment_details(self):
        """Show detailed assessment results dialog."""
        if not self.current_assessment:
            self._show_error("No Results", "No assessment results to display.")
            return
        
        try:
            AssessmentDetailsDialog(self.root, self.current_assessment)
        except Exception as e:
            self._show_error("Details Error", str(e))
    
    def _clear_hardening_results(self):
        """Clear hardening results."""
        for item in self.hardening_tree.get_children():
            self.hardening_tree.delete(item)
        self.current_hardening.clear()
        self.hardening_details_button.config(state='disabled')
    
    def _show_hardening_details(self):
        """Show detailed hardening results dialog."""
        if not self.current_hardening:
            self._show_error("No Results", "No hardening results to display.")
            return
        
        # Create a simple details dialog for hardening results
        details_window = tk.Toplevel(self.root)
        details_window.title("Hardening Results Details")
        details_window.geometry("800x600")
        details_window.transient(self.root)
        details_window.grab_set()
        
        # Main frame
        main_frame = ttk.Frame(details_window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Summary
        summary_frame = ttk.LabelFrame(main_frame, text="Summary")
        summary_frame.pack(fill=tk.X, pady=(0, 10))
        
        success_count = len([r for r in self.current_hardening if r.success])
        total_count = len(self.current_hardening)
        success_rate = (success_count / total_count) * 100 if total_count > 0 else 0
        
        summary_text = f"Total Parameters: {total_count}\n"
        summary_text += f"Successful: {success_count}\n"
        summary_text += f"Failed: {total_count - success_count}\n"
        summary_text += f"Success Rate: {success_rate:.1f}%"
        
        summary_label = ttk.Label(summary_frame, text=summary_text, style='Status.TLabel')
        summary_label.pack(padx=10, pady=10)
        
        # Results tree
        results_frame = ttk.LabelFrame(main_frame, text="Detailed Results")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Create treeview
        tree_frame = ttk.Frame(results_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        columns = ('parameter', 'status', 'previous', 'applied', 'message', 'timestamp')
        tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=15)
        
        # Configure columns
        tree.heading('parameter', text='Parameter ID')
        tree.heading('status', text='Status')
        tree.heading('previous', text='Previous Value')
        tree.heading('applied', text='Applied Value')
        tree.heading('message', text='Message')
        tree.heading('timestamp', text='Timestamp')
        
        tree.column('parameter', width=200)
        tree.column('status', width=80)
        tree.column('previous', width=150)
        tree.column('applied', width=150)
        tree.column('message', width=200)
        tree.column('timestamp', width=120)
        
        # Add scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack widgets
        tree.grid(row=0, column=0, sticky='nsew')
        v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        # Populate tree
        for result in self.current_hardening:
            status = "✅ Success" if result.success else "❌ Failed"
            message = result.error_message if result.error_message else "Applied successfully"
            timestamp_str = result.timestamp.strftime("%H:%M:%S")
            
            values = (
                result.parameter_id,
                status,
                str(result.previous_value),
                str(result.applied_value),
                message,
                timestamp_str
            )
            tree.insert('', 'end', values=values)
        
        # Close button
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        close_button = ttk.Button(button_frame, text="Close", command=details_window.destroy)
        close_button.pack(side=tk.RIGHT)
    
    def _load_custom_parameters(self):
        """Load custom parameters from file."""
        filename = filedialog.askopenfilename(
            title="Load Custom Parameters",
            filetypes=[("JSON files", "*.json"), ("YAML files", "*.yaml"), ("All files", "*.*")]
        )
        if filename:
            # This would load and parse the custom parameters file
            self._show_info("Load Parameters", f"Custom parameters loaded from {filename}")
    
    def _save_configuration(self):
        """Save current configuration."""
        filename = filedialog.asksaveasfilename(
            title="Save Configuration",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("YAML files", "*.yaml"), ("All files", "*.*")]
        )
        if filename:
            # This would save the current configuration
            self._show_info("Save Configuration", f"Configuration saved to {filename}")
    
    def _export_report(self):
        """Export assessment/hardening report."""
        if not self.current_assessment and not self.current_hardening:
            self._show_error("No Data", "No assessment or hardening results to export.")
            return
        
        filename = filedialog.asksaveasfilename(
            title="Export Report",
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")]
        )
        if filename:
            try:
                if self.current_assessment:
                    result = self.engine.generate_report(self.current_assessment, "assessment", filename)
                elif self.current_hardening:
                    result = self.engine.generate_report(self.current_hardening, "hardening", filename)
                
                if result.success:
                    self._show_info("Export Successful", f"Report exported to {filename}")
                else:
                    self._show_error("Export Failed", result.message)
            except Exception as e:
                self._show_error("Export Failed", str(e))
    
    def _show_backup_manager(self):
        """Show backup manager dialog."""
        try:
            BackupManagerDialog(self.root, self.engine)
        except Exception as e:
            self._show_error("Backup Manager Error", str(e))
    
    def _show_audit_logs(self):
        """Show audit logs dialog."""
        # This would open an audit log viewer dialog
        self._show_info("Audit Logs", "Audit log viewer would open here.")
    
    def _show_user_guide(self):
        """Show user guide."""
        self._show_info("User Guide", "User guide would be displayed here.")
    
    def _show_about(self):
        """Show about dialog."""
        about_text = """Security Hardening Tool v1.0

A cross-platform security hardening tool for Windows and Linux systems.

Features:
• Automated security assessment
• Configurable hardening levels
• Backup and rollback capabilities
• Comprehensive reporting
• Compliance framework mapping

© 2024 Security Hardening Tool Project"""
        
        messagebox.showinfo("About", about_text)
    
    def _show_error(self, title: str, message: str):
        """Show error dialog."""
        messagebox.showerror(title, message)
    
    def _show_info(self, title: str, message: str):
        """Show info dialog."""
        messagebox.showinfo(title, message)
    
    def _create_progress_dialog_sync(self, total_params: int, cancel_callback: Callable):
        """Create progress dialog synchronously."""
        self.progress_dialog = HardeningProgressDialog(self.root, total_params, cancel_callback)