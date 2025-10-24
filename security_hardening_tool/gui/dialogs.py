"""Dialog windows for the security hardening tool GUI."""

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Dict, List, Optional, Callable
from datetime import datetime

from ..core.models import (
    AssessmentResult, HardeningResult, BackupData, Parameter, 
    Severity, Platform, OSInfo
)
from .widgets import create_severity_style, format_timestamp


class AssessmentDetailsDialog:
    """Dialog for displaying detailed assessment results."""
    
    def __init__(self, parent, results: List[AssessmentResult]):
        """Initialize the assessment details dialog."""
        self.parent = parent
        self.results = results
        self.dialog = None
        self.filtered_results = results.copy()
        
        # Filter variables
        self.severity_filter = tk.StringVar(value="All")
        self.compliance_filter = tk.StringVar(value="All")
        self.search_var = tk.StringVar()
        
        self._create_dialog()
    
    def _create_dialog(self):
        """Create the dialog window."""
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title("Assessment Results Details")
        self.dialog.geometry("1000x700")
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        
        # Main frame
        main_frame = ttk.Frame(self.dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Filter frame
        self._create_filter_frame(main_frame)
        
        # Results frame
        self._create_results_frame(main_frame)
        
        # Button frame
        self._create_button_frame(main_frame)
        
        # Initial population
        self._apply_filters()
    
    def _create_filter_frame(self, parent):
        """Create the filter controls."""
        filter_frame = ttk.LabelFrame(parent, text="Filters")
        filter_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Filter controls row
        controls_frame = ttk.Frame(filter_frame)
        controls_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Search
        ttk.Label(controls_frame, text="Search:").pack(side=tk.LEFT)
        search_entry = ttk.Entry(controls_frame, textvariable=self.search_var, width=20)
        search_entry.pack(side=tk.LEFT, padx=(5, 20))
        search_entry.bind('<KeyRelease>', lambda e: self._apply_filters())
        
        # Severity filter
        ttk.Label(controls_frame, text="Severity:").pack(side=tk.LEFT)
        severity_combo = ttk.Combobox(
            controls_frame, 
            textvariable=self.severity_filter,
            values=["All", "Critical", "High", "Medium", "Low", "Info"],
            state="readonly",
            width=10
        )
        severity_combo.pack(side=tk.LEFT, padx=(5, 20))
        severity_combo.bind('<<ComboboxSelected>>', lambda e: self._apply_filters())
        
        # Compliance filter
        ttk.Label(controls_frame, text="Status:").pack(side=tk.LEFT)
        compliance_combo = ttk.Combobox(
            controls_frame,
            textvariable=self.compliance_filter,
            values=["All", "Compliant", "Non-Compliant"],
            state="readonly",
            width=12
        )
        compliance_combo.pack(side=tk.LEFT, padx=(5, 20))
        compliance_combo.bind('<<ComboboxSelected>>', lambda e: self._apply_filters())
        
        # Clear filters button
        clear_button = ttk.Button(
            controls_frame, 
            text="Clear Filters", 
            command=self._clear_filters
        )
        clear_button.pack(side=tk.RIGHT)
    
    def _create_results_frame(self, parent):
        """Create the results display."""
        results_frame = ttk.LabelFrame(parent, text="Results")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Create treeview with scrollbars
        tree_frame = ttk.Frame(results_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        columns = ('parameter', 'current', 'expected', 'status', 'severity', 'risk')
        self.tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=20)
        
        # Configure columns
        self.tree.heading('parameter', text='Parameter ID')
        self.tree.heading('current', text='Current Value')
        self.tree.heading('expected', text='Expected Value')
        self.tree.heading('status', text='Status')
        self.tree.heading('severity', text='Severity')
        self.tree.heading('risk', text='Risk Description')
        
        self.tree.column('parameter', width=200)
        self.tree.column('current', width=150)
        self.tree.column('expected', width=150)
        self.tree.column('status', width=100)
        self.tree.column('severity', width=80)
        self.tree.column('risk', width=300)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack widgets
        self.tree.grid(row=0, column=0, sticky='nsew')
        v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        # Bind double-click for details
        self.tree.bind('<Double-1>', self._show_parameter_details)
        
        # Summary label
        self.summary_label = ttk.Label(results_frame, text="", style='Status.TLabel')
        self.summary_label.pack(pady=(0, 10))
    
    def _create_button_frame(self, parent):
        """Create the button controls."""
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill=tk.X)
        
        # Export button
        export_button = ttk.Button(
            button_frame, 
            text="Export Filtered Results", 
            command=self._export_results
        )
        export_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # Close button
        close_button = ttk.Button(
            button_frame, 
            text="Close", 
            command=self.dialog.destroy
        )
        close_button.pack(side=tk.RIGHT)
    
    def _apply_filters(self):
        """Apply current filters to the results."""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Apply filters
        search_text = self.search_var.get().lower()
        severity_filter = self.severity_filter.get()
        compliance_filter = self.compliance_filter.get()
        
        self.filtered_results = []
        
        for result in self.results:
            # Apply search filter
            if search_text and search_text not in result.parameter_id.lower():
                continue
            
            # Apply severity filter
            if severity_filter != "All" and result.severity.value.title() != severity_filter:
                continue
            
            # Apply compliance filter
            if compliance_filter == "Compliant" and not result.compliant:
                continue
            elif compliance_filter == "Non-Compliant" and result.compliant:
                continue
            
            self.filtered_results.append(result)
        
        # Populate tree with filtered results
        for result in self.filtered_results:
            status = "✅ Compliant" if result.compliant else "❌ Non-Compliant"
            values = (
                result.parameter_id,
                str(result.current_value),
                str(result.expected_value),
                status,
                result.severity.value.title(),
                result.risk_description
            )
            self.tree.insert('', 'end', values=values)
        
        # Update summary
        total_filtered = len(self.filtered_results)
        compliant_filtered = sum(1 for r in self.filtered_results if r.compliant)
        
        if total_filtered > 0:
            compliance_rate = (compliant_filtered / total_filtered) * 100
            summary_text = f"Showing {total_filtered} of {len(self.results)} results | "
            summary_text += f"Compliance: {compliant_filtered}/{total_filtered} ({compliance_rate:.1f}%)"
        else:
            summary_text = f"No results match current filters (Total: {len(self.results)})"
        
        self.summary_label.config(text=summary_text)
    
    def _clear_filters(self):
        """Clear all filters."""
        self.search_var.set("")
        self.severity_filter.set("All")
        self.compliance_filter.set("All")
        self._apply_filters()
    
    def _show_parameter_details(self, event):
        """Show detailed information for selected parameter."""
        selection = self.tree.selection()
        if not selection:
            return
        
        item = self.tree.item(selection[0])
        parameter_id = item['values'][0]
        
        # Find the result
        result = next((r for r in self.filtered_results if r.parameter_id == parameter_id), None)
        if result:
            ParameterDetailsDialog(self.dialog, result)
    
    def _export_results(self):
        """Export filtered results."""
        # This would implement export functionality
        messagebox.showinfo("Export", f"Would export {len(self.filtered_results)} filtered results")


class ParameterDetailsDialog:
    """Dialog for displaying detailed parameter information."""
    
    def __init__(self, parent, result: AssessmentResult):
        """Initialize the parameter details dialog."""
        self.parent = parent
        self.result = result
        self.dialog = None
        
        self._create_dialog()
    
    def _create_dialog(self):
        """Create the dialog window."""
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title(f"Parameter Details: {self.result.parameter_id}")
        self.dialog.geometry("600x500")
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        
        # Main frame with scrollbar
        canvas = tk.Canvas(self.dialog)
        scrollbar = ttk.Scrollbar(self.dialog, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Content
        self._create_content(scrollable_frame)
        
        # Pack scrollable components
        canvas.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        scrollbar.pack(side="right", fill="y", pady=10)
        
        # Close button
        button_frame = ttk.Frame(self.dialog)
        button_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        close_button = ttk.Button(button_frame, text="Close", command=self.dialog.destroy)
        close_button.pack(side=tk.RIGHT)
    
    def _create_content(self, parent):
        """Create the content for parameter details."""
        # Title
        title_label = ttk.Label(parent, text=self.result.parameter_id, style='Title.TLabel')
        title_label.pack(anchor=tk.W, pady=(0, 10))
        
        # Status
        status_frame = ttk.Frame(parent)
        status_frame.pack(fill=tk.X, pady=(0, 10))
        
        status_text = "✅ COMPLIANT" if self.result.compliant else "❌ NON-COMPLIANT"
        status_style = 'Success.TLabel' if self.result.compliant else 'Error.TLabel'
        
        ttk.Label(status_frame, text="Status:", style='Subtitle.TLabel').pack(side=tk.LEFT)
        ttk.Label(status_frame, text=status_text, style=status_style).pack(side=tk.LEFT, padx=(10, 0))
        
        # Severity
        severity_frame = ttk.Frame(parent)
        severity_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(severity_frame, text="Severity:", style='Subtitle.TLabel').pack(side=tk.LEFT)
        severity_style = create_severity_style(self.result.severity)
        ttk.Label(severity_frame, text=self.result.severity.value.title(), style=severity_style).pack(side=tk.LEFT, padx=(10, 0))
        
        # Values section
        values_frame = ttk.LabelFrame(parent, text="Values")
        values_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Current value
        current_frame = ttk.Frame(values_frame)
        current_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(current_frame, text="Current Value:", style='Subtitle.TLabel').pack(anchor=tk.W)
        current_text = tk.Text(current_frame, height=3, wrap=tk.WORD)
        current_text.insert('1.0', str(self.result.current_value))
        current_text.config(state=tk.DISABLED)
        current_text.pack(fill=tk.X, pady=(5, 0))
        
        # Expected value
        expected_frame = ttk.Frame(values_frame)
        expected_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(expected_frame, text="Expected Value:", style='Subtitle.TLabel').pack(anchor=tk.W)
        expected_text = tk.Text(expected_frame, height=3, wrap=tk.WORD)
        expected_text.insert('1.0', str(self.result.expected_value))
        expected_text.config(state=tk.DISABLED)
        expected_text.pack(fill=tk.X, pady=(5, 0))
        
        # Risk description
        risk_frame = ttk.LabelFrame(parent, text="Risk Description")
        risk_frame.pack(fill=tk.X, pady=(0, 10))
        
        risk_text = tk.Text(risk_frame, height=4, wrap=tk.WORD)
        risk_text.insert('1.0', self.result.risk_description)
        risk_text.config(state=tk.DISABLED)
        risk_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Remediation steps
        if self.result.remediation_steps:
            remediation_frame = ttk.LabelFrame(parent, text="Remediation Steps")
            remediation_frame.pack(fill=tk.X, pady=(0, 10))
            
            for i, step in enumerate(self.result.remediation_steps, 1):
                step_frame = ttk.Frame(remediation_frame)
                step_frame.pack(fill=tk.X, padx=10, pady=2)
                
                ttk.Label(step_frame, text=f"{i}.", style='Subtitle.TLabel').pack(side=tk.LEFT, anchor=tk.N)
                
                step_text = tk.Text(step_frame, height=2, wrap=tk.WORD)
                step_text.insert('1.0', step)
                step_text.config(state=tk.DISABLED)
                step_text.pack(fill=tk.X, side=tk.LEFT, padx=(5, 0))
        
        # Timestamp
        timestamp_frame = ttk.Frame(parent)
        timestamp_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Label(timestamp_frame, text="Assessment Time:", style='Subtitle.TLabel').pack(side=tk.LEFT)
        timestamp_text = format_timestamp(self.result.timestamp)
        ttk.Label(timestamp_frame, text=timestamp_text, style='Status.TLabel').pack(side=tk.LEFT, padx=(10, 0))


class HardeningProgressDialog:
    """Dialog for displaying real-time hardening progress."""
    
    def __init__(self, parent, total_parameters: int, cancel_callback: Optional[Callable] = None):
        """Initialize the hardening progress dialog."""
        self.parent = parent
        self.total_parameters = total_parameters
        self.cancel_callback = cancel_callback
        self.dialog = None
        self.cancelled = False
        
        # Progress tracking
        self.current_parameter = 0
        self.successful_parameters = 0
        self.failed_parameters = 0
        
        self._create_dialog()
    
    def _create_dialog(self):
        """Create the progress dialog."""
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title("Applying Hardening Configuration")
        self.dialog.geometry("500x300")
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        
        # Prevent closing during operation
        self.dialog.protocol("WM_DELETE_WINDOW", self._on_close_attempt)
        
        # Main frame
        main_frame = ttk.Frame(self.dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        title_label = ttk.Label(main_frame, text="Applying Security Hardening", style='Title.TLabel')
        title_label.pack(pady=(0, 20))
        
        # Overall progress
        progress_frame = ttk.LabelFrame(main_frame, text="Overall Progress")
        progress_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.overall_progress = ttk.Progressbar(progress_frame, mode='determinate')
        self.overall_progress.pack(fill=tk.X, padx=10, pady=10)
        
        self.progress_label = ttk.Label(progress_frame, text="Preparing...", style='Status.TLabel')
        self.progress_label.pack(pady=(0, 10))
        
        # Current parameter
        current_frame = ttk.LabelFrame(main_frame, text="Current Parameter")
        current_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.current_label = ttk.Label(current_frame, text="Initializing...", style='Status.TLabel')
        self.current_label.pack(padx=10, pady=10)
        
        # Statistics
        stats_frame = ttk.LabelFrame(main_frame, text="Statistics")
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(padx=10, pady=10)
        
        ttk.Label(stats_grid, text="Successful:", style='Subtitle.TLabel').grid(row=0, column=0, sticky=tk.W)
        self.success_label = ttk.Label(stats_grid, text="0", style='Success.TLabel')
        self.success_label.grid(row=0, column=1, padx=(10, 20), sticky=tk.W)
        
        ttk.Label(stats_grid, text="Failed:", style='Subtitle.TLabel').grid(row=0, column=2, sticky=tk.W)
        self.failed_label = ttk.Label(stats_grid, text="0", style='Error.TLabel')
        self.failed_label.grid(row=0, column=3, padx=(10, 0), sticky=tk.W)
        
        # Cancel button
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.cancel_button = ttk.Button(
            button_frame, 
            text="Cancel Operation", 
            command=self._cancel_operation
        )
        self.cancel_button.pack(side=tk.RIGHT)
    
    def update_progress(self, current: int, parameter_name: str, success: bool):
        """Update progress display."""
        if self.cancelled:
            return
        
        self.current_parameter = current
        
        if success:
            self.successful_parameters += 1
        else:
            self.failed_parameters += 1
        
        # Update progress bar
        progress_percentage = (current / self.total_parameters) * 100
        self.overall_progress['value'] = progress_percentage
        
        # Update labels
        self.progress_label.config(text=f"Processing {current}/{self.total_parameters} ({progress_percentage:.1f}%)")
        self.current_label.config(text=parameter_name)
        self.success_label.config(text=str(self.successful_parameters))
        self.failed_label.config(text=str(self.failed_parameters))
        
        # Update display
        self.dialog.update()
    
    def set_completed(self):
        """Mark operation as completed."""
        self.progress_label.config(text="Hardening completed!")
        self.current_label.config(text="Operation finished")
        self.cancel_button.config(text="Close", command=self.dialog.destroy)
        
        # Allow closing
        self.dialog.protocol("WM_DELETE_WINDOW", self.dialog.destroy)
    
    def _cancel_operation(self):
        """Cancel the hardening operation."""
        if self.cancel_callback and not self.cancelled:
            if messagebox.askyesno("Cancel Operation", "Are you sure you want to cancel the hardening operation?"):
                self.cancelled = True
                self.cancel_callback()
                self.progress_label.config(text="Cancelling operation...")
                self.cancel_button.config(state='disabled')
    
    def _on_close_attempt(self):
        """Handle attempt to close dialog during operation."""
        if not self.cancelled:
            self._cancel_operation()
        else:
            self.dialog.destroy()


class BackupManagerDialog:
    """Dialog for managing backups."""
    
    def __init__(self, parent, engine):
        """Initialize the backup manager dialog."""
        self.parent = parent
        self.engine = engine
        self.dialog = None
        self.backups = []
        
        self._create_dialog()
        self._refresh_backups()
    
    def _create_dialog(self):
        """Create the backup manager dialog."""
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title("Backup Manager")
        self.dialog.geometry("800x600")
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        
        # Main frame
        main_frame = ttk.Frame(self.dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Backup list
        list_frame = ttk.LabelFrame(main_frame, text="Available Backups")
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Create treeview
        columns = ('backup_id', 'timestamp', 'os_info', 'parameters', 'size', 'description')
        self.tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)
        
        # Configure columns
        self.tree.heading('backup_id', text='Backup ID')
        self.tree.heading('timestamp', text='Created')
        self.tree.heading('os_info', text='OS Info')
        self.tree.heading('parameters', text='Parameters')
        self.tree.heading('size', text='Size')
        self.tree.heading('description', text='Description')
        
        self.tree.column('backup_id', width=150)
        self.tree.column('timestamp', width=120)
        self.tree.column('os_info', width=120)
        self.tree.column('parameters', width=80)
        self.tree.column('size', width=80)
        self.tree.column('description', width=200)
        
        # Scrollbars
        tree_frame = ttk.Frame(list_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        v_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        self.tree.grid(row=0, column=0, sticky='nsew')
        v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        refresh_button = ttk.Button(button_frame, text="Refresh", command=self._refresh_backups)
        refresh_button.pack(side=tk.LEFT, padx=(0, 10))
        
        details_button = ttk.Button(button_frame, text="View Details", command=self._view_details)
        details_button.pack(side=tk.LEFT, padx=(0, 10))
        
        verify_button = ttk.Button(button_frame, text="Verify Integrity", command=self._verify_backup)
        verify_button.pack(side=tk.LEFT, padx=(0, 10))
        
        delete_button = ttk.Button(button_frame, text="Delete", command=self._delete_backup)
        delete_button.pack(side=tk.LEFT, padx=(0, 10))
        
        close_button = ttk.Button(button_frame, text="Close", command=self.dialog.destroy)
        close_button.pack(side=tk.RIGHT)
    
    def _refresh_backups(self):
        """Refresh the backup list."""
        try:
            self.backups = self.engine.list_backups()
            
            # Clear existing items
            for item in self.tree.get_children():
                self.tree.delete(item)
            
            # Add backups
            for backup in self.backups:
                os_info_str = f"{backup.os_info.platform.value} {backup.os_info.version}"
                timestamp_str = format_timestamp(backup.timestamp)
                description = backup.description or "No description"
                
                # Calculate approximate size (placeholder)
                size_str = "N/A"  # Would calculate actual size
                
                values = (
                    backup.backup_id,
                    timestamp_str,
                    os_info_str,
                    len(backup.parameters),
                    size_str,
                    description
                )
                
                self.tree.insert('', 'end', values=values)
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh backups: {e}")
    
    def _view_details(self):
        """View details of selected backup."""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a backup to view details.")
            return
        
        backup_id = self.tree.item(selection[0])['values'][0]
        backup = next((b for b in self.backups if b.backup_id == backup_id), None)
        
        if backup:
            BackupDetailsDialog(self.dialog, backup)
    
    def _verify_backup(self):
        """Verify integrity of selected backup."""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a backup to verify.")
            return
        
        backup_id = self.tree.item(selection[0])['values'][0]
        
        try:
            is_valid = self.engine.backup_manager.verify_backup_integrity(backup_id)
            if is_valid:
                messagebox.showinfo("Verification", f"Backup {backup_id} integrity verified successfully.")
            else:
                messagebox.showerror("Verification Failed", f"Backup {backup_id} failed integrity check.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to verify backup: {e}")
    
    def _delete_backup(self):
        """Delete selected backup."""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a backup to delete.")
            return
        
        backup_id = self.tree.item(selection[0])['values'][0]
        
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete backup {backup_id}?"):
            try:
                if self.engine.backup_manager.delete_backup(backup_id):
                    self._refresh_backups()
                    messagebox.showinfo("Success", "Backup deleted successfully.")
                else:
                    messagebox.showerror("Error", "Failed to delete backup.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete backup: {e}")


class BackupDetailsDialog:
    """Dialog for displaying backup details."""
    
    def __init__(self, parent, backup: BackupData):
        """Initialize the backup details dialog."""
        self.parent = parent
        self.backup = backup
        self.dialog = None
        
        self._create_dialog()
    
    def _create_dialog(self):
        """Create the backup details dialog."""
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title(f"Backup Details: {self.backup.backup_id}")
        self.dialog.geometry("600x500")
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        
        # Main frame with scrollbar
        canvas = tk.Canvas(self.dialog)
        scrollbar = ttk.Scrollbar(self.dialog, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Content
        self._create_content(scrollable_frame)
        
        # Pack scrollable components
        canvas.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        scrollbar.pack(side="right", fill="y", pady=10)
        
        # Close button
        button_frame = ttk.Frame(self.dialog)
        button_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        close_button = ttk.Button(button_frame, text="Close", command=self.dialog.destroy)
        close_button.pack(side=tk.RIGHT)
    
    def _create_content(self, parent):
        """Create the content for backup details."""
        # Basic information
        info_frame = ttk.LabelFrame(parent, text="Backup Information")
        info_frame.pack(fill=tk.X, pady=(0, 10))
        
        info_grid = ttk.Frame(info_frame)
        info_grid.pack(padx=10, pady=10)
        
        # Backup ID
        ttk.Label(info_grid, text="Backup ID:", style='Subtitle.TLabel').grid(row=0, column=0, sticky=tk.W)
        ttk.Label(info_grid, text=self.backup.backup_id).grid(row=0, column=1, sticky=tk.W, padx=(10, 0))
        
        # Timestamp
        ttk.Label(info_grid, text="Created:", style='Subtitle.TLabel').grid(row=1, column=0, sticky=tk.W)
        timestamp_text = format_timestamp(self.backup.timestamp)
        ttk.Label(info_grid, text=timestamp_text).grid(row=1, column=1, sticky=tk.W, padx=(10, 0))
        
        # OS Info
        ttk.Label(info_grid, text="OS Info:", style='Subtitle.TLabel').grid(row=2, column=0, sticky=tk.W)
        os_text = f"{self.backup.os_info.platform.value} {self.backup.os_info.version}"
        ttk.Label(info_grid, text=os_text).grid(row=2, column=1, sticky=tk.W, padx=(10, 0))
        
        # Parameter count
        ttk.Label(info_grid, text="Parameters:", style='Subtitle.TLabel').grid(row=3, column=0, sticky=tk.W)
        ttk.Label(info_grid, text=str(len(self.backup.parameters))).grid(row=3, column=1, sticky=tk.W, padx=(10, 0))
        
        # Description
        if self.backup.description:
            desc_frame = ttk.LabelFrame(parent, text="Description")
            desc_frame.pack(fill=tk.X, pady=(0, 10))
            
            desc_text = tk.Text(desc_frame, height=3, wrap=tk.WORD)
            desc_text.insert('1.0', self.backup.description)
            desc_text.config(state=tk.DISABLED)
            desc_text.pack(fill=tk.X, padx=10, pady=10)
        
        # Parameters list
        params_frame = ttk.LabelFrame(parent, text="Backed Up Parameters")
        params_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create listbox with scrollbar
        listbox_frame = ttk.Frame(params_frame)
        listbox_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        params_listbox = tk.Listbox(listbox_frame)
        params_scrollbar = ttk.Scrollbar(listbox_frame, orient=tk.VERTICAL, command=params_listbox.yview)
        params_listbox.configure(yscrollcommand=params_scrollbar.set)
        
        # Add parameters
        for param in self.backup.parameters:
            params_listbox.insert(tk.END, f"{param.parameter_id}: {param.original_value}")
        
        params_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        params_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)