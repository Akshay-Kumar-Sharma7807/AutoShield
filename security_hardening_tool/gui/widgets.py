"""Custom GUI widgets for the security hardening tool."""

import tkinter as tk
from tkinter import ttk
from typing import Dict, List, Optional, Callable
from datetime import datetime

from ..core.models import (
    SystemInfo, OSInfo, Platform, Architecture, HardeningLevel,
    Parameter, AssessmentResult, HardeningResult, BackupData, Severity
)


class SystemInfoFrame(ttk.Frame):
    """Frame displaying system information."""
    
    def __init__(self, parent):
        super().__init__(parent)
        self._create_widgets()
    
    def _create_widgets(self):
        """Create system information widgets."""
        # Title
        title_label = ttk.Label(self, text="System Information", style='Title.TLabel')
        title_label.pack(anchor=tk.W, pady=(0, 10))
        
        # Info grid
        info_frame = ttk.Frame(self)
        info_frame.pack(fill=tk.BOTH, expand=True)
        
        # OS Information
        os_frame = ttk.LabelFrame(info_frame, text="Operating System")
        os_frame.grid(row=0, column=0, sticky="ew", padx=(0, 10), pady=(0, 10))
        
        self.os_platform_label = ttk.Label(os_frame, text="Platform: Not detected")
        self.os_platform_label.pack(anchor=tk.W, padx=10, pady=5)
        
        self.os_version_label = ttk.Label(os_frame, text="Version: Not detected")
        self.os_version_label.pack(anchor=tk.W, padx=10, pady=5)
        
        self.os_arch_label = ttk.Label(os_frame, text="Architecture: Not detected")
        self.os_arch_label.pack(anchor=tk.W, padx=10, pady=5)
        
        self.os_edition_label = ttk.Label(os_frame, text="Edition: Not detected")
        self.os_edition_label.pack(anchor=tk.W, padx=10, pady=5)
        
        # System Information
        sys_frame = ttk.LabelFrame(info_frame, text="System Details")
        sys_frame.grid(row=0, column=1, sticky="ew", padx=(10, 0), pady=(0, 10))
        
        self.hostname_label = ttk.Label(sys_frame, text="Hostname: Not detected")
        self.hostname_label.pack(anchor=tk.W, padx=10, pady=5)
        
        self.domain_label = ttk.Label(sys_frame, text="Domain: Not detected")
        self.domain_label.pack(anchor=tk.W, padx=10, pady=5)
        
        self.memory_label = ttk.Label(sys_frame, text="Memory: Not detected")
        self.memory_label.pack(anchor=tk.W, padx=10, pady=5)
        
        self.cpu_label = ttk.Label(sys_frame, text="CPU Cores: Not detected")
        self.cpu_label.pack(anchor=tk.W, padx=10, pady=5)
        
        # Configure grid weights
        info_frame.columnconfigure(0, weight=1)
        info_frame.columnconfigure(1, weight=1)
        
        # Status indicator
        self.status_frame = ttk.Frame(self)
        self.status_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.status_label = ttk.Label(
            self.status_frame, 
            text="System information not loaded", 
            style='Status.TLabel'
        )
        self.status_label.pack(side=tk.LEFT)
        
        self.refresh_button = ttk.Button(
            self.status_frame, 
            text="Refresh", 
            command=self._refresh_info
        )
        self.refresh_button.pack(side=tk.RIGHT)
    
    def update_system_info(self, system_info: SystemInfo):
        """Update display with system information."""
        os_info = system_info.os_info
        
        # Update OS information
        self.os_platform_label.config(text=f"Platform: {os_info.platform.value.title()}")
        self.os_version_label.config(text=f"Version: {os_info.version}")
        self.os_arch_label.config(text=f"Architecture: {os_info.architecture.value}")
        
        edition_text = f"Edition: {os_info.edition}" if os_info.edition else "Edition: Standard"
        self.os_edition_label.config(text=edition_text)
        
        # Update system information
        self.hostname_label.config(text=f"Hostname: {system_info.hostname}")
        
        domain_text = f"Domain: {system_info.domain}" if system_info.domain else "Domain: Workgroup"
        self.domain_label.config(text=domain_text)
        
        if system_info.total_memory:
            memory_gb = system_info.total_memory / (1024**3)
            self.memory_label.config(text=f"Memory: {memory_gb:.1f} GB")
        else:
            self.memory_label.config(text="Memory: Not available")
        
        cpu_text = f"CPU Cores: {system_info.cpu_count}" if system_info.cpu_count else "CPU Cores: Not available"
        self.cpu_label.config(text=cpu_text)
        
        # Update status
        self.status_label.config(text="System information loaded successfully", style='Success.TLabel')
    
    def _refresh_info(self):
        """Refresh system information."""
        # This will be connected to the main window's refresh method
        pass


class HardeningLevelFrame(ttk.Frame):
    """Frame for selecting hardening level."""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.selected_level = tk.StringVar(value=HardeningLevel.MODERATE.value)
        self._create_widgets()
    
    def _create_widgets(self):
        """Create hardening level selection widgets."""
        # Title
        title_label = ttk.Label(self, text="Hardening Level", style='Subtitle.TLabel')
        title_label.pack(anchor=tk.W, pady=(0, 5))
        
        # Radio buttons
        levels_frame = ttk.Frame(self)
        levels_frame.pack(fill=tk.X)
        
        # Basic level
        basic_frame = ttk.Frame(levels_frame)
        basic_frame.pack(fill=tk.X, pady=2)
        
        basic_radio = ttk.Radiobutton(
            basic_frame, 
            text="Basic", 
            variable=self.selected_level, 
            value=HardeningLevel.BASIC.value
        )
        basic_radio.pack(side=tk.LEFT)
        
        basic_desc = ttk.Label(
            basic_frame, 
            text="Essential security settings with minimal impact",
            style='Status.TLabel'
        )
        basic_desc.pack(side=tk.LEFT, padx=(10, 0))
        
        # Moderate level
        moderate_frame = ttk.Frame(levels_frame)
        moderate_frame.pack(fill=tk.X, pady=2)
        
        moderate_radio = ttk.Radiobutton(
            moderate_frame, 
            text="Moderate", 
            variable=self.selected_level, 
            value=HardeningLevel.MODERATE.value
        )
        moderate_radio.pack(side=tk.LEFT)
        
        moderate_desc = ttk.Label(
            moderate_frame, 
            text="Recommended security settings for most environments",
            style='Status.TLabel'
        )
        moderate_desc.pack(side=tk.LEFT, padx=(10, 0))
        
        # Strict level
        strict_frame = ttk.Frame(levels_frame)
        strict_frame.pack(fill=tk.X, pady=2)
        
        strict_radio = ttk.Radiobutton(
            strict_frame, 
            text="Strict", 
            variable=self.selected_level, 
            value=HardeningLevel.STRICT.value
        )
        strict_radio.pack(side=tk.LEFT)
        
        strict_desc = ttk.Label(
            strict_frame, 
            text="Maximum security settings for high-security environments",
            style='Status.TLabel'
        )
        strict_desc.pack(side=tk.LEFT, padx=(10, 0))
    
    def get_selected_level(self) -> HardeningLevel:
        """Get the selected hardening level."""
        return HardeningLevel(self.selected_level.get())


class ParameterCustomizationFrame(ttk.Frame):
    """Frame for customizing parameters."""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.custom_parameters: Dict[str, any] = {}
        self._create_widgets()
    
    def _create_widgets(self):
        """Create parameter customization widgets."""
        # Title
        title_label = ttk.Label(self, text="Parameter Customization", style='Subtitle.TLabel')
        title_label.pack(anchor=tk.W, pady=(0, 5))
        
        # Controls frame
        controls_frame = ttk.Frame(self)
        controls_frame.pack(fill=tk.X)
        
        self.load_custom_button = ttk.Button(
            controls_frame, 
            text="Load Custom Parameters...", 
            command=self._load_custom_parameters
        )
        self.load_custom_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.clear_custom_button = ttk.Button(
            controls_frame, 
            text="Clear Custom", 
            command=self._clear_custom_parameters
        )
        self.clear_custom_button.pack(side=tk.LEFT)
        
        # Status
        self.custom_status_label = ttk.Label(
            controls_frame, 
            text="No custom parameters loaded",
            style='Status.TLabel'
        )
        self.custom_status_label.pack(side=tk.RIGHT)
    
    def _load_custom_parameters(self):
        """Load custom parameters from file."""
        # This will be implemented to load from JSON/YAML file
        pass
    
    def _clear_custom_parameters(self):
        """Clear custom parameters."""
        self.custom_parameters.clear()
        self.custom_status_label.config(text="No custom parameters loaded")
    
    def get_custom_parameters(self) -> Dict[str, any]:
        """Get custom parameters."""
        return self.custom_parameters.copy()


class ProgressFrame(ttk.Frame):
    """Frame for displaying operation progress."""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.is_visible = False
        self._create_widgets()
    
    def _create_widgets(self):
        """Create progress widgets."""
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            self, 
            variable=self.progress_var, 
            maximum=100
        )
        self.progress_bar.pack(fill=tk.X, pady=(0, 5))
        
        # Status and details frame
        status_frame = ttk.Frame(self)
        status_frame.pack(fill=tk.X)
        
        self.status_label = ttk.Label(status_frame, text="Ready", style='Status.TLabel')
        self.status_label.pack(side=tk.LEFT)
        
        self.details_label = ttk.Label(status_frame, text="", style='Status.TLabel')
        self.details_label.pack(side=tk.RIGHT)
        
        # Cancel button
        self.cancel_button = ttk.Button(
            status_frame, 
            text="Cancel", 
            command=self._cancel_operation
        )
        # Cancel button will be packed when operation starts
    
    def show(self):
        """Show the progress frame."""
        if not self.is_visible:
            self.pack(fill=tk.X, pady=(10, 0))
            self.is_visible = True
    
    def hide(self):
        """Hide the progress frame."""
        if self.is_visible:
            self.pack_forget()
            self.is_visible = False
    
    def update_progress(self, percentage: float, status: str, details: str = ""):
        """Update progress display."""
        self.progress_var.set(percentage)
        self.status_label.config(text=status)
        self.details_label.config(text=details)
    
    def set_indeterminate(self, status: str):
        """Set progress bar to indeterminate mode."""
        self.progress_bar.config(mode='indeterminate')
        self.progress_bar.start()
        self.status_label.config(text=status)
    
    def set_determinate(self):
        """Set progress bar to determinate mode."""
        self.progress_bar.stop()
        self.progress_bar.config(mode='determinate')
    
    def _cancel_operation(self):
        """Cancel current operation."""
        # This will be connected to the main window's cancel method
        pass


class StatusFrame(ttk.Frame):
    """Status bar frame."""
    
    def __init__(self, parent):
        super().__init__(parent, relief=tk.SUNKEN, borderwidth=1)
        self._create_widgets()
    
    def _create_widgets(self):
        """Create status bar widgets."""
        self.status_label = ttk.Label(self, text="Ready", style='Status.TLabel')
        self.status_label.pack(side=tk.LEFT, padx=5, pady=2)
        
        # Separator
        separator = ttk.Separator(self, orient=tk.VERTICAL)
        separator.pack(side=tk.RIGHT, fill=tk.Y, padx=5)
        
        # Time label
        self.time_label = ttk.Label(self, text="", style='Status.TLabel')
        self.time_label.pack(side=tk.RIGHT, padx=5, pady=2)
        
        # Update time periodically
        self._update_time()
    
    def set_status(self, message: str, style: str = 'Status.TLabel'):
        """Set status message."""
        self.status_label.config(text=message, style=style)
    
    def _update_time(self):
        """Update time display."""
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.config(text=current_time)
        self.after(1000, self._update_time)  # Update every second


def create_severity_style(severity: Severity) -> str:
    """Get style name for severity level."""
    severity_styles = {
        Severity.CRITICAL: 'Critical.TLabel',
        Severity.HIGH: 'High.TLabel',
        Severity.MEDIUM: 'Medium.TLabel',
        Severity.LOW: 'Low.TLabel',
        Severity.INFO: 'Info.TLabel'
    }
    return severity_styles.get(severity, 'Status.TLabel')


def format_timestamp(timestamp: datetime) -> str:
    """Format timestamp for display."""
    return timestamp.strftime("%Y-%m-%d %H:%M:%S")


def format_file_size(size_bytes: int) -> str:
    """Format file size for display."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"