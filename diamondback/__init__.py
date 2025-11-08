import os
import sys
import importlib
import pkgutil
import inspect
import logging
from pathlib import Path
from types import ModuleType
from typing import Dict, List, Any, Optional, Callable, Set

# Configure logging
logger = logging.getLogger(__name__)

# Store loaded modules
_modules: Dict[str, ModuleType] = {}
_classes: Dict[str, type] = {}
_functions: Dict[str, Callable] = {}

class LazyModuleLoader:
    """
    Lazy module loader that only imports modules when accessed.
    Good for large packages where not all modules are always needed.
    """
    
    def __init__(self, module_name: str):
        self._module_name = module_name
        self._module = None
    
    def __getattr__(self, name):
        if self._module is None:
            self._module = importlib.import_module(self._module_name)
            logger.debug(f"Lazy loaded: {self._module_name}")
        return getattr(self._module, name)
    
    def __repr__(self):
        return f"<LazyModule '{self._module_name}'>"

def setup_lazy_loading():
    """
    Set up lazy loading for all modules in the package.
    """
    package_dir = Path(__file__).parent
    package_name = __name__
    
    for py_file in package_dir.rglob("*.py"):
        if py_file.name.startswith("_"):
            continue
        
        relative_path = py_file.relative_to(package_dir)
        module_path = str(relative_path.with_suffix(""))
        module_name = f"{package_name}.{module_path.replace(os.sep, '.')}"
        
        # Create lazy loader
        short_name = Path(module_path).stem
        globals()[short_name] = LazyModuleLoader(module_name)

def load_all_modules_pkgutil():
    """
    Use pkgutil to load all modules in the package.
    This is the standard library approach.
    """
    package_dir = Path(__file__).parent
    package_name = __name__
    
    # Walk through all modules in the package
    for importer, modname, ispkg in pkgutil.walk_packages(
        path=[str(package_dir)],
        prefix=f"{package_name}.",
        onerror=lambda name: logger.error(f"Error importing {name}")
    ):
        try:
            module = importlib.import_module(modname)
            _modules[modname] = module
            logger.debug(f"Loaded {'package' if ispkg else 'module'}: {modname}")
        except Exception as e:
            logger.error(f"Failed to import {modname}: {e}")


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_all_classes(base_class: Optional[type] = None) -> Dict[str, type]:
    """
    Get all loaded classes, optionally filtered by base class.
    """
    if base_class is None:
        return _classes.copy()
    
    return {
        name: cls for name, cls in _classes.items()
        if issubclass(cls, base_class)
    }


def get_all_functions() -> Dict[str, Callable]:
    """Get all loaded functions."""
    return _functions.copy()


def get_all_modules() -> Dict[str, ModuleType]:
    """Get all loaded modules."""
    return _modules.copy()


def reload_all():
    """Reload all loaded modules."""
    for module in _modules.values():
        importlib.reload(module)
    logger.info(f"Reloaded {len(_modules)} modules")


def find_plugins(plugin_base_class: type) -> Dict[str, type]:
    """
    Find all plugin classes that inherit from a base class.
    Useful for plugin architectures.
    """
    plugins = {}
    
    for name, cls in _classes.items():
        if cls != plugin_base_class and issubclass(cls, plugin_base_class):
            plugins[name] = cls
            logger.debug(f"Found plugin: {name}")
    
    return plugins


class ModuleLoader:
    """
    Advanced module loader with filtering, configuration, and auto-discovery.
    """
    
    def __init__(self, 
                 package_path: Optional[Path] = None,
                 package_name: Optional[str] = None,
                 recursive: bool = True,
                 include_private: bool = False,
                 exclude_patterns: Optional[List[str]] = None,
                 include_patterns: Optional[List[str]] = None,
                 auto_register: bool = True,
                 load_classes: bool = True,
                 load_functions: bool = True,
                 base_class: Optional[type] = None):
        """
        Initialize the module loader.
        
        Args:
            package_path: Path to the package directory (defaults to current)
            package_name: Name of the package (defaults to __name__)
            recursive: Whether to search subdirectories
            include_private: Whether to include modules starting with _
            exclude_patterns: List of patterns to exclude (e.g., ['test_*', '*_old'])
            include_patterns: List of patterns to include (e.g., ['plugin_*'])
            auto_register: Whether to automatically register discovered items
            load_classes: Whether to extract and register classes
            load_functions: Whether to extract and register functions
            base_class: If specified, only load classes that inherit from this
        """
        self.package_path = package_path or Path(__file__).parent
        self.package_name = package_name or __name__
        self.recursive = recursive
        self.include_private = include_private
        self.exclude_patterns = exclude_patterns or ['test_*', '*_test', '__pycache__']
        self.include_patterns = include_patterns or ['*']
        self.auto_register = auto_register
        self.load_classes = load_classes
        self.load_functions = load_functions
        self.base_class = base_class
        
        self.modules: Dict[str, ModuleType] = {}
        self.classes: Dict[str, type] = {}
        self.functions: Dict[str, Callable] = {}
        self.errors: List[Dict[str, Any]] = []
    
    def should_load_file(self, file_path: Path) -> bool:
        """Check if a file should be loaded based on filters."""
        name = file_path.stem
        
        # Skip __init__.py
        if name == "__init__":
            return False
        
        # Check private modules
        if not self.include_private and name.startswith("_"):
            return False
        
        # Check exclude patterns
        for pattern in self.exclude_patterns:
            if file_path.match(pattern):
                return False
        
        # Check include patterns
        for pattern in self.include_patterns:
            if file_path.match(pattern):
                return True
        
        # Default to exclude if include_patterns is specified and no match
        return len(self.include_patterns) == 1 and self.include_patterns[0] == '*'
    
    def get_module_name(self, file_path: Path) -> str:
        """Convert file path to module name."""
        relative_path = file_path.relative_to(self.package_path)
        module_path = str(relative_path.with_suffix(""))
        return f"{self.package_name}.{module_path.replace(os.sep, '.')}"
    
    def extract_members(self, module: ModuleType) -> None:
        """Extract classes and functions from a module."""
        for name, obj in inspect.getmembers(module):
            # Skip private members
            if name.startswith("_"):
                continue
            
            # Skip imported members (only get defined in this module)
            if hasattr(obj, "__module__") and obj.__module__ != module.__name__:
                continue
            
            # Extract classes
            if self.load_classes and inspect.isclass(obj):
                if self.base_class is None or issubclass(obj, self.base_class):
                    self.classes[name] = obj
                    if self.auto_register:
                        # Register in parent namespace
                        globals()[name] = obj
            
            # Extract functions
            elif self.load_functions and inspect.isfunction(obj):
                self.functions[name] = obj
                if self.auto_register:
                    globals()[name] = obj
    
    def load_module(self, file_path: Path) -> Optional[ModuleType]:
        """Load a single module."""
        module_name = self.get_module_name(file_path)
        
        try:
            module = importlib.import_module(module_name)
            self.modules[module_name] = module
            
            # Extract members if requested
            self.extract_members(module)
            
            logger.debug(f"Loaded module: {module_name}")
            return module
            
        except Exception as e:
            error_info = {
                'file': str(file_path),
                'module': module_name,
                'error': str(e),
                'type': type(e).__name__
            }
            self.errors.append(error_info)
            logger.error(f"Failed to load {module_name}: {e}")
            return None
    
    def discover_modules(self) -> List[Path]:
        """Discover all Python files to load."""
        if self.recursive:
            pattern = "**/*.py"
        else:
            pattern = "*.py"
        
        py_files = []
        for file_path in self.package_path.glob(pattern):
            if self.should_load_file(file_path):
                py_files.append(file_path)
        
        return sorted(py_files)
    
    def load_all(self) -> Dict[str, Any]:
        """Load all modules and return summary."""
        py_files = self.discover_modules()
        
        for file_path in py_files:
            self.load_module(file_path)
        
        # Update global registries if auto_register is True
        if self.auto_register:
            _modules.update(self.modules)
            _classes.update(self.classes)
            _functions.update(self.functions)
        
        return {
            'modules': list(self.modules.keys()),
            'classes': list(self.classes.keys()),
            'functions': list(self.functions.keys()),
            'errors': self.errors,
            'stats': {
                'total_files': len(py_files),
                'loaded_modules': len(self.modules),
                'loaded_classes': len(self.classes),
                'loaded_functions': len(self.functions),
                'errors': len(self.errors)
            }
        }
    
def load_all_modules_simple():
    """
    Simple approach to load all modules in the package.
    """
    package_dir = Path(__file__).parent
    package_name = __name__
    
    for py_file in package_dir.rglob("*.py"):
        # Skip __init__.py files and private modules
        if py_file.name.startswith("_"):
            continue
            
        # Calculate module name relative to package
        relative_path = py_file.relative_to(package_dir)
        module_path = str(relative_path.with_suffix(""))
        module_name = f"{package_name}.{module_path.replace(os.sep, '.')}"
        
        try:
            module = importlib.import_module(module_name)
            _modules[module_name] = module
            logger.debug(f"Loaded module: {module_name}")
        except Exception as e:
            logger.error(f"Failed to load module {module_name}: {e}")