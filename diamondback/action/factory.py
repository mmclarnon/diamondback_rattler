# factory.py
import os
import sys
import importlib
import inspect
import pkgutil
import logging
from pathlib import Path
from typing import Dict, Type, Optional, Any, List, Tuple, Set
from functools import lru_cache
import threading

# Import the base Action class
from action import Action,call_before_decorator

logger = logging.getLogger(__name__)

class ActionRegistry:
    """
    Thread-safe registry for discovered Action classes.
    """
    
    def __init__(self):
        self._registry: Dict[str, Type[Action]] = {}
        self._aliases: Dict[str, str] = {}
        self._lock = threading.RLock()
        self._discovered = False
        
    def register(self, cls: Type[Action], name: Optional[str] = None, 
                 aliases: Optional[List[str]] = None) -> None:
        """Register an Action class with optional aliases."""
        with self._lock:
            class_name = name or cls.__name__
            
            # Store the class
            self._registry[class_name] = cls
            self._registry[class_name.lower()] = cls  # Case-insensitive lookup
            
            # Register aliases
            if aliases:
                for alias in aliases:
                    self._aliases[alias] = class_name
                    self._aliases[alias.lower()] = class_name
    
    def get(self, name: str) -> Optional[Type[Action]]:
        """Get an Action class by name or alias."""
        with self._lock:
            # Direct lookup
            if name in self._registry:
                return self._registry[name]
            
            # Case-insensitive lookup
            name_lower = name.lower()
            if name_lower in self._registry:
                return self._registry[name_lower]
            
            # Alias lookup
            if name in self._aliases:
                return self._registry.get(self._aliases[name])
            
            if name_lower in self._aliases:
                return self._registry.get(self._aliases[name_lower])
            
            return None
    
    def get_all(self) -> Dict[str, Type[Action]]:
        """Get all registered Action classes."""
        with self._lock:
            # Return unique classes only (remove duplicates from case-insensitive entries)
            unique_classes = {}
            seen = set()
            for name, cls in self._registry.items():
                if cls not in seen and not name.islower():
                    unique_classes[name] = cls
                    seen.add(cls)
            return unique_classes
    
    def clear(self) -> None:
        """Clear the registry."""
        with self._lock:
            self._registry.clear()
            self._aliases.clear()
            self._discovered = False


class ActionFactory:
    """
    Factory class for discovering and creating Action instances.
    """
    
    # Class-level registry shared across all instances
    _registry = ActionRegistry()
    _discovery_lock = threading.Lock()
    
    @classmethod
    def discover_actions(cls, 
                        base_path: Optional[str] = None,
                        package_name: str = "diamondback.action",
                        recursive: bool = True,
                        exclude_patterns: Optional[List[str]] = None,
                        include_private: bool = False,
                        force_reload: bool = False) -> Dict[str, Type[Action]]:
        """
        Discover all Action subclasses in the specified package.
        
        Args:
            base_path: Base path to search (defaults to 'action' folder)
            package_name: Name of the package to search
            recursive: Whether to search subdirectories
            exclude_patterns: Patterns to exclude (e.g., ['test_*', '*_test'])
            include_private: Whether to include modules starting with underscore
            force_reload: Force re-discovery even if already done
        
        Returns:
            Dictionary mapping class names to Action classes
        """
        with cls._discovery_lock:
            # Check if already discovered
            if cls._registry._discovered and not force_reload:
                return cls._registry.get_all()
            
            # Clear registry if forcing reload
            if force_reload:
                cls._registry.clear()
            
            # Determine the base path
            if base_path is None:
                # Try to find the action package
                try:
                    action_module = importlib.import_module(package_name)
                    base_path = Path(action_module.__file__).parent
                except ImportError:
                    # Fallback to relative path
                    base_path = Path(__file__).parent / package_name
            else:
                base_path = Path(base_path)
            
            if not base_path.exists():
                logger.error(f"Action package path does not exist: {base_path}")
                return {}
            
            # Default exclude patterns
            if exclude_patterns is None:
                exclude_patterns = ['test_*', '*_test', '__pycache__', '*.pyc']
            
            # Discover using multiple methods
            cls._discover_with_walk(base_path, package_name, exclude_patterns, include_private)
            cls._discover_with_pkgutil(package_name)
            
            cls._registry._discovered = True
            return cls._registry.get_all()
    
    @classmethod
    def _discover_with_walk(cls, base_path: Path, package_name: str,
                           exclude_patterns: List[str], include_private: bool) -> None:
        """Discover actions by walking the filesystem."""
        
        for root, dirs, files in os.walk(base_path):
            # Filter directories
            dirs[:] = [d for d in dirs if not d.startswith('__')]
            
            for file in files:
                if not file.endswith('.py'):
                    continue
                
                # Skip __init__.py and check patterns
                if file == '__init__.py':
                    continue
                
                if not include_private and file.startswith('_'):
                    continue
                
                # Check exclude patterns
                skip = False
                for pattern in exclude_patterns:
                    if Path(file).match(pattern):
                        skip = True
                        break
                
                if skip:
                    continue
                
                # Build module name
                rel_path = Path(root).relative_to(base_path.parent)
                module_parts = list(rel_path.parts)
                module_parts.append(Path(file).stem)
                module_name = 'diamondback.' + '.'.join(module_parts)
                cls._load_module_actions(module_name)
    
    @classmethod
    def _discover_with_pkgutil(cls, package_name: str) -> None:
        """Discover actions using pkgutil (catches dynamically added modules)."""
        try:
            package = importlib.import_module(package_name)
            
            # Walk the package
            for importer, modname, ispkg in pkgutil.walk_packages(
                path=package.__path__,
                prefix=f"{package_name}.",
                onerror=lambda name: logger.debug(f"Error walking package: {name}")
            ):
                cls._load_module_actions(modname)
                
        except ImportError as e:
            logger.debug(f"Could not import package {package_name}: {e}")
    
    @classmethod
    def _load_module_actions(cls, module_name: str) -> None:
        """Load Action classes from a specific module."""
        try:
            module = importlib.import_module(module_name)
            logger.info( f'examining {module_name}' )
            # Find all Action subclasses in the module
            for name, obj in inspect.getmembers(module, inspect.isclass):
                # Check if it's a subclass of Action (but not Action itself)
                mro = inspect.getmro(obj)
                if len(mro) > 1:
                    base_class = mro[1]  # The first base class in the MRO
                    logger.debug(f"  {name}: Base Class = {base_class.__name__}")
                if base_class.__name__ == 'Action' and obj is not Action:
                    # Only register if defined in this module
                    if obj.__module__ == module_name:
                        cls._registry.register(obj)
                        logger.info(f"Registered action: {obj.__name__} from {module_name}")
        except ImportError as e:
            logger.debug(f"Could not import module {module_name}: {e}")
        except Exception as e:
            logger.error(f"Error loading actions from {module_name}: {e}")
    
    @staticmethod
    def create(class_name: str, *args, **kwargs) -> Action:
        """
        Create an instance of an Action subclass by name.
        
        Args:
            class_name: Name of the Action subclass to instantiate
            *args: Positional arguments to pass to the constructor
            **kwargs: Keyword arguments to pass to the constructor
        
        Returns:
            An instance of the requested Action subclass
        
        Raises:
            ValueError: If the class name is not found
            TypeError: If the class cannot be instantiated with given arguments
        """
        # Ensure actions are discovered
        if not ActionFactory._registry._discovered:
            ActionFactory.discover_actions()
        
        # Get the class
        action_class = ActionFactory._registry.get(class_name)
        
        if action_class is None:
            available = list(ActionFactory._registry.get_all().keys())
            raise ValueError(
                f"Action class '{class_name}' not found. "
                f"Available actions: {', '.join(sorted(available))}"
            )
        
        try:
            # Create and return instance
            instance = action_class(*args, **kwargs)
            logger.debug(f"Created instance of {action_class.__name__}")
            return instance
            
        except TypeError as e:
            # Provide helpful error message about constructor parameters
            sig = inspect.signature(action_class.__init__)
            raise TypeError(
                f"Failed to instantiate {action_class.__name__} with provided arguments. "
                f"Constructor signature: {sig}\n"
                f"Error: {e}"
            )
    
    @staticmethod
    def create_safe(class_name: str, *args, **kwargs) -> Optional[Action]:
        """
        Safely create an Action instance, returning None on failure.
        
        Args:
            class_name: Name of the Action subclass to instantiate
            *args: Positional arguments to pass to the constructor
            **kwargs: Keyword arguments to pass to the constructor
        
        Returns:
            An instance of the requested Action subclass, or None if failed
        """
        try:
            return ActionFactory.create(class_name, *args, **kwargs)
        except Exception as e:
            logger.error(f"Failed to create action '{class_name}': {e}")
            return None
    
    @staticmethod
    def get_action_class(class_name: str) -> Optional[Type[Action]]:
        """
        Get an Action class by name without instantiating it.
        
        Args:
            class_name: Name of the Action subclass
        
        Returns:
            The Action subclass, or None if not found
        """
        if not ActionFactory._registry._discovered:
            ActionFactory.discover_actions()
        
        return ActionFactory._registry.get(class_name)
    
    @staticmethod
    def list_actions() -> List[str]:
        """
        List all available Action class names.
        
        Returns:
            List of available Action class names
        """
        if not ActionFactory._registry._discovered:
            ActionFactory.discover_actions()
        
        return sorted(ActionFactory._registry.get_all().keys())
    
    @staticmethod
    def get_action_info(class_name: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about an Action class.
        
        Args:
            class_name: Name of the Action subclass
        
        Returns:
            Dictionary with class information, or None if not found
        """
        action_class = ActionFactory.get_action_class(class_name)
        
        if action_class is None:
            return None
        
        # Get constructor signature
        sig = inspect.signature(action_class.__init__)
        params = []
        for param_name, param in sig.parameters.items():
            if param_name in ('self', 'args', 'kwargs'):
                continue
            param_info = {
                'name': param_name,
                'required': param.default == inspect.Parameter.empty,
                'default': None if param.default == inspect.Parameter.empty else param.default,
                'annotation': str(param.annotation) if param.annotation != inspect.Parameter.empty else None
            }
            params.append(param_info)
        
        return {
            'name': action_class.__name__,
            'module': action_class.__module__,
            'docstring': inspect.getdoc(action_class),
            'parameters': params,
            'methods': [m for m in dir(action_class) if not m.startswith('_') and callable(getattr(action_class, m))],
            'is_abstract': inspect.isabstract(action_class),
            'base_classes': [base.__name__ for base in action_class.__bases__]
        }
    
    @staticmethod
    def register_action(action_class: Type[Action], 
                       name: Optional[str] = None,
                       aliases: Optional[List[str]] = None) -> None:
        """
        Manually register an Action class.
        
        Args:
            action_class: The Action subclass to register
            name: Optional name to register under (defaults to class name)
            aliases: Optional list of aliases for the action
        """
        if not issubclass(action_class, Action):
            raise ValueError(f"{action_class} must be a subclass of Action")
        
        ActionFactory._registry.register(action_class, name, aliases)
        logger.info(f"Manually registered action: {name or action_class.__name__}")
    
    @staticmethod
    def clear_registry() -> None:
        """Clear the action registry (useful for testing)."""
        ActionFactory._registry.clear()
        logger.info("Cleared action registry")