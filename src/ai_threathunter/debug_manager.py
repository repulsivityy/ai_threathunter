import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional
import hashlib
from functools import wraps


class DebugManager:
    """Manages debug logging for API calls in the threat hunting system"""
    
    _instance = None
    _initialized = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not self._initialized:
            self.debug_enabled = os.getenv('DEBUG_API_CALLS', 'false').lower() == 'true'
            self.debug_dir = Path(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))) / 'debugs'
            self.session_dir = None
            self.call_counter = 0
            
            if self.debug_enabled:
                self._initialize_debug_session()
            
            DebugManager._initialized = True
    
    def log(self, message: str):
        """Log a message to the console if debug mode is enabled."""
        if self.debug_enabled:
            print(message)

    def _initialize_debug_session(self):
        """Initialize a new debug session directory"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.session_dir = self.debug_dir / f'session_{timestamp}'
        self.session_dir.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories for different API types
        (self.session_dir / 'gti').mkdir(exist_ok=True)
        (self.session_dir / 'urlscan').mkdir(exist_ok=True)
        (self.session_dir / 'summary').mkdir(exist_ok=True)
        
        # Create session info file
        session_info = {
            'session_start': datetime.now().isoformat(),
            'debug_enabled': True,
            'session_id': timestamp
        }
        
        with open(self.session_dir / 'session_info.json', 'w') as f:
            json.dump(session_info, f, indent=2)
        
        print(f"🔍 Debug Mode Enabled - Session: {self.session_dir}")
    
    def log_api_call(self, 
                     api_name: str, 
                     endpoint: str, 
                     request_data: Dict[str, Any],
                     response_data: Any,
                     error: Optional[Exception] = None,
                     execution_time: float = 0):
        """Log an API call and its response"""
        if not self.debug_enabled or not self.session_dir:
            return
        
        self.call_counter += 1
        timestamp = datetime.now().isoformat()
        
        # Create a unique filename
        call_id = f"{self.call_counter:04d}_{api_name}_{datetime.now().strftime('%H%M%S_%f')}"
        
        # Prepare log entry
        log_entry = {
            'call_id': call_id,
            'call_number': self.call_counter,
            'timestamp': timestamp,
            'api_name': api_name,
            'endpoint': endpoint,
            'execution_time_seconds': execution_time,
            'request': request_data,
            'response': self._safe_serialize(response_data),
            'error': str(error) if error else None,
            'success': error is None
        }
        
        # Save to appropriate directory
        api_dir = self.session_dir / api_name.lower().replace(' ', '_')
        if not api_dir.exists():
            api_dir.mkdir(exist_ok=True)
        
        # Save the full log
        log_file = api_dir / f"{call_id}.json"
        with open(log_file, 'w') as f:
            json.dump(log_entry, f, indent=2)
        
        # Update summary
        self._update_summary(api_name, endpoint, error is None)
        
        # Console output for real-time monitoring
        if error:
            print(f"❌ API Call #{self.call_counter} - {api_name}: {endpoint} - ERROR: {error}")
        else:
            print(f"✅ API Call #{self.call_counter} - {api_name}: {endpoint} - SUCCESS")
    
    def _safe_serialize(self, data: Any) -> Any:
        """Safely serialize data for JSON storage"""
        if isinstance(data, dict):
            return {k: self._safe_serialize(v) for k, v in data.items()}
        elif isinstance(data, (list, tuple)):
            return [self._safe_serialize(item) for item in data]
        elif isinstance(data, bytes):
            return f"<bytes: {len(data)} bytes>"
        elif hasattr(data, '__dict__'):
            return self._safe_serialize(data.__dict__)
        else:
            try:
                json.dumps(data)
                return data
            except:
                return str(data)
    
    def _update_summary(self, api_name: str, endpoint: str, success: bool):
        """Update the summary file with API call statistics"""
        summary_file = self.session_dir / 'summary' / 'api_calls_summary.json'
        
        if summary_file.exists():
            with open(summary_file, 'r') as f:
                summary = json.load(f)
        else:
            summary = {
                'total_calls': 0,
                'successful_calls': 0,
                'failed_calls': 0,
                'apis': {}
            }
        
        # Update totals
        summary['total_calls'] += 1
        if success:
            summary['successful_calls'] += 1
        else:
            summary['failed_calls'] += 1
        
        # Update API-specific stats
        if api_name not in summary['apis']:
            summary['apis'][api_name] = {
                'total': 0,
                'successful': 0,
                'failed': 0,
                'endpoints': {}
            }
        
        summary['apis'][api_name]['total'] += 1
        if success:
            summary['apis'][api_name]['successful'] += 1
        else:
            summary['apis'][api_name]['failed'] += 1
        
        # Track endpoints
        if endpoint not in summary['apis'][api_name]['endpoints']:
            summary['apis'][api_name]['endpoints'][endpoint] = {
                'count': 0,
                'successes': 0,
                'failures': 0
            }
        
        summary['apis'][api_name]['endpoints'][endpoint]['count'] += 1
        if success:
            summary['apis'][api_name]['endpoints'][endpoint]['successes'] += 1
        else:
            summary['apis'][api_name]['endpoints'][endpoint]['failures'] += 1
        
        # Save updated summary
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
    
    def create_investigation_summary(self, ioc: str):
        """Create a final investigation summary"""
        if not self.debug_enabled or not self.session_dir:
            return
        
        summary_file = self.session_dir / 'summary' / 'investigation_summary.json'
        
        investigation_summary = {
            'ioc': ioc,
            'timestamp': datetime.now().isoformat(),
            'total_api_calls': self.call_counter,
            'session_directory': str(self.session_dir)
        }
        
        with open(summary_file, 'w') as f:
            json.dump(investigation_summary, f, indent=2)
        
        print(f"\n📊 Debug Summary: {self.call_counter} API calls logged to {self.session_dir}")


def debug_api_call(api_name: str):
    """Decorator to automatically log API calls"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            debug_manager = DebugManager()
            
            if not debug_manager.debug_enabled:
                return func(*args, **kwargs)
            
            import time
            start_time = time.time()
            error = None
            result = None
            
            # Extract request information
            request_info = {
                'function': func.__name__,
                'args': [str(arg)[:500] for arg in args[1:]] if len(args) > 1 else [],  # Skip self
                'kwargs': {k: str(v)[:500] for k, v in kwargs.items()}
            }
            
            # Determine endpoint from function call
            if len(args) > 1 and hasattr(args[0], '__class__'):
                if 'url' in str(args) or 'endpoint' in kwargs:
                    endpoint = kwargs.get('endpoint', str(args[1]) if len(args) > 1 else 'unknown')
                else:
                    endpoint = func.__name__
            else:
                endpoint = func.__name__
            
            try:
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                error = e
                raise
            finally:
                execution_time = time.time() - start_time
                debug_manager.log_api_call(
                    api_name=api_name,
                    endpoint=endpoint,
                    request_data=request_info,
                    response_data=result,
                    error=error,
                    execution_time=execution_time
                )
        
        return wrapper
    return decorator