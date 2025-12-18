import json
import hashlib
import time
from pathlib import Path
from typing import Optional, Dict, Any

class CacheManager:
    def __init__(self, cache_dir: str = ".cache", ttl_seconds: int = 86400):
        self.cache_dir = Path(cache_dir)
        self.ttl_seconds = ttl_seconds
        self.cache_dir.mkdir(exist_ok=True)

    def _get_cache_key(self, key: str) -> str:
        return hashlib.md5(key.encode()).hexdigest()

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Retrieve data from cache if valid"""
        cache_file = self.cache_dir / f"{self._get_cache_key(key)}.json"
        
        if not cache_file.exists():
            return None

        try:
            with open(cache_file, 'r') as f:
                cached_data = json.load(f)
            
            # Check TTL
            if time.time() - cached_data['timestamp'] > self.ttl_seconds:
                return None
                
            return cached_data['data']
        except Exception:
            return None

    def set(self, key: str, data: Any):
        """Save data to cache with automatic cleanup"""
        # Cleanup expired entries before writing
        self._cleanup_expired()
        
        cache_file = self.cache_dir / f"{self._get_cache_key(key)}.json"
        
        try:
            with open(cache_file, 'w') as f:
                json.dump({
                    'timestamp': time.time(),
                    'data': data
                }, f)
        except Exception as e:
            print(f"Warning: Failed to write to cache: {e}")
    
    def _cleanup_expired(self):
        """Remove expired cache files"""
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                with open(cache_file, 'r') as f:
                    cached_data = json.load(f)
                
                # Check if expired
                if time.time() - cached_data['timestamp'] > self.ttl_seconds:
                    cache_file.unlink()
            except Exception:
                # If we can't read the file, skip it
                pass


    def clear(self):
        """Clear all cache"""
        for f in self.cache_dir.glob("*.json"):
            try:
                f.unlink()
            except:
                pass
