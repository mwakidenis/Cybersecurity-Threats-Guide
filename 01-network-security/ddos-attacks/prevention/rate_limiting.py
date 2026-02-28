#!/usr/bin/env python3
"""
Rate Limiting Implementation for DDoS Prevention
Location: 01-network-security/ddos-attacks/prevention/rate_limiting.py

This script demonstrates various rate limiting techniques to prevent DDoS attacks.
"""

import time
from collections import defaultdict, deque
import threading
import argparse
import logging
from datetime import datetime, timedelta
import redis
import hashlib

class RateLimiter:
    """Base class for rate limiters"""
    
    def __init__(self, max_requests, time_window):
        """
        Initialize rate limiter
        
        Args:
            max_requests: Maximum requests allowed in time window
            time_window: Time window in seconds
        """
        self.max_requests = max_requests
        self.time_window = time_window
        
    def is_allowed(self, key):
        """Check if request is allowed for given key"""
        raise NotImplementedError

class TokenBucketRateLimiter(RateLimiter):
    """
    Token Bucket Algorithm
    - Tokens added at constant rate
    - Each request consumes one token
    - If no tokens available, request is denied
    """
    
    def __init__(self, max_requests, time_window, refill_rate=None):
        super().__init__(max_requests, time_window)
        self.buckets = {}
        self.refill_rate = refill_rate or (max_requests / time_window)
        self.lock = threading.Lock()
        
    def _get_bucket(self, key):
        """Get or create token bucket for key"""
        if key not in self.buckets:
            self.buckets[key] = {
                'tokens': self.max_requests,
                'last_refill': time.time()
            }
        return self.buckets[key]
    
    def _refill_bucket(self, bucket):
        """Refill tokens based on elapsed time"""
        now = time.time()
        elapsed = now - bucket['last_refill']
        new_tokens = elapsed * self.refill_rate
        bucket['tokens'] = min(self.max_requests, bucket['tokens'] + new_tokens)
        bucket['last_refill'] = now
        
    def is_allowed(self, key):
        with self.lock:
            bucket = self._get_bucket(key)
            self._refill_bucket(bucket)
            
            if bucket['tokens'] >= 1:
                bucket['tokens'] -= 1
                return True
            return False

class SlidingWindowRateLimiter(RateLimiter):
    """
    Sliding Window Log Algorithm
    - Maintains timestamp log of requests
    - Counts requests in current time window
    - More accurate but uses more memory
    """
    
    def __init__(self, max_requests, time_window):
        super().__init__(max_requests, time_window)
        self.requests = defaultdict(deque)
        self.lock = threading.Lock()
        
    def _clean_old_requests(self, key):
        """Remove requests outside current time window"""
        now = time.time()
        while self.requests[key] and self.requests[key][0] < now - self.time_window:
            self.requests[key].popleft()
            
    def is_allowed(self, key):
        with self.lock:
            self._clean_old_requests(key)
            
            if len(self.requests[key]) < self.max_requests:
                self.requests[key].append(time.time())
                return True
            return False

class FixedWindowRateLimiter(RateLimiter):
    """
    Fixed Window Counter Algorithm
    - Simple counter per time window
    - Can allow double the requests at boundaries
    """
    
    def __init__(self, max_requests, time_window):
        super().__init__(max_requests, time_window)
        self.counters = defaultdict(int)
        self.window_starts = {}
        self.lock = threading.Lock()
        
    def _get_current_window(self):
        """Get current window start time"""
        return int(time.time() / self.time_window) * self.time_window
        
    def is_allowed(self, key):
        with self.lock:
            current_window = self._get_current_window()
            
            # Reset counter if new window
            if key not in self.window_starts or self.window_starts[key] != current_window:
                self.counters[key] = 0
                self.window_starts[key] = current_window
            
            if self.counters[key] < self.max_requests:
                self.counters[key] += 1
                return True
            return False

class RedisRateLimiter(RateLimiter):
    """
    Distributed rate limiting using Redis
    Suitable for microservices and distributed systems
    """
    
    def __init__(self, max_requests, time_window, redis_host='localhost', redis_port=6379):
        super().__init__(max_requests, time_window)
        self.redis_client = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)
        
    def is_allowed(self, key):
        """Using Redis INCR with expiration"""
        pipe = self.redis_client.pipeline()
        now = time.time()
        key_name = f"rate_limit:{key}"
        
        # Clean old requests
        pipe.zremrangebyscore(key_name, 0, now - self.time_window)
        
        # Count requests in window
        pipe.zcard(key_name)
        
        # Add current request
        pipe.zadd(key_name, {str(now): now})
        pipe.expire(key_name, self.time_window)
        
        results = pipe.execute()
        request_count = results[1]  # zcard result
        
        return request_count < self.max_requests

class WebApplicationFirewall:
    """
    Web Application Firewall with rate limiting
    Demonstrates practical DDoS prevention
    """
    
    def __init__(self):
        self.rate_limiters = {
            'ip': TokenBucketRateLimiter(max_requests=100, time_window=60),
            'user': SlidingWindowRateLimiter(max_requests=50, time_window=60),
            'endpoint': FixedWindowRateLimiter(max_requests=500, time_window=60),
            'global': TokenBucketRateLimiter(max_requests=10000, time_window=60)
        }
        
        self.blocked_ips = set()
        self.request_log = []
        self.setup_logging()
        
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('waf.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def get_client_ip(self, request):
        """Extract client IP from request (simulated)"""
        # In real implementation, get from request object
        return request.get('remote_addr', '127.0.0.1')
    
    def get_user_id(self, request):
        """Extract user ID from request (simulated)"""
        return request.get('user_id', 'anonymous')
    
    def get_endpoint(self, request):
        """Extract endpoint from request (simulated)"""
        return request.get('path', '/')
    
    def is_malicious(self, request):
        """Check for malicious patterns"""
        # Check for SQL injection patterns
        sql_patterns = ["'", "OR 1=1", "UNION SELECT", "DROP TABLE"]
        for pattern in sql_patterns:
            if pattern in str(request):
                return True, f"SQL injection pattern: {pattern}"
        
        # Check for XSS patterns
        xss_patterns = ["<script", "javascript:", "onerror="]
        for pattern in xss_patterns:
            if pattern in str(request):
                return True, f"XSS pattern: {pattern}"
        
        return False, "Clean"
    
    def process_request(self, request):
        """Process incoming request with rate limiting and security checks"""
        client_ip = self.get_client_ip(request)
        
        # Check if IP is blocked
        if client_ip in self.blocked_ips:
            self.logger.warning(f"Blocked request from {client_ip} (IP blocked)")
            return False, "IP is blocked"
        
        # Check for malicious content
        is_malicious, reason = self.is_malicious(request)
        if is_malicious:
            self.logger.error(f"Malicious request from {client_ip}: {reason}")
            self.blocked_ips.add(client_ip)
            return False, f"Malicious request detected: {reason}"
        
        # Apply rate limiting
        limits = [
            (self.rate_limiters['ip'].is_allowed(client_ip), "IP rate limit exceeded"),
            (self.rate_limiters['user'].is_allowed(self.get_user_id(request)), "User rate limit exceeded"),
            (self.rate_limiters['endpoint'].is_allowed(self.get_endpoint(request)), "Endpoint rate limit exceeded"),
            (self.rate_limiters['global'].is_allowed("global"), "Global rate limit exceeded")
        ]
        
        for allowed, message in limits:
            if not allowed:
                self.logger.warning(f"Rate limit: {message} for {client_ip}")
                return False, message
        
        # Request allowed
        self.logger.info(f"Request allowed from {client_ip}")
        self.request_log.append({
            'timestamp': datetime.now().isoformat(),
            'ip': client_ip,
            'path': self.get_endpoint(request),
            'user': self.get_user_id(request)
        })
        
        return True, "Request allowed"
    
    def get_stats(self):
        """Get WAF statistics"""
        return {
            'total_requests': len(self.request_log),
            'blocked_ips': len(self.blocked_ips),
            'active_rate_limiters': {
                'ip': len
