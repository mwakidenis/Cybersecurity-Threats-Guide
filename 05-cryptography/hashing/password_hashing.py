#!/usr/bin/env python3

import os
import base64
import hashlib
import argparse
import getpass
from datetime import datetime
import bcrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Try to import argon2 (may need installation)
try:
    from argon2 import PasswordHasher as Argon2Hasher
    from argon2.exceptions import VerifyMismatchError
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False
    print("[!] argon2-cffi not installed. Install with: pip install argon2-cffi")

class PasswordHasher:
    """
    Secure password hashing with multiple algorithms
    """
    
    def __init__(self):
        self.backend = default_backend()
        
    def hash_bcrypt(self, password, rounds=12):
        """
        Hash password using bcrypt
        
        Args:
            password: Plaintext password
            rounds: Work factor (higher = slower but more secure)
        
        Returns:
            String containing salt + hash in modular crypt format
        """
        # bcrypt handles salt generation automatically
        password_bytes = password.encode('utf-8')
        
        # Generate salt and hash
        salt = bcrypt.gensalt(rounds=rounds)
        hashed = bcrypt.hashpw(password_bytes, salt)
        
        return hashed.decode('utf-8')
    
    def verify_bcrypt(self, password, hashed):
        """Verify password against bcrypt hash"""
        try:
            password_bytes = password.encode('utf-8')
            hashed_bytes = hashed.encode('utf-8')
            return bcrypt.checkpw(password_bytes, hashed_bytes)
        except Exception:
            return False
    
    def hash_pbkdf2(self, password, salt=None, iterations=600000):
        """
        Hash password using PBKDF2 (NIST standard)
        
        Args:
            password: Plaintext password
            salt: Optional salt (random if not provided)
            iterations: Number of iterations (higher = slower)
        
        Returns:
            Dictionary with salt, iterations, and hash
        """
        if salt is None:
            salt = os.urandom(16)
        elif isinstance(salt, str):
            salt = base64.b64decode(salt)
        
        password_bytes = password.encode('utf-8')
        
        # Create KDF
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=self.backend
        )
        
        # Derive key (used as hash)
        key = kdf.derive(password_bytes)
        
        # Return components for storage
        return {
            'algorithm': 'pbkdf2-sha256',
            'salt': base64.b64encode(salt).decode('utf-8'),
            'iterations': iterations,
            'hash': base64.b64encode(key).decode('utf-8')
        }
    
    def verify_pbkdf2(self, password, stored_data):
        """Verify password against PBKDF2 hash"""
        try:
            salt = base64.b64decode(stored_data['salt'])
            iterations = stored_data['iterations']
            stored_hash = base64.b64decode(stored_data['hash'])
            
            password_bytes = password.encode('utf-8')
            
            # Recompute hash
            kdf = PBKDF2(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=iterations,
                backend=self.backend
            )
            
            # verify_key raises exception if mismatch
            kdf.verify(password_bytes, stored_hash)
            return True
        except Exception:
            return False
    
    def hash_argon2(self, password):
        """
        Hash password using Argon2 (modern, recommended)
        Requires argon2-cffi library
        """
        if not ARGON2_AVAILABLE:
            raise ImportError("argon2-cffi not installed")
        
        ph = Argon2Hasher(
            time_cost=2,      # Number of iterations
            memory_cost=102400,  # 100 MB memory usage
            parallelism=8,    # Number of parallel threads
            hash_len=32       # Output hash length
        )
        
        return ph.hash(password)
    
    def verify_argon2(self, password, hashed):
        """Verify password against Argon2 hash"""
        if not ARGON2_AVAILABLE:
            raise ImportError("argon2-cffi not installed")
        
        ph = Argon2Hasher()
        try:
            ph.verify(hashed, password)
            return True
        except VerifyMismatchError:
            return False
    
    def hash_sha256_salted(self, password, salt=None):
        """
        WARNING: Simple SHA-256 with salt is NOT sufficient for passwords!
        This is shown for educational purposes only.
        Always use bcrypt/Argon2/PBKDF2 for real passwords.
        """
        if salt is None:
            salt = os.urandom(16)
        elif isinstance(salt, str):
            salt = base64.b64decode(salt)
        
        password_bytes = password.encode('utf-8')
        
        # Combine password and salt
        salted = password_bytes + salt
        
        # Hash with SHA-256
        hash_obj = hashlib.sha256(salted)
        hash_bytes = hash_obj.digest()
        
        return {
            'algorithm': 'sha256-salted',
            'salt': base64.b64encode(salt).decode('utf-8'),
            'hash': base64.b64encode(hash_bytes).decode('utf-8'),
            'warning': '⚠️ NOT SECURE for passwords - educational only'
        }
    
    def verify_sha256_salted(self, password, stored_data):
        """Verify SHA-256 salted hash (INSECURE - educational only)"""
        salt = base64.b64decode(stored_data['salt'])
        stored_hash = base64.b64decode(stored_data['hash'])
        
        password_bytes = password.encode('utf-8')
        salted = password_bytes + salt
        hash_obj = hashlib.sha256(salted)
        
        return hash_obj.digest() == stored_hash

class PasswordManager:
    """
    Simple password manager demonstrating storage and verification
    """
    
    def __init__(self, storage_file='passwords.json'):
        self.storage_file = storage_file
        self.hasher = PasswordHasher()
        self.users = self._load_users()
    
    def _load_users(self):
        """Load users from storage file"""
        import json
        try:
            with open(self.storage_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
    
    def _save_users(self):
        """Save users to storage file"""
        import json
        with open(self.storage_file, 'w') as f:
            json.dump(self.users, f, indent=2)
    
    def add_user_bcrypt(self, username, password):
        """Add user with bcrypt hashed password"""
        if username in self.users:
            print(f"[!] User {username} already exists")
            return False
        
        hash_data = self.hasher.hash_bcrypt(password)
        self.users[username] = {
            'algorithm': 'bcrypt',
            'hash': hash_data,
            'created': datetime.now().isoformat()
        }
        self._save_users()
        print(f"[✓] User {username} added with bcrypt")
        return True
    
    def add_user_pbkdf2(self, username, password):
        """Add user with PBKDF2 hashed password"""
        if username in self.users:
            print(f"[!] User {username} already exists")
            return False
        
        hash_data = self.hasher.hash_pbkdf2(password)
        self.users[username] = {
            'algorithm': 'pbkdf2',
            'data': hash_data,
            'created': datetime.now().isoformat()
        }
        self._save_users()
        print(f"[✓] User {username} added with PBKDF2")
        return True
    
    def add_user_argon2(self, username, password):
        """Add user with Argon2 hashed password"""
        if not ARGON2_AVAILABLE:
            print("[!] Argon2 not available")
            return False
        
        if username in self.users:
            print(f"[!] User {username} already exists")
            return False
        
        hash_data = self.hasher.hash_argon2(password)
        self.users[username] = {
            'algorithm': 'argon2',
            'hash': hash_data,
            'created': datetime.now().isoformat()
        }
        self._save_users()
        print(f"[✓] User {username} added with Argon2")
        return True
    
    def verify_user(self, username, password):
        """Verify user password"""
        if username not in self.users:
            print(f"[!] User {username} not found")
            return False
        
        user = self.users[username]
        algorithm = user['algorithm']
        
        if algorithm == 'bcrypt':
            result = self.hasher.verify_bcrypt(password, user['hash'])
        elif algorithm == 'pbkdf2':
            result = self.hasher.verify_pbkdf2(password, user['data'])
        elif algorithm == 'argon2':
            result = self.hasher.verify_argon2(password, user['hash'])
        else:
            print(f"[!] Unknown algorithm: {algorithm}")
            return False
        
        if result:
            print(f"[✓] Password verified for {username}")
        else:
            print(f"[✗] Invalid password for {username}")
        
        return result

def demonstrate_hashing():
    """Demonstrate password hashing techniques"""
    print("""
    ╔═══════════════════════════════════════╗
    ║     Password Hashing Demo             ║
    ╚═══════════════════════════════════════╝
    """)
    
    hasher = PasswordHasher()
    password = "MySecurePassword123!"
    print(f"[*] Testing password: {password}\n")
    
    # 1. bcrypt
    print("="*50)
    print("1. bcrypt Hashing")
    print("="*50)
    bcrypt_hash = hasher.hash_bcrypt(password)
    print(f"   Hash: {bcrypt_hash}")
    print(f"   Format: {type(bcrypt_hash)}")
    
    # Verify
    valid = hasher.verify_bcrypt(password, bcrypt_hash)
    print(f"   Correct password valid: {valid}")
    valid = hasher.verify_bcrypt("wrongpassword", bcrypt_hash)
    print(f"   Wrong password valid: {valid}")
    
    # 2. PBKDF2
    print("\n" + "="*50)
    print("2. PBKDF2 Hashing")
    print("="*50)
    pbkdf2_data = hasher.hash_pbkdf2(password)
    for key, value in pbkdf2_data.items():
        if key != 'warning':
            print(f"   {key}: {value[:50]}..." if len(str(value)) > 50 else f"   {key}: {value}")
    
    valid = hasher.verify_pbkdf2(password, pbkdf2_data)
    print(f"   Correct password valid: {valid}")
    
    # 3. Argon2 (if available)
    if ARGON2_AVAILABLE:
        print("\n" + "="*50)
        print("3. Argon2 Hashing (Recommended)")
        print("="*50)
        argon2_hash = hasher.hash_argon2(password)
        print(f"   Hash: {argon2_hash[:100]}...")
        
        valid = hasher.verify_argon2(password, argon2_hash)
        print(f"   Correct password valid: {valid}")
    
    # 4. Insecure SHA-256 (educational only)
    print("\n" + "="*50)
    print("4. INSECURE: SHA-256 with Salt")
    print("="*50)
    print("   ⚠️ This is for educational comparison only!")
    sha_data = hasher.hash_sha256_salted(password)
    print(f"   Salt: {sha_data['salt'][:30]}...")
    print(f"   Hash: {sha_data['hash'][:30]}...")
    print(f"   {sha_data['warning']}")

def main():
    parser = argparse.ArgumentParser(description='Password Hashing Tool')
    parser.add_argument('--hash', help='Hash a password')
    parser.add_argument('--verify', nargs=2, metavar=('PASSWORD', 'HASH_FILE'),
                       help='Verify password against stored hash')
    parser.add_argument('--algorithm', default='bcrypt',
                       choices=['bcrypt', 'pbkdf2', 'argon2', 'sha256'],
                       help='Hashing algorithm')
    parser.add_argument('--add-user', nargs=2, metavar=('USERNAME', 'PASSWORD'),
                       help='Add user to password manager')
    parser.add_argument('--check-user', nargs=2, metavar=('USERNAME', 'PASSWORD'),
                       help='Check user password')
    parser.add_argument('--demo', action='store_true', help='Run demonstration')
    
    args = parser.parse_args()
    
    if args.demo:
        demonstrate_hashing()
        return
    
    hasher = PasswordHasher()
    
    if args.hash:
        password = args.hash
        if args.algorithm == 'bcrypt':
            result = hasher.hash_bcrypt(password)
            print(result)
        elif args.algorithm == 'pbkdf2':
            result = hasher.hash_pbkdf2(password)
            import json
            print(json.dumps(result, indent=2))
        elif args.algorithm == 'argon2':
            if not ARGON2_AVAILABLE:
                print("[!] Argon2 not available")
                return
            result = hasher.hash_argon2(password)
            print(result)
        elif args.algorithm == 'sha256':
            result = hasher.hash_sha256_salted(password)
            import json
            print(json.dumps(result, indent=2))
            print("\n⚠️  WARNING: SHA-256 is NOT secure for passwords!")
    
    elif args.verify:
        password, hash_file = args.verify
        with open(hash_file, 'r') as f:
            import json
            stored = json.load(f)
        
        if args.algorithm == 'bcrypt':
            valid = hasher.verify_bcrypt(password, stored)
        elif args.algorithm == 'pbkdf2':
            valid = hasher.verify_pbkdf2(password, stored)
        elif args.algorithm == 'argon2':
            if not ARGON2_AVAILABLE:
                print("[!] Argon2 not available")
                return
            valid = hasher.verify_argon2(password, stored)
        
        print(f"Password valid: {valid}")
    
    elif args.add_user:
        username, password = args.add_user
        manager = PasswordManager()
        
        if args.algorithm == 'bcrypt':
            manager.add_user_bcrypt(username, password)
        elif args.algorithm == 'pbkdf2':
            manager.add_user_pbkdf2(username, password)
        elif args.algorithm == 'argon2':
            manager.add_user_argon2(username, password)
    
    elif args.check_user:
        username, password = args.check_user
        manager = PasswordManager()
        manager.verify_user(username, password)
    
    else:
        print("Use --demo for demonstration or --help for options")

if __name__ == "__main__":
    main()
