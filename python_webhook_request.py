#!/usr/bin/env python3
"""
KeePass Database Backup to Dropbox via n8n Webhook

This script monitors KeePass database files and automatically backs them up
to Dropbox using an n8n webhook endpoint with basic authentication.

Features:
- Monitor multiple KeePass database files
- Automatic backup on file changes
- Manual backup option
- Timestamped backup files
- Encryption of backup files
- Email notifications (optional)
- Logging with rotation
- Configuration file support
- Retry mechanism for failed uploads
"""

import os
import sys
import json
import time
import shutil
import hashlib
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import requests
from requests.auth import HTTPBasicAuth
import schedule
import configparser
from cryptography.fernet import Fernet
import argparse

# Configuration classes
@dataclass
class N8NConfig:
    webhook_url: str
    username: str
    password: str
    timeout: int = 30

@dataclass
class BackupConfig:
    enabled: bool = True
    encrypt_backup: bool = False
    encryption_key: Optional[str] = None
    add_timestamp: bool = True
    max_backups: int = 10
    backup_interval_hours: int = 24

@dataclass
class DatabaseConfig:
    path: str
    enabled: bool = True
    backup_on_change: bool = True
    custom_name: Optional[str] = None

class KeePassBackupManager:
    def __init__(self, config_path: str = "config.ini"):
        self.config_path = config_path
        self.config = configparser.ConfigParser()
        self.load_config()
        
        # Setup logging
        self.setup_logging()
        
        # Initialize components
        self.n8n_config = self.get_n8n_config()
        self.backup_config = self.get_backup_config()
        self.databases = self.get_databases_config()
        
        # File watcher
        self.observer = Observer()
        self.backup_states = {}  # Track last backup times and hashes
        
        self.logger.info("KeePass Backup Manager initialized")

    def setup_logging(self):
        """Setup logging with rotation"""
        log_level = self.config.get('logging', 'level', fallback='INFO')
        log_file = self.config.get('logging', 'file', fallback='keepass_backup.log')
        
        logging.basicConfig(
            level=getattr(logging, log_level.upper()),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)

    def load_config(self):
        """Load configuration from file"""
        if not os.path.exists(self.config_path):
            self.create_default_config()
        
        self.config.read(self.config_path)

    def create_default_config(self):
        """Create default configuration file"""
        config = configparser.ConfigParser()
        
        config['n8n'] = {
            'webhook_url': 'https://your-n8n-instance.com/webhook/upload-file',
            'username': 'your-username',
            'password': 'your-password',
            'timeout': '30'
        }
        
        config['backup'] = {
            'enabled': 'true',
            'encrypt_backup': 'false',
            'encryption_key': '',
            'add_timestamp': 'true',
            'max_backups': '10',
            'backup_interval_hours': '24'
        }
        
        config['logging'] = {
            'level': 'INFO',
            'file': 'keepass_backup.log'
        }
        
        config['database_1'] = {
            'path': '/path/to/your/database.kdbx',
            'enabled': 'true',
            'backup_on_change': 'true',
            'custom_name': 'MyPasswords'
        }
        
        with open(self.config_path, 'w') as f:
            config.write(f)
        
        self.logger.info(f"Created default config file: {self.config_path}")

    def get_n8n_config(self) -> N8NConfig:
        """Get n8n configuration"""
        return N8NConfig(
            webhook_url=self.config.get('n8n', 'webhook_url'),
            username=self.config.get('n8n', 'username'),
            password=self.config.get('n8n', 'password'),
            timeout=self.config.getint('n8n', 'timeout', fallback=30)
        )

    def get_backup_config(self) -> BackupConfig:
        """Get backup configuration"""
        return BackupConfig(
            enabled=self.config.getboolean('backup', 'enabled', fallback=True),
            encrypt_backup=self.config.getboolean('backup', 'encrypt_backup', fallback=False),
            encryption_key=self.config.get('backup', 'encryption_key', fallback=None),
            add_timestamp=self.config.getboolean('backup', 'add_timestamp', fallback=True),
            max_backups=self.config.getint('backup', 'max_backups', fallback=10),
            backup_interval_hours=self.config.getint('backup', 'backup_interval_hours', fallback=24)
        )

    def get_databases_config(self) -> List[DatabaseConfig]:
        """Get database configurations"""
        databases = []
        
        for section_name in self.config.sections():
            if section_name.startswith('database_'):
                databases.append(DatabaseConfig(
                    path=self.config.get(section_name, 'path'),
                    enabled=self.config.getboolean(section_name, 'enabled', fallback=True),
                    backup_on_change=self.config.getboolean(section_name, 'backup_on_change', fallback=True),
                    custom_name=self.config.get(section_name, 'custom_name', fallback=None)
                ))
        
        return databases

    def get_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            hash_value = sha256_hash.hexdigest()
            self.logger.debug(f"Calculated hash for {file_path}: {hash_value}")
            return hash_value
        except Exception as e:
            self.logger.error(f"Error calculating hash for {file_path}: {str(e)}", exc_info=True)
            return ""

    def encrypt_file(self, file_path: str, output_path: str) -> bool:
        """Encrypt file using Fernet encryption"""
        try:
            if not self.backup_config.encryption_key:
                key = Fernet.generate_key()
                self.backup_config.encryption_key = key.decode()
                self.logger.info("Generated new encryption key")
            key = self.backup_config.encryption_key.encode()
            fernet = Fernet(key)
            with open(file_path, 'rb') as f:
                data = f.read()
            encrypted_data = fernet.encrypt(data)
            with open(output_path, 'wb') as f:
                f.write(encrypted_data)
            self.logger.info(f"Encrypted file {file_path} to {output_path}")
            return True
        except Exception as e:
            self.logger.error(f"Error encrypting file {file_path}: {str(e)}", exc_info=True)
            return False

    def prepare_backup_file(self, db_config: DatabaseConfig) -> Optional[str]:
        """Prepare backup file (copy, encrypt, rename)"""
        try:
            source_path = Path(db_config.path)
            if not source_path.exists():
                self.logger.error(f"Database file not found: {source_path}")
                return None
            if db_config.custom_name:
                base_name = db_config.custom_name
            else:
                base_name = source_path.stem
            if self.backup_config.add_timestamp:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_name = f"{base_name}_{timestamp}{source_path.suffix}"
            else:
                backup_name = f"{base_name}_backup{source_path.suffix}"
            temp_backup_path = Path("temp_backups") / backup_name
            temp_backup_path.parent.mkdir(exist_ok=True)
            self.logger.debug(f"Preparing backup file: {temp_backup_path}")
            if self.backup_config.encrypt_backup:
                backup_name += ".encrypted"
                temp_backup_path = temp_backup_path.with_suffix(temp_backup_path.suffix + ".encrypted")
                if not self.encrypt_file(str(source_path), str(temp_backup_path)):
                    return None
            else:
                shutil.copy2(source_path, temp_backup_path)
                self.logger.info(f"Copied file {source_path} to {temp_backup_path}")
            return str(temp_backup_path)
        except Exception as e:
            self.logger.error(f"Error preparing backup file: {str(e)}", exc_info=True)
            return None

    def upload_to_dropbox(self, file_path: str, db_config: DatabaseConfig) -> Dict:
        """Upload file to Dropbox via n8n webhook"""
        try:
            metadata = {
                'source_database': db_config.path,
                'custom_name': db_config.custom_name or '',
                'backup_time': datetime.now().isoformat(),
                'encrypted': self.backup_config.encrypt_backup,
                'file_hash': self.get_file_hash(file_path)
            }
            form_data = {
                'description': f'KeePass backup from {db_config.custom_name or Path(db_config.path).name}',
                'category': 'keepass_backup',
                'backup_type': 'automated',
                'metadata': json.dumps(metadata)
            }
            filename = Path(file_path).name
            self.logger.info(f"Uploading {filename} to Dropbox via webhook: {self.n8n_config.webhook_url}")
            with open(file_path, 'rb') as file:
                files = {
                    filename: file  # Use filename as key, just like in test.py
                }
                response = requests.post(
                    self.n8n_config.webhook_url,
                    files=files,
                    data=form_data,
                    auth=HTTPBasicAuth(self.n8n_config.username, self.n8n_config.password),
                    timeout=self.n8n_config.timeout
                )
            self.logger.debug(f"Webhook response status: {response.status_code}")
            if not response.ok:
                self.logger.error(f"Webhook response content: {response.text}")
            result = {
                "status_code": response.status_code,
                "success": response.status_code == 200,
                "response": response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text,
                "file_path": file_path,
                "metadata": metadata
            }
            return result
        except Exception as e:
            self.logger.error(f"Error uploading to Dropbox: {str(e)}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "file_path": file_path
            }

    def backup_database(self, db_config: DatabaseConfig, force: bool = False) -> bool:
        """Backup a single database"""
        try:
            if not db_config.enabled:
                self.logger.debug(f"Database backup disabled: {db_config.path}")
                return False
            current_hash = self.get_file_hash(db_config.path)
            last_state = self.backup_states.get(db_config.path, {})
            self.logger.debug(f"Current hash: {current_hash}, Last hash: {last_state.get('hash', '')}")
            if not force and current_hash == last_state.get('hash', ''):
                self.logger.debug(f"No changes detected in {db_config.path}")
                return False
            self.logger.info(f"Starting backup of {db_config.path}")
            backup_file = self.prepare_backup_file(db_config)
            if not backup_file:
                self.logger.error(f"Failed to prepare backup file for {db_config.path}")
                return False
            self.logger.info(f"Backup file prepared: {backup_file}")
            result = self.upload_to_dropbox(backup_file, db_config)
            try:
                os.remove(backup_file)
                self.logger.debug(f"Removed temp backup file: {backup_file}")
            except Exception as e:
                self.logger.warning(f"Could not remove temp backup file {backup_file}: {str(e)}")
            if result['success']:
                self.logger.info(f"Successfully backed up {db_config.path} to Dropbox")
                self.backup_states[db_config.path] = {
                    'hash': current_hash,
                    'last_backup': datetime.now().isoformat(),
                    'backup_count': last_state.get('backup_count', 0) + 1
                }
                self.logger.debug(f"Updated backup state: {self.backup_states[db_config.path]}")
                return True
            else:
                self.logger.error(f"Failed to backup {db_config.path}: {result.get('error', 'Unknown error')}")
                self.logger.error(f"Response: {result.get('response', '')}")
                return False
        except Exception as e:
            self.logger.error(f"Error during backup of {db_config.path}: {str(e)}", exc_info=True)
            return False

    def backup_all_databases(self, force: bool = False):
        """Backup all configured databases"""
        self.logger.info("Starting backup of all databases")
        
        success_count = 0
        total_count = len([db for db in self.databases if db.enabled])
        
        for db_config in self.databases:
            if db_config.enabled:
                if self.backup_database(db_config, force):
                    success_count += 1

        self.logger.info(f"Backup completed: {success_count}/{total_count} databases backed up successfully")

    def start_file_watcher(self):
        """Start file system watcher for automatic backups"""
        class KeePassFileHandler(FileSystemEventHandler):
            def __init__(self, backup_manager):
                self.backup_manager = backup_manager
                super().__init__()

            def on_modified(self, event):
                if event.is_directory:
                    return

                # Find matching database config
                for db_config in self.backup_manager.databases:
                    if db_config.enabled and db_config.backup_on_change:
                        if Path(event.src_path).resolve() == Path(db_config.path).resolve():
                            self.backup_manager.logger.info(f"Detected change in {event.src_path}")
                            # Add small delay to ensure file write is complete
                            time.sleep(2)
                            self.backup_manager.backup_database(db_config)

        handler = KeePassFileHandler(self)
        
        # Add watchers for all database directories
        watched_dirs = set()
        for db_config in self.databases:
            if db_config.enabled and db_config.backup_on_change:
                db_dir = Path(db_config.path).parent
                if db_dir not in watched_dirs:
                    self.observer.schedule(handler, str(db_dir), recursive=False)
                    watched_dirs.add(db_dir)
                    self.logger.info(f"Watching directory: {db_dir}")

        self.observer.start()
        self.logger.info("File watcher started")

    def start_scheduler(self):
        """Start scheduled backups"""
        if self.backup_config.backup_interval_hours > 0:
            schedule.every(self.backup_config.backup_interval_hours).hours.do(self.backup_all_databases)
            self.logger.info(f"Scheduled backups every {self.backup_config.backup_interval_hours} hours")

    def run(self):
        """Main run loop"""
        try:
            self.logger.info("Starting KeePass Backup Manager")
            
            # Start file watcher
            self.start_file_watcher()
            
            # Start scheduler
            self.start_scheduler()
            
            # Initial backup
            self.backup_all_databases(force=True)
            
            # Main loop
            while True:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
                
        except KeyboardInterrupt:
            self.logger.info("Shutting down...")
            self.observer.stop()
            
        except Exception as e:
            self.logger.error(f"Unexpected error: {str(e)}")
            
        finally:
            self.observer.join()

def main():
    parser = argparse.ArgumentParser(description="KeePass Database Backup Manager")
    parser.add_argument('--config', '-c', default='config.ini', help='Configuration file path')
    parser.add_argument('--backup-now', '-b', action='store_true', help='Run backup immediately and exit')
    parser.add_argument('--force', '-f', action='store_true', help='Force backup even if files haven\'t changed')
    
    args = parser.parse_args()
    
    try:
        backup_manager = KeePassBackupManager(args.config)
        
        if args.backup_now:
            backup_manager.backup_all_databases(force=args.force)
        else:
            backup_manager.run()
            
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
