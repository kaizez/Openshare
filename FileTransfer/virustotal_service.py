#!/usr/bin/env python3
"""
VirusTotal Service - Fast Path and Async Scanning
Provides both instant hash lookup and async file scanning capabilities
"""

import time
import hashlib
import requests
from datetime import datetime


class VirusTotalService:
    """
    Service for interacting with VirusTotal API
    Supports both hash lookup (instant) and full file scanning
    """
    
    def __init__(self, api_key, timeout=60, enabled=True):
        self.api_key = api_key
        self.timeout = timeout
        self.enabled = enabled
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": api_key}
    
    def check_file_by_hash(self, file_hash):
        """
        Fast path: Check if file hash exists in VirusTotal database
        This is INSTANT and doesn't require uploading the file
        
        Args:
            file_hash: SHA256 hash of the file
            
        Returns:
            dict: {
                'found': bool - True if file exists in VT database
                'passed': bool - True if file is clean (only if found)
                'malicious_count': int
                'suspicious_count': int
                'total_engines': int
                'error': str or None
            }
        """
        if not self.api_key or not self.enabled:
            return {'found': False, 'passed': True, 'error': 'VT not configured'}
        
        print(f"[VirusTotal] Checking hash: {file_hash[:16]}...", flush=True)
        
        try:
            url = f"{self.base_url}/files/{file_hash}"
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                # File found in database
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                harmless = stats.get('harmless', 0)
                undetected = stats.get('undetected', 0)
                total = malicious + suspicious + harmless + undetected
                
                result = {
                    'found': True,
                    'passed': malicious == 0 and suspicious < 3,  # Same threshold as full scan
                    'malicious_count': malicious,
                    'suspicious_count': suspicious,
                    'total_engines': total,
                    'error': None
                }
                
                print(f"[VirusTotal] Hash found - malicious: {malicious}, suspicious: {suspicious}, total: {total}", flush=True)
                return result
                
            elif response.status_code == 404:
                # File not in database - needs full scan
                print("[VirusTotal] Hash not found - file needs full scan", flush=True)
                return {'found': False, 'passed': None, 'error': None}
                
            else:
                print(f"[VirusTotal] Hash lookup failed: {response.status_code}", flush=True)
                return {'found': False, 'passed': None, 'error': f'API error: {response.status_code}'}
                
        except Exception as e:
            print(f"[VirusTotal] Hash lookup error: {e}", flush=True)
            return {'found': False, 'passed': None, 'error': str(e)}
    
    def upload_file_for_scan(self, file_content, filename):
        """
        Upload file to VirusTotal for scanning (async - returns analysis ID)
        This starts the scan but doesn't wait for results
        
        Args:
            file_content: Binary file content
            filename: Original filename
            
        Returns:
            dict: {
                'success': bool
                'analysis_id': str - ID to poll for results
                'error': str or None
            }
        """
        if not self.api_key or not self.enabled:
            return {'success': False, 'error': 'VT not configured'}
        
        print(f"[VirusTotal] Uploading file for async scan: {filename}", flush=True)
        
        try:
            url = f"{self.base_url}/files"
            files = {"file": (filename, file_content)}
            
            response = requests.post(url, headers=self.headers, files=files, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                analysis_id = data.get('data', {}).get('id')
                
                if analysis_id:
                    print(f"[VirusTotal] File uploaded - analysis ID: {analysis_id}", flush=True)
                    return {'success': True, 'analysis_id': analysis_id, 'error': None}
                else:
                    return {'success': False, 'error': 'No analysis ID returned'}
                    
            elif response.status_code == 401:
                return {'success': False, 'error': 'Invalid API key'}
            else:
                return {'success': False, 'error': f'Upload failed: {response.status_code}'}
                
        except Exception as e:
            print(f"[VirusTotal] Upload error: {e}", flush=True)
            return {'success': False, 'error': str(e)}
    
    def get_analysis_result(self, analysis_id):
        """
        Get the result of a scan by analysis ID
        
        Args:
            analysis_id: Analysis ID from upload_file_for_scan
            
        Returns:
            dict: {
                'completed': bool
                'passed': bool or None (None if not completed)
                'status': str - 'queued', 'in-progress', 'completed'
                'malicious_count': int
                'suspicious_count': int
                'total_engines': int
                'error': str or None
            }
        """
        if not self.api_key or not self.enabled:
            return {'completed': False, 'error': 'VT not configured'}
        
        try:
            url = f"{self.base_url}/analyses/{analysis_id}"
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code != 200:
                return {'completed': False, 'error': f'API error: {response.status_code}'}
            
            data = response.json()
            status = data.get('data', {}).get('attributes', {}).get('status')
            
            if status == 'completed':
                stats = data.get('data', {}).get('attributes', {}).get('stats', {})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                harmless = stats.get('harmless', 0)
                undetected = stats.get('undetected', 0)
                total = malicious + suspicious + harmless + undetected
                
                return {
                    'completed': True,
                    'passed': malicious == 0 and suspicious < 3,
                    'status': 'completed',
                    'malicious_count': malicious,
                    'suspicious_count': suspicious,
                    'total_engines': total,
                    'error': None
                }
            else:
                return {
                    'completed': False,
                    'passed': None,
                    'status': status,
                    'malicious_count': 0,
                    'suspicious_count': 0,
                    'total_engines': 0,
                    'error': None
                }
                
        except Exception as e:
            return {'completed': False, 'error': str(e)}
    
    def scan_file_sync(self, file_content, filename, file_hash=None):
        """
        HYBRID SCAN: Try hash lookup first, then full scan if needed
        This is the synchronous version that waits for results
        
        Args:
            file_content: Binary file content
            filename: Original filename
            file_hash: Optional pre-calculated SHA256 hash
            
        Returns:
            dict: {
                'passed': bool
                'scanned': bool
                'scan_method': str - 'hash_lookup', 'full_scan', or 'skipped'
                'error_type': str or None
                'error_message': str or None
                'malicious_count': int
                'suspicious_count': int
                'total_engines': int
            }
        """
        result = {
            'passed': True,
            'scanned': False,
            'scan_method': 'skipped',
            'error_type': None,
            'error_message': None,
            'malicious_count': 0,
            'suspicious_count': 0,
            'total_engines': 0
        }
        
        if not self.api_key or not self.enabled:
            return result
        
        # Calculate hash if not provided
        if not file_hash:
            file_hash = hashlib.sha256(file_content).hexdigest()
        
        # Step 1: Try fast path - hash lookup
        hash_result = self.check_file_by_hash(file_hash)
        
        if hash_result['found']:
            # File found in database - use cached results (INSTANT!)
            result['scanned'] = True
            result['scan_method'] = 'hash_lookup'
            result['passed'] = hash_result['passed']
            result['malicious_count'] = hash_result['malicious_count']
            result['suspicious_count'] = hash_result['suspicious_count']
            result['total_engines'] = hash_result['total_engines']
            
            if not hash_result['passed']:
                result['error_type'] = 'malicious'
                result['error_message'] = f"File flagged by {hash_result['malicious_count']} security vendors"
            
            return result
        
        # Step 2: File not in database - do full scan
        print(f"[VirusTotal] File not in database - performing full scan", flush=True)
        result['scanned'] = True
        result['scan_method'] = 'full_scan'
        
        # Upload file
        upload_result = self.upload_file_for_scan(file_content, filename)
        if not upload_result['success']:
            result['passed'] = False
            result['error_type'] = 'api_error'
            result['error_message'] = upload_result['error']
            return result
        
        # Poll for results
        analysis_id = upload_result['analysis_id']
        start_time = time.time()
        
        while time.time() - start_time < self.timeout:
            elapsed = int(time.time() - start_time)
            
            analysis_result = self.get_analysis_result(analysis_id)
            
            if analysis_result.get('error'):
                result['passed'] = False
                result['error_type'] = 'api_error'
                result['error_message'] = analysis_result['error']
                return result
            
            if analysis_result['completed']:
                result['passed'] = analysis_result['passed']
                result['malicious_count'] = analysis_result['malicious_count']
                result['suspicious_count'] = analysis_result['suspicious_count']
                result['total_engines'] = analysis_result['total_engines']
                
                if not analysis_result['passed']:
                    result['error_type'] = 'malicious'
                    result['error_message'] = f"File flagged by {analysis_result['malicious_count']} security vendors"
                
                return result
            
            # Still scanning
            print(f"[VirusTotal] Scan status: {analysis_result['status']} (elapsed: {elapsed}s)", flush=True)
            time.sleep(3)
        
        # Timeout
        result['passed'] = False
        result['error_type'] = 'api_error'
        result['error_message'] = 'Virus scan timed out'
        return result
    
    def scan_file_async_start(self, file_content, filename, file_hash=None):
        """
        ASYNC START: Check hash, upload if needed, return immediately
        Returns status and analysis_id for later polling
        
        Args:
            file_content: Binary file content
            filename: Original filename
            file_hash: Optional pre-calculated SHA256 hash
            
        Returns:
            dict: {
                'immediate_result': bool - True if we have immediate result (hash found)
                'passed': bool or None - None if needs async scan
                'analysis_id': str or None - For async polling
                'scan_method': str - 'hash_lookup', 'needs_scan', or 'skipped'
                'malicious_count': int
                'suspicious_count': int
                'total_engines': int
                'error': str or None
            }
        """
        if not self.api_key or not self.enabled:
            return {
                'immediate_result': True,
                'passed': True,
                'analysis_id': None,
                'scan_method': 'skipped',
                'malicious_count': 0,
                'suspicious_count': 0,
                'total_engines': 0,
                'error': None
            }
        
        # Calculate hash if not provided
        if not file_hash:
            file_hash = hashlib.sha256(file_content).hexdigest()
        
        # Try hash lookup first
        hash_result = self.check_file_by_hash(file_hash)
        
        if hash_result['found']:
            # Immediate result!
            return {
                'immediate_result': True,
                'passed': hash_result['passed'],
                'analysis_id': None,
                'scan_method': 'hash_lookup',
                'malicious_count': hash_result['malicious_count'],
                'suspicious_count': hash_result['suspicious_count'],
                'total_engines': hash_result['total_engines'],
                'error': None
            }
        
        # Need to upload for scan
        upload_result = self.upload_file_for_scan(file_content, filename)
        
        if upload_result['success']:
            return {
                'immediate_result': False,
                'passed': None,  # Unknown - needs polling
                'analysis_id': upload_result['analysis_id'],
                'scan_method': 'needs_scan',
                'malicious_count': 0,
                'suspicious_count': 0,
                'total_engines': 0,
                'error': None
            }
        else:
            return {
                'immediate_result': True,
                'passed': False,  # Error - reject file
                'analysis_id': None,
                'scan_method': 'error',
                'malicious_count': 0,
                'suspicious_count': 0,
                'total_engines': 0,
                'error': upload_result['error']
            }
