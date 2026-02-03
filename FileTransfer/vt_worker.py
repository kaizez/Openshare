#!/usr/bin/env python3
"""
Background worker to process pending VirusTotal scans
Polls analysis results and updates file status in database
"""

import os
import sys
import time
from datetime import datetime
from virustotal_service import VirusTotalService
from db import get_db

def process_pending_scans():
    """
    Process all files with scan_status='pending'
    Poll their VirusTotal analysis results and update status
    """
    # Initialize services
    api_key = os.environ.get('VIRUSTOTAL_API_KEY', '')
    vt_service = VirusTotalService(
        api_key=api_key,
        timeout=300,  # 5 minute max for background processing
        enabled=os.environ.get('VIRUSTOTAL_ENABLED', 'true').lower() == 'true'
    )
    
    # CRITICAL FIX: Create fresh DB instance each cycle (NOT singleton!)
    # This ensures we always see new data without caching
    from db import Database
    db = Database()
    
    print(f"[VT Worker] Starting scan processor at {datetime.now()}", flush=True)
    
    # Get all files pending scan (fresh query)
    pending_files = db.get_files_by_scan_status('pending')
    
    if not pending_files:
        print("[VT Worker] No pending scans", flush=True)
        db.close()  # Clean up connection
        return
    
    print(f"[VT Worker] Found {len(pending_files)} files pending scan", flush=True)
    
    for file_id, file_info in pending_files.items():
        process_single_scan(vt_service, db, file_id, file_info)
    
    # Close connection after processing
    db.close()



def process_single_scan(vt_service, db, file_id, file_info):
    """Process a single pending scan"""
    analysis_id = file_info.get('vt_analysis_id')
    
    if not analysis_id:
        print(f"[VT Worker] File {file_id} has no analysis ID - marking as error", flush=True)
        db.update_scan_status(
            file_id,
            scan_status='error',
            scan_error='No analysis ID available'
        )
        return
    
    print(f"[VT Worker] Checking scan for {file_id} (analysis: {analysis_id})", flush=True)
    
    # Get analysis result
    result = vt_service.get_analysis_result(analysis_id)
    
    if result.get('error'):
        print(f"[VT Worker] Error getting result: {result['error']}", flush=True)
        # Don't mark as error yet - might be temporary API issue
        return
    
    if not result['completed']:
        # Still scanning
        status = result.get('status', 'unknown')
        print(f"[VT Worker] Scan still in progress: {status}", flush=True)
        return
    
    # Scan completed!
    if result['passed']:
        print(f"[VT Worker] ✅ File {file_id} is CLEAN", flush=True)
        db.update_scan_status(
            file_id,
            scan_status='clean',
            malicious_count=result['malicious_count'],
            suspicious_count=result['suspicious_count'],
            total_engines=result['total_engines'],
            scan_completed_at=datetime.now().isoformat()
        )
        
        # Log the scan
        db.log_virus_scan(
            file_id=file_id,
            filename=file_info['original_filename'],
            file_size=file_info['file_size'],
            file_hash=file_info['file_hash'],
            scan_status='clean',
            malicious_count=result['malicious_count'],
            suspicious_count=result['suspicious_count'],
            scan_details=f"Scanned by {result['total_engines']} engines - No threats detected",
            ip_address=file_info.get('upload_ip', 'background-worker')
        )
        
    else:
        print(f"[VT Worker] ❌ File {file_id} is MALICIOUS - deleting", flush=True)
        db.update_scan_status(
            file_id,
            scan_status='malicious',
            malicious_count=result['malicious_count'],
            suspicious_count=result['suspicious_count'],
            total_engines=result['total_engines'],
            scan_completed_at=datetime.now().isoformat(),
            scan_error=f"Flagged as malicious by {result['malicious_count']} vendors"
        )
        
        # Log the failed scan
        db.log_virus_scan(
            file_id=file_id,
            filename=file_info['original_filename'],
            file_size=file_info['file_size'],
            file_hash=file_info['file_hash'],
            scan_status='failed',
            malicious_count=result['malicious_count'],
            suspicious_count=result['suspicious_count'],
            scan_details=f"Flagged as malicious by {result['malicious_count']} security vendors",
            ip_address=file_info.get('upload_ip', 'background-worker')
        )
        
        # Delete the malicious file
        db.delete_file(file_id)
        print(f"[VT Worker] Deleted malicious file {file_id}", flush=True)

def main():
    """Main worker loop"""
    print("[VT Worker] VirusTotal Background Worker starting...", flush=True)
    
    # Check interval (seconds)
    check_interval = int(os.environ.get('VT_WORKER_INTERVAL', 10))
    
    while True:
        try:
            process_pending_scans()
        except Exception as e:
            print(f"[VT Worker] Error in worker loop: {e}", flush=True)
            import traceback
            traceback.print_exc()
        
        # Wait before next check
        time.sleep(check_interval)

if __name__ == '__main__':
    main()
