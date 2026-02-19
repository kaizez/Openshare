#!/usr/bin/env python3
"""
OpenShare Data Retention API

Flask Blueprint providing API endpoints to manage retention policies.
These endpoints are intended for admin page integration.

Note: These endpoints should be protected by admin authentication
when integrated into the main application.
"""

from flask import Blueprint, jsonify, request
from retention_policy import get_retention_policy

# Create Blueprint
retention_bp = Blueprint('retention', __name__, url_prefix='/api/retention')


@retention_bp.route('/policy', methods=['GET'])
def get_policy():
    """
    Get the current retention policy configuration.

    Returns:
        JSON object with complete policy configuration
    """
    policy = get_retention_policy()
    return jsonify({
        'success': True,
        'policy': policy.get_policy(),
        'summary': policy.get_policy_summary()
    })


@retention_bp.route('/policy/summary', methods=['GET'])
def get_policy_summary():
    """
    Get a human-readable summary of retention settings.

    Returns:
        JSON object with formatted retention times
    """
    policy = get_retention_policy()
    return jsonify({
        'success': True,
        'summary': policy.get_policy_summary()
    })


@retention_bp.route('/files/<storage_type>', methods=['PUT'])
def set_file_retention(storage_type):
    """
    Set retention period for a file storage type.

    Path Parameters:
        storage_type: 'working_db', 'storage_db', or 'filesystem'

    Request Body (JSON):
        retention_minutes: int - Retention period in minutes (0 = forever)
        enabled: bool - Whether retention is enabled (optional, default True)

    Returns:
        JSON success/error response
    """
    valid_types = ['working_db', 'storage_db', 'filesystem']
    if storage_type not in valid_types:
        return jsonify({
            'success': False,
            'error': f'Invalid storage type. Must be one of: {valid_types}'
        }), 400

    data = request.get_json()
    if not data:
        return jsonify({
            'success': False,
            'error': 'Request body required'
        }), 400

    retention_minutes = data.get('retention_minutes')
    if retention_minutes is None:
        return jsonify({
            'success': False,
            'error': 'retention_minutes is required'
        }), 400

    try:
        retention_minutes = int(retention_minutes)
        if retention_minutes < 0:
            raise ValueError("Must be non-negative")
    except (ValueError, TypeError) as e:
        return jsonify({
            'success': False,
            'error': f'retention_minutes must be a non-negative integer: {e}'
        }), 400

    enabled = data.get('enabled', True)
    updated_by = data.get('updated_by', 'api')

    policy = get_retention_policy()
    success = policy.set_file_retention(
        storage_type,
        retention_minutes * 60,  # Convert to seconds
        enabled,
        updated_by
    )

    if success:
        return jsonify({
            'success': True,
            'message': f'File retention for {storage_type} updated',
            'retention_minutes': retention_minutes,
            'enabled': enabled,
            'formatted': policy.format_retention_time(retention_minutes * 60)
        })
    else:
        return jsonify({
            'success': False,
            'error': 'Failed to save retention policy'
        }), 500


@retention_bp.route('/logs/<log_type>', methods=['PUT'])
def set_log_retention(log_type):
    """
    Set retention period for a log type.

    Path Parameters:
        log_type: 'access_logs', 'failed_upload_logs', 'virus_scan_logs',
                 or 'approval_requests'

    Request Body (JSON):
        retention_minutes: int - Retention period in minutes (0 = forever)
        enabled: bool - Whether retention is enabled (optional, default True)

    Returns:
        JSON success/error response
    """
    valid_types = ['access_logs', 'failed_upload_logs', 'virus_scan_logs', 'approval_requests']
    if log_type not in valid_types:
        return jsonify({
            'success': False,
            'error': f'Invalid log type. Must be one of: {valid_types}'
        }), 400

    data = request.get_json()
    if not data:
        return jsonify({
            'success': False,
            'error': 'Request body required'
        }), 400

    retention_minutes = data.get('retention_minutes')
    if retention_minutes is None:
        return jsonify({
            'success': False,
            'error': 'retention_minutes is required'
        }), 400

    try:
        retention_minutes = int(retention_minutes)
        if retention_minutes < 0:
            raise ValueError("Must be non-negative")
    except (ValueError, TypeError) as e:
        return jsonify({
            'success': False,
            'error': f'retention_minutes must be a non-negative integer: {e}'
        }), 400

    enabled = data.get('enabled', True)
    updated_by = data.get('updated_by', 'api')

    policy = get_retention_policy()
    success = policy.set_log_retention(
        log_type,
        retention_minutes * 60,  # Convert to seconds
        enabled,
        updated_by
    )

    if success:
        return jsonify({
            'success': True,
            'message': f'Log retention for {log_type} updated',
            'retention_minutes': retention_minutes,
            'enabled': enabled,
            'formatted': policy.format_retention_time(retention_minutes * 60)
        })
    else:
        return jsonify({
            'success': False,
            'error': 'Failed to save retention policy'
        }), 500


@retention_bp.route('/cleanup-interval', methods=['PUT'])
def set_cleanup_interval():
    """
    Set the cleanup interval.

    Request Body (JSON):
        interval_minutes: int - Time between cleanup runs (minimum 1 minute)

    Returns:
        JSON success/error response
    """
    data = request.get_json()
    if not data:
        return jsonify({
            'success': False,
            'error': 'Request body required'
        }), 400

    interval_minutes = data.get('interval_minutes')
    if interval_minutes is None:
        return jsonify({
            'success': False,
            'error': 'interval_minutes is required'
        }), 400

    try:
        interval_minutes = int(interval_minutes)
        if interval_minutes < 1:
            raise ValueError("Must be at least 1 minute")
    except (ValueError, TypeError) as e:
        return jsonify({
            'success': False,
            'error': f'interval_minutes must be a positive integer: {e}'
        }), 400

    updated_by = data.get('updated_by', 'api')

    policy = get_retention_policy()
    success = policy.set_cleanup_interval(
        interval_minutes * 60,  # Convert to seconds
        updated_by
    )

    if success:
        return jsonify({
            'success': True,
            'message': 'Cleanup interval updated',
            'interval_minutes': interval_minutes,
            'formatted': policy.format_retention_time(interval_minutes * 60)
        })
    else:
        return jsonify({
            'success': False,
            'error': 'Failed to save retention policy'
        }), 500


@retention_bp.route('/dry-run', methods=['PUT'])
def set_dry_run():
    """
    Enable or disable dry run mode.

    Request Body (JSON):
        enabled: bool - True to enable dry run mode

    Returns:
        JSON success/error response
    """
    data = request.get_json()
    if not data:
        return jsonify({
            'success': False,
            'error': 'Request body required'
        }), 400

    enabled = data.get('enabled')
    if enabled is None:
        return jsonify({
            'success': False,
            'error': 'enabled is required'
        }), 400

    updated_by = data.get('updated_by', 'api')

    policy = get_retention_policy()
    success = policy.set_dry_run(bool(enabled), updated_by)

    if success:
        return jsonify({
            'success': True,
            'message': f'Dry run mode {"enabled" if enabled else "disabled"}',
            'dry_run': enabled
        })
    else:
        return jsonify({
            'success': False,
            'error': 'Failed to save retention policy'
        }), 500


@retention_bp.route('/bulk', methods=['PUT'])
def set_bulk_retention():
    """
    Set multiple retention policies at once.

    Request Body (JSON):
        files: dict - Optional, file retention settings by storage_type
        logs: dict - Optional, log retention settings by log_type
        cleanup_interval_minutes: int - Optional
        dry_run: bool - Optional

    Example:
        {
            "files": {
                "working_db": {"retention_minutes": 60, "enabled": true},
                "storage_db": {"retention_minutes": 1440, "enabled": true}
            },
            "logs": {
                "access_logs": {"retention_minutes": 10080, "enabled": true}
            },
            "cleanup_interval_minutes": 60,
            "updated_by": "admin"
        }

    Returns:
        JSON with success status and any errors
    """
    data = request.get_json()
    if not data:
        return jsonify({
            'success': False,
            'error': 'Request body required'
        }), 400

    policy = get_retention_policy()
    updated_by = data.get('updated_by', 'api')
    errors = []
    updates = []

    # Update file retention
    if 'files' in data:
        for storage_type, settings in data['files'].items():
            if storage_type in ['working_db', 'storage_db', 'filesystem']:
                retention_minutes = settings.get('retention_minutes', 0)
                enabled = settings.get('enabled', True)
                if policy.set_file_retention(storage_type, retention_minutes * 60, enabled, updated_by):
                    updates.append(f"files.{storage_type}")
                else:
                    errors.append(f"Failed to update files.{storage_type}")
            else:
                errors.append(f"Invalid storage type: {storage_type}")

    # Update log retention
    if 'logs' in data:
        valid_log_types = ['access_logs', 'failed_upload_logs', 'virus_scan_logs', 'approval_requests']
        for log_type, settings in data['logs'].items():
            if log_type in valid_log_types:
                retention_minutes = settings.get('retention_minutes', 0)
                enabled = settings.get('enabled', True)
                if policy.set_log_retention(log_type, retention_minutes * 60, enabled, updated_by):
                    updates.append(f"logs.{log_type}")
                else:
                    errors.append(f"Failed to update logs.{log_type}")
            else:
                errors.append(f"Invalid log type: {log_type}")

    # Update cleanup interval
    if 'cleanup_interval_minutes' in data:
        interval = data['cleanup_interval_minutes']
        if isinstance(interval, int) and interval >= 1:
            if policy.set_cleanup_interval(interval * 60, updated_by):
                updates.append("cleanup_interval")
            else:
                errors.append("Failed to update cleanup_interval")
        else:
            errors.append("cleanup_interval_minutes must be >= 1")

    # Update dry run
    if 'dry_run' in data:
        if policy.set_dry_run(bool(data['dry_run']), updated_by):
            updates.append("dry_run")
        else:
            errors.append("Failed to update dry_run")

    return jsonify({
        'success': len(errors) == 0,
        'updated': updates,
        'errors': errors,
        'summary': policy.get_policy_summary()
    })


@retention_bp.route('/reload', methods=['POST'])
def reload_policy():
    """
    Reload the retention policy from the config file.

    Returns:
        JSON with the reloaded policy
    """
    policy = get_retention_policy()
    policy.reload()

    return jsonify({
        'success': True,
        'message': 'Policy reloaded from config file',
        'policy': policy.get_policy(),
        'summary': policy.get_policy_summary()
    })
