// Dashboard JavaScript for Playbook Actions

// Show Block IP Modal
function showBlockIPModal(ipAddress, description) {
    document.getElementById('blockIPAddress').value = ipAddress;
    document.getElementById('blockIPDisplay').value = ipAddress;
    document.getElementById('blockIPReason').value = `Blocked due to: ${description}`;
    document.getElementById('blockIPModal').style.display = 'block';
}

// Show Terminate Session Modal
function showTerminateSessionModal(userId, description) {
    document.getElementById('terminateUserID').value = userId;
    document.getElementById('terminateUserIDDisplay').value = userId;
    document.getElementById('terminateSessionReason').value = `Terminated due to: ${description}`;
    document.getElementById('terminateSessionModal').style.display = 'block';
}

// Show Quarantine File Modal
function showQuarantineFileModal(fileName, userId, ipAddress, description) {
    document.getElementById('quarantineFileName').value = fileName;
    document.getElementById('quarantineFileNameDisplay').value = fileName;
    document.getElementById('quarantineFileUserID').value = userId || '';
    document.getElementById('quarantineFileIP').value = ipAddress || '';
    document.getElementById('quarantineFileReason').value = `Quarantined due to: ${description}`;
    document.getElementById('quarantineFileModal').style.display = 'block';
}

// Close Modal
function closeModal(modalId) {
    document.getElementById(modalId).style.display = 'none';
}

// Close modal when clicking outside
window.onclick = function(event) {
    const modals = ['blockIPModal', 'terminateSessionModal', 'quarantineFileModal'];
    modals.forEach(modalId => {
        const modal = document.getElementById(modalId);
        if (event.target == modal) {
            modal.style.display = 'none';
        }
    });
}

// Block IP Form Handler
document.getElementById('blockIPForm').addEventListener('submit', async function(e) {
    e.preventDefault();

    const formData = {
        ip_address: document.getElementById('blockIPAddress').value,
        reason: document.getElementById('blockIPReason').value
    };

    try {
        const response = await fetch('/siem/api/playbook/block_ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(formData)
        });
        const result = await response.json();
        if (result.status === 'success') {
            alert(`Success: ${result.message}`);
            closeModal('blockIPModal');
            location.reload();
        } else {
            alert(`Error: ${result.message}`);
        }
    } catch (error) {
        alert(`Error: ${error.message}`);
    }
});

// Terminate Session Form Handler
document.getElementById('terminateSessionForm').addEventListener('submit', async function(e) {
    e.preventDefault();

    const formData = {
        user_id: parseInt(document.getElementById('terminateUserID').value),
        reason: document.getElementById('terminateSessionReason').value
    };

    try {
        const response = await fetch('/siem/api/playbook/terminate_session', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(formData)
        });
        const result = await response.json();
        if (result.status === 'success') {
            alert(`Success: ${result.message}`);
            closeModal('terminateSessionModal');
            location.reload();
        } else {
            alert(`Error: ${result.message}`);
        }
    } catch (error) {
        alert(`Error: ${error.message}`);
    }
});

// Quarantine File Form Handler
document.getElementById('quarantineFileForm').addEventListener('submit', async function(e) {
    e.preventDefault();

    const formData = {
        file_name: document.getElementById('quarantineFileName').value,
        reason: document.getElementById('quarantineFileReason').value,
        user_id: document.getElementById('quarantineFileUserID').value || null,
        ip_address: document.getElementById('quarantineFileIP').value || null
    };

    try {
        const response = await fetch('/siem/api/playbook/quarantine_file', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(formData)
        });
        const result = await response.json();
        if (result.status === 'success') {
            alert(`Success: ${result.message}`);
            closeModal('quarantineFileModal');
            location.reload();
        } else {
            alert(`Error: ${result.message}`);
        }
    } catch (error) {
        alert(`Error: ${error.message}`);
    }
});

// Release IP Handler
async function releaseIP(ipAddress) {
    if (!confirm(`Are you sure you want to release IP ${ipAddress} from quarantine?`)) {
        return;
    }

    try {
        const response = await fetch('/siem/api/playbook/release_ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip_address: ipAddress })
        });
        const result = await response.json();
        if (result.status === 'success') {
            alert(`Success: ${result.message}`);
            location.reload();
        } else {
            alert(`Error: ${result.message}`);
        }
    } catch (error) {
        alert(`Error: ${error.message}`);
    }
}
