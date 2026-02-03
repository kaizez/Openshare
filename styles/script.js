// Get DOM elements
const uploadArea = document.getElementById('uploadArea');
const fileInput = document.getElementById('fileInput');
const progressSection = document.getElementById('progressSection');
const successSection = document.getElementById('successSection');
const progressFill = document.getElementById('progressFill');
const progressText = document.getElementById('progressText');
const errorModal = document.getElementById('errorModal');

// Toast notification system
function showToast(message, type = 'success', duration = 5000) {
    // Create toast container if it doesn't exist
    let toastContainer = document.getElementById('toastContainer');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.id = 'toastContainer';
        toastContainer.className = 'toast-container';
        document.body.appendChild(toastContainer);
    }

    // Create toast element
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    // Icon based on type
    let icon = '';
    if (type === 'success') {
        icon = `<svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
        </svg>`;
    } else if (type === 'error') {
        icon = `<svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"/>
        </svg>`;
    } else if (type === 'warning') {
        icon = `<svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
            <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/>
        </svg>`;
    }

    toast.innerHTML = `
        <span class="toast-icon">${icon}</span>
        <span class="toast-message">${message}</span>
        <button class="toast-close" onclick="this.parentElement.remove()">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                <path d="M4.293 4.293a1 1 0 011.414 0L8 6.586l2.293-2.293a1 1 0 111.414 1.414L9.414 8l2.293 2.293a1 1 0 01-1.414 1.414L8 9.414l-2.293 2.293a1 1 0 01-1.414-1.414L6.586 8 4.293 5.707a1 1 0 010-1.414z"/>
            </svg>
        </button>
    `;

    toastContainer.appendChild(toast);

    // Trigger animation
    setTimeout(() => toast.classList.add('show'), 10);

    // Auto remove after duration
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, duration);
}

// Custom error modal functions
function showError(title, message) {
    document.getElementById('errorTitle').textContent = title;
    document.getElementById('errorMessage').textContent = message;
    errorModal.classList.add('show');
}

function closeErrorModal() {
    errorModal.classList.remove('show');
}

// Close modal when clicking outside
errorModal.addEventListener('click', function (e) {
    if (e.target === errorModal) {
        closeErrorModal();
    }
});

// Close modal with Escape key
document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && errorModal.classList.contains('show')) {
        closeErrorModal();
    }
});

// Prevent default drag behaviors
['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    uploadArea.addEventListener(eventName, preventDefaults, false);
    document.body.addEventListener(eventName, preventDefaults, false);
});

function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}

// Highlight drop area when item is dragged over it
['dragenter', 'dragover'].forEach(eventName => {
    uploadArea.addEventListener(eventName, highlight, false);
});

['dragleave', 'drop'].forEach(eventName => {
    uploadArea.addEventListener(eventName, unhighlight, false);
});

function highlight() {
    uploadArea.classList.add('drag-over');
}

function unhighlight() {
    uploadArea.classList.remove('drag-over');
}

// Handle dropped files
uploadArea.addEventListener('drop', handleDrop, false);

function handleDrop(e) {
    const dt = e.dataTransfer;
    const files = dt.files;

    if (files.length > 0) {
        handleFiles(files);
    }
}

// Handle file input change
fileInput.addEventListener('change', function () {
    if (this.files.length > 0) {
        handleFiles(this.files);
    }
});

// Click on upload area to trigger file input
uploadArea.addEventListener('click', function (e) {
    if (e.target === uploadArea || e.target.closest('.upload-icon') || e.target.tagName === 'H3') {
        fileInput.click();
    }
});

// Handle file upload
function handleFiles(files) {
    const file = files[0]; // Only handle first file

    // Validate file type FIRST (before any upload)
    if (!isValidFileType(file)) {
        const fileName = file.name.toLowerCase();
        const extension = fileName.split('.').pop();
        showError(
            'File Type Not Allowed',
            `The file type ".${extension}" is not supported.\n\nAllowed types:\n• Documents: PDF, DOC, DOCX, XLS, XLSX, PPT, PPTX\n• Images: PNG, JPG, JPEG, GIF\n• Archives: ZIP, RAR, 7Z, TAR, GZ\n• Videos: MP4, AVI, MKV, MOV\n• Audio: MP3\n• Text: TXT, CSV, JSON, XML`
        );
        return;
    }

    // Validate file size (500MB max)
    const maxSize = 500 * 1024 * 1024; // 500MB in bytes
    if (file.size > maxSize) {
        showError(
            'File Too Large',
            `Your file is ${formatFileSize(file.size)}.\n\nMaximum allowed size is 500MB.`
        );
        return;
    }

    // Show progress section
    uploadArea.style.display = 'none';
    progressSection.style.display = 'block';
    successSection.style.display = 'none';

    // Upload file
    uploadFile(file);
}

function uploadFile(file) {
    const formData = new FormData();
    formData.append('file', file);

    // Get data classification value
    const classification = document.getElementById('dataClassification').value;
    formData.append('classification', classification);

    const xhr = new XMLHttpRequest();

    // Track upload progress
    xhr.upload.addEventListener('progress', function (e) {
        if (e.lengthComputable) {
            const percentComplete = (e.loaded / e.total) * 100;
            progressFill.style.width = percentComplete + '%';
            progressText.textContent = `Uploading... ${Math.round(percentComplete)}%`;
        }
    });

    // When upload completes, show validation status
    xhr.upload.addEventListener('load', function () {
        progressFill.style.width = '100%';
        progressText.textContent = 'Scanning for viruses...';
    });

    // Handle upload completion
    xhr.addEventListener('load', function () {
        if (xhr.status === 200) {
            const response = JSON.parse(xhr.responseText);

            if (response.success) {
                // Show success section
                progressSection.style.display = 'none';
                successSection.style.display = 'block';

                // Display file info
                document.getElementById('fileName').textContent = response.filename;
                document.getElementById('fileSize').textContent = response.file_size;
                document.getElementById('expiresAt').textContent = response.expires_at;

                // Hide scan result section - users don't need to see VT scan status
                const scanResult = document.getElementById('scanResult');
                if (scanResult) {
                    scanResult.style.display = 'none';
                }

                // Get OTP section elements
                const otpSectionClean = document.getElementById('otpSectionClean');
                const otpSectionPending = document.getElementById('otpSectionPending');

                // Check if file is clean or pending scan
                if (response.otp_code) {
                    // File is clean - show OTP code
                    document.getElementById('otpCode').textContent = response.otp_code;
                    if (otpSectionClean) otpSectionClean.style.display = 'block';
                    if (otpSectionPending) otpSectionPending.style.display = 'none';
                    showToast('File uploaded successfully', 'success', 4000);
                } else {
                    // File is pending scan - hide OTP code
                    if (otpSectionClean) otpSectionClean.style.display = 'none';
                    if (otpSectionPending) otpSectionPending.style.display = 'block';
                    showToast('File uploaded - security scan in progress', 'warning', 5000);
                }

            } else {
                showError('Upload Failed', response.error || 'An unknown error occurred. Please try again.');
                resetUpload();
            }
        } else {
            const response = JSON.parse(xhr.responseText);
            showError('Upload Failed', response.error || 'Server error occurred. Please try again.');
            resetUpload();
        }
    });

    // Handle upload errors
    xhr.addEventListener('error', function () {
        showError('Connection Error', 'Failed to upload file. Please check your internet connection and try again.');
        resetUpload();
    });

    // Send request
    xhr.open('POST', '/upload');
    xhr.send(formData);
}

// Copy OTP code to clipboard
function copyOTP() {
    const otpCode = document.getElementById('otpCode').textContent;
    const copyBtn = document.querySelector('.otp-code-container .btn-copy');

    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(otpCode).then(function () {
            showCopyFeedback(copyBtn);
        });
    } else {
        // Fallback
        const tempInput = document.createElement('input');
        tempInput.value = otpCode;
        document.body.appendChild(tempInput);
        tempInput.select();
        document.execCommand('copy');
        document.body.removeChild(tempInput);
        showCopyFeedback(copyBtn);
    }
}

function showCopyFeedback(button) {
    const originalText = button.innerHTML;

    button.innerHTML = `
        <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
            <path d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"/>
        </svg>
        Copied!
    `;

    setTimeout(() => {
        button.innerHTML = originalText;
    }, 2000);
}

// Reset upload form
function resetUpload() {
    uploadArea.style.display = 'block';
    progressSection.style.display = 'none';
    successSection.style.display = 'none';
    fileInput.value = '';
    progressFill.style.width = '0%';
    progressText.textContent = 'Uploading...';
}

// Format file size
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';

    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

// Validate file type (basic check)
function isValidFileType(file) {
    const allowedExtensions = [
        'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx',
        'xls', 'xlsx', 'ppt', 'pptx', 'zip', 'rar', '7z', 'tar', 'gz',
        'mp3', 'mp4', 'avi', 'mkv', 'mov', 'csv', 'json', 'xml'
    ];

    const fileName = file.name.toLowerCase();
    const extension = fileName.split('.').pop();

    return allowedExtensions.includes(extension);
}
