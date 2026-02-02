// Get DOM elements
const uploadArea = document.getElementById('uploadArea');
const fileInput = document.getElementById('fileInput');
const progressSection = document.getElementById('progressSection');
const successSection = document.getElementById('successSection');
const progressFill = document.getElementById('progressFill');
const progressText = document.getElementById('progressText');
const errorModal = document.getElementById('errorModal');

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
errorModal.addEventListener('click', function(e) {
    if (e.target === errorModal) {
        closeErrorModal();
    }
});

// Close modal with Escape key
document.addEventListener('keydown', function(e) {
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
fileInput.addEventListener('change', function() {
    if (this.files.length > 0) {
        handleFiles(this.files);
    }
});

// Click on upload area to trigger file input
uploadArea.addEventListener('click', function(e) {
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
    xhr.upload.addEventListener('progress', function(e) {
        if (e.lengthComputable) {
            const percentComplete = (e.loaded / e.total) * 100;
            progressFill.style.width = percentComplete + '%';
            progressText.textContent = `Uploading... ${Math.round(percentComplete)}%`;
        }
    });

    // When upload completes, show validation status
    xhr.upload.addEventListener('load', function() {
        progressFill.style.width = '100%';
        progressText.textContent = 'Validating file type...';
    });

    // Handle upload completion
    xhr.addEventListener('load', function() {
        if (xhr.status === 200) {
            const response = JSON.parse(xhr.responseText);

            if (response.success) {
                // Show success section
                progressSection.style.display = 'none';
                successSection.style.display = 'block';

                // Display file info
                document.getElementById('fileName').textContent = response.filename;
                document.getElementById('fileSize').textContent = response.file_size;

                // Display OTP code and expiration
                document.getElementById('otpCode').textContent = response.otp_code;
                document.getElementById('expiresAt').textContent = response.expires_at;
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
    xhr.addEventListener('error', function() {
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
        navigator.clipboard.writeText(otpCode).then(function() {
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
