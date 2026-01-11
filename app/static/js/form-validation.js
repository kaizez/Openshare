document.addEventListener('DOMContentLoaded', function() {
    // Password validation
    const passwordInput = document.getElementById('password');
    const confirmPasswordInput = document.getElementById('confirm_password');
    const passwordMatchMessage = document.getElementById('password-match-message');

    // Input sanitization function
    function sanitizeInput(input) {
        // Remove any HTML tags and trim whitespace
        return input.replace(/<[^>]*>/g, '').trim();
    }

    // Apply sanitization to all form inputs on submit
    const authForms = document.querySelectorAll('.auth-form');
    authForms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const inputs = form.querySelectorAll('input[type="text"], input[type="email"]');
            inputs.forEach(input => {
                input.value = sanitizeInput(input.value);
            });
        });
    });

    if (passwordInput) {
        const passwordRequirements = document.querySelector('.password-requirements');

        // Show requirements when user focuses or starts typing
        passwordInput.addEventListener('focus', function() {
            if (passwordRequirements) {
                passwordRequirements.classList.add('show');
            }
        });

        // Real-time password requirements validation
        passwordInput.addEventListener('input', function() {
            const password = this.value;

            // Show requirements if user starts typing
            if (passwordRequirements && password.length > 0) {
                passwordRequirements.classList.add('show');
            } else if (passwordRequirements && password.length === 0) {
                passwordRequirements.classList.remove('show');
            }

            // Check each requirement
            const hasLength = password.length >= 8;
            const hasUppercase = /[A-Z]/.test(password);
            const hasLowercase = /[a-z]/.test(password);
            const hasNumber = /\d/.test(password);
            const hasSpecial = /[@$!%*?&]/.test(password);

            // Update UI for each requirement
            updateRequirement('req-length', hasLength);
            updateRequirement('req-uppercase', hasUppercase);
            updateRequirement('req-lowercase', hasLowercase);
            updateRequirement('req-number', hasNumber);
            updateRequirement('req-special', hasSpecial);

            // Check password match if confirm field has value
            if (confirmPasswordInput && confirmPasswordInput.value) {
                checkPasswordMatch();
            }
        });

        // Hide requirements when user leaves the field if it's empty
        passwordInput.addEventListener('blur', function() {
            if (passwordRequirements && this.value.length === 0) {
                passwordRequirements.classList.remove('show');
            }
        });
    }

    if (confirmPasswordInput) {
        // Check password match in real-time
        confirmPasswordInput.addEventListener('input', checkPasswordMatch);
    }

    function updateRequirement(elementId, isMet) {
        const element = document.getElementById(elementId);
        if (element) {
            if (isMet) {
                element.classList.add('requirement-met');
                element.classList.remove('requirement-unmet');
            } else {
                element.classList.add('requirement-unmet');
                element.classList.remove('requirement-met');
            }
        }
    }

    function checkPasswordMatch() {
        if (!passwordInput || !confirmPasswordInput || !passwordMatchMessage) return;

        const password = passwordInput.value;
        const confirmPassword = confirmPasswordInput.value;

        if (confirmPassword === '') {
            passwordMatchMessage.textContent = '';
            passwordMatchMessage.className = 'form-text';
            return;
        }

        if (password === confirmPassword) {
            passwordMatchMessage.textContent = '✓ Passwords match';
            passwordMatchMessage.className = 'form-text text-success';
        } else {
            passwordMatchMessage.textContent = '✗ Passwords do not match';
            passwordMatchMessage.className = 'form-text text-danger';
        }
    }
});
