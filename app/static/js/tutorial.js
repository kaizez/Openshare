// Tutorial System
class Tutorial {
    constructor(steps) {
        this.steps = steps;
        this.currentStep = 0;
        this.overlay = null;
        this.init();
    }

    init() {
        this.createOverlay();
        this.createHelpButton();
        this.attachEventListeners();
    }

    createHelpButton() {
        const helpButton = document.createElement('div');
        helpButton.className = 'help-button';
        helpButton.id = 'help-button';
        helpButton.innerHTML = `
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="white">
                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 17h-2v-2h2v2zm2.07-7.75l-.9.92C13.45 12.9 13 13.5 13 15h-2v-.5c0-1.1.45-2.1 1.17-2.83l1.24-1.26c.37-.36.59-.86.59-1.41 0-1.1-.9-2-2-2s-2 .9-2 2H8c0-2.21 1.79-4 4-4s4 1.79 4 4c0 .88-.36 1.68-.93 2.25z"/>
            </svg>
        `;
        helpButton.addEventListener('click', () => this.start());
        document.body.appendChild(helpButton);
    }

    createOverlay() {
        this.overlay = document.createElement('div');
        this.overlay.className = 'tutorial-overlay';
        this.overlay.id = 'tutorial-overlay';

        const content = document.createElement('div');
        content.className = 'tutorial-content';

        content.innerHTML = `
            <div class="tutorial-header">
                <div class="tutorial-icon">?</div>
                <h3>Quick Guide</h3>
            </div>
            <div class="tutorial-body" id="tutorial-body">
                <!-- Steps will be inserted here -->
            </div>
            <div class="tutorial-progress" id="tutorial-progress">
                <!-- Progress dots will be inserted here -->
            </div>
            <div class="tutorial-buttons">
                <button class="tutorial-btn btn-skip" id="btn-skip">Skip</button>
                <button class="tutorial-btn btn-prev" id="btn-prev" style="display: none;">Previous</button>
                <button class="tutorial-btn btn-next" id="btn-next">Next</button>
            </div>
        `;

        this.overlay.appendChild(content);
        document.body.appendChild(this.overlay);
    }

    attachEventListeners() {
        document.getElementById('btn-skip').addEventListener('click', () => this.close());
        document.getElementById('btn-next').addEventListener('click', () => this.nextStep());
        document.getElementById('btn-prev').addEventListener('click', () => this.prevStep());

        // Close on overlay click (but not on content click)
        this.overlay.addEventListener('click', (e) => {
            if (e.target === this.overlay) {
                this.close();
            }
        });
    }

    start() {
        this.currentStep = 0;
        this.renderSteps();
        this.renderProgress();
        this.showStep(0);
        this.overlay.classList.add('active');
    }

    close() {
        this.overlay.classList.remove('active');
    }

    renderSteps() {
        const body = document.getElementById('tutorial-body');
        body.innerHTML = '';

        this.steps.forEach((step, index) => {
            const stepDiv = document.createElement('div');
            stepDiv.className = 'tutorial-step';
            stepDiv.id = `step-${index}`;

            stepDiv.innerHTML = `
                <div class="step-title">${step.title}</div>
                <div class="step-description">${step.description}</div>
                ${step.highlight ? `<div class="step-highlight">${step.highlight}</div>` : ''}
            `;

            body.appendChild(stepDiv);
        });
    }

    renderProgress() {
        const progress = document.getElementById('tutorial-progress');
        progress.innerHTML = '';

        this.steps.forEach((_, index) => {
            const dot = document.createElement('div');
            dot.className = 'progress-dot';
            dot.id = `progress-dot-${index}`;
            progress.appendChild(dot);
        });
    }

    showStep(index) {
        // Hide all steps
        document.querySelectorAll('.tutorial-step').forEach(step => {
            step.classList.remove('active');
        });

        // Show current step
        document.getElementById(`step-${index}`).classList.add('active');

        // Update progress dots
        document.querySelectorAll('.progress-dot').forEach((dot, i) => {
            dot.classList.toggle('active', i === index);
        });

        // Update buttons
        const prevBtn = document.getElementById('btn-prev');
        const nextBtn = document.getElementById('btn-next');

        prevBtn.style.display = index > 0 ? 'block' : 'none';

        if (index === this.steps.length - 1) {
            nextBtn.textContent = 'Finish';
            nextBtn.className = 'tutorial-btn btn-finish';
        } else {
            nextBtn.textContent = 'Next';
            nextBtn.className = 'tutorial-btn btn-next';
        }
    }

    nextStep() {
        if (this.currentStep < this.steps.length - 1) {
            this.currentStep++;
            this.showStep(this.currentStep);
        } else {
            this.close();
        }
    }

    prevStep() {
        if (this.currentStep > 0) {
            this.currentStep--;
            this.showStep(this.currentStep);
        }
    }
}

// Initialize tutorial when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Check which page we're on and load appropriate tutorial
    const currentPath = window.location.pathname;

    let tutorialSteps = [];

    if (currentPath.includes('/login')) {
        tutorialSteps = [
            {
                title: 'Welcome to MoveIT Login',
                description: 'This is where you can access your MoveIT account. Let me show you how to get started!',
                highlight: '💡 Tip: You can close this guide anytime by clicking "Skip"'
            },
            {
                title: 'Enter Your Credentials',
                description: 'Type your username and password in the respective fields. Make sure your credentials are correct.',
                highlight: '🔒 Your password is securely encrypted'
            },
            {
                title: 'Forgot Your Password?',
                description: 'If you can\'t remember your password, click the "Forgot your password?" link below the password field to reset it.',
                highlight: '📧 You\'ll receive a reset link via email'
            },
            {
                title: 'Sign In with Google',
                description: 'You can also use Google OAuth to sign in quickly without typing your password.',
                highlight: '⚡ Fast and secure authentication'
            },
            {
                title: 'New to MoveIT?',
                description: 'Don\'t have an account yet? Click "Register here" at the bottom to create a new account.',
                highlight: '🎉 Registration is quick and easy!'
            }
        ];
    } else if (currentPath.includes('/register')) {
        tutorialSteps = [
            {
                title: 'Create Your MoveIT Account',
                description: 'Welcome! Let\'s set up your new account. Follow these steps to get started.',
                highlight: '🚀 You\'re just a few steps away!'
            },
            {
                title: 'Choose a Username',
                description: 'Pick a unique username that will identify you on MoveIT. This will be visible to other users.',
                highlight: '💡 Choose something memorable'
            },
            {
                title: 'Enter Your Email',
                description: 'Provide a valid email address. We\'ll use this for account verification and password recovery.',
                highlight: '📧 Make sure you have access to this email'
            },
            {
                title: 'Create a Strong Password',
                description: 'Your password must meet the security requirements shown below the field. Watch as each requirement turns green when met!',
                highlight: '🔒 Requirements: 8+ characters, uppercase, lowercase, number, and special character'
            },
            {
                title: 'Confirm Your Password',
                description: 'Type your password again to make sure it matches. You\'ll see a confirmation message when both passwords match.',
                highlight: '✓ Real-time validation helps prevent typos'
            },
            {
                title: 'Alternative: Sign Up with Google',
                description: 'Want to skip the form? You can also register using your Google account for faster setup.',
                highlight: '⚡ Quick registration with Google OAuth'
            }
        ];
    }

    // Only initialize tutorial if we have steps for this page
    if (tutorialSteps.length > 0) {
        new Tutorial(tutorialSteps);
    }
});
