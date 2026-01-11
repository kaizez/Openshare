// Language Switcher with Google Translate Integration
document.addEventListener('DOMContentLoaded', function() {
    const languageSelect = document.getElementById('language-select');

    if (!languageSelect) return;

    // Load Google Translate script
    const script = document.createElement('script');
    script.src = '//translate.google.com/translate_a/element.js?cb=googleTranslateElementInit';
    script.async = true;
    document.head.appendChild(script);

    // Store the original page content
    let isTranslated = false;
    let currentLanguage = 'en';

    // Initialize Google Translate
    window.googleTranslateElementInit = function() {
        new google.translate.TranslateElement({
            pageLanguage: 'en',
            includedLanguages: 'en,es,fr,de,zh-CN,ja,ko,ar,hi,pt,ru,it,nl,pl,tr,vi,th,id',
            layout: google.translate.TranslateElement.InlineLayout.SIMPLE,
            autoDisplay: false
        }, 'google_translate_element');

        // Hide the default Google Translate widget
        hideGoogleTranslateToolbar();
    };

    // Hide Google Translate toolbar
    function hideGoogleTranslateToolbar() {
        const style = document.createElement('style');
        style.innerHTML = `
            .goog-te-banner-frame.skiptranslate { display: none !important; }
            body { top: 0px !important; }
            .goog-te-balloon-frame { display: none !important; }
            .goog-tooltip { display: none !important; }
            .goog-tooltip:hover { display: none !important; }
            .goog-text-highlight { background-color: transparent !important; box-shadow: none !important; }
            #google_translate_element { display: none !important; }
        `;
        document.head.appendChild(style);
    }

    // Create hidden div for Google Translate element
    const translateDiv = document.createElement('div');
    translateDiv.id = 'google_translate_element';
    translateDiv.style.display = 'none';
    document.body.appendChild(translateDiv);

    // Load saved language preference
    const savedLanguage = localStorage.getItem('selectedLanguage') || 'en';
    languageSelect.value = savedLanguage;
    currentLanguage = savedLanguage;

    // Handle language selection - automatically translate
    languageSelect.addEventListener('change', function() {
        const selectedLanguage = this.value;

        // If same language, do nothing
        if (selectedLanguage === currentLanguage) {
            return;
        }

        // Save preference
        localStorage.setItem('selectedLanguage', selectedLanguage);
        currentLanguage = selectedLanguage;

        if (selectedLanguage === 'en') {
            // Reset to original English
            resetToEnglish();
        } else {
            // Trigger Google Translate automatically
            translatePage(selectedLanguage);
        }
    });

    // Function to translate page
    function translatePage(targetLang) {
        showNotification('Translating page...', 'info');

        // Wait for Google Translate to be ready
        let attempts = 0;
        const maxAttempts = 50;

        const checkGoogleTranslate = setInterval(function() {
            attempts++;
            const selectElement = document.querySelector('.goog-te-combo');

            if (selectElement) {
                clearInterval(checkGoogleTranslate);

                // Set the target language in Google Translate dropdown
                selectElement.value = targetLang;

                // Trigger the change event
                selectElement.dispatchEvent(new Event('change'));

                isTranslated = true;

                // Show success notification
                setTimeout(() => {
                    showNotification('Page translated successfully!', 'success');
                }, 500);
            } else if (attempts >= maxAttempts) {
                clearInterval(checkGoogleTranslate);
                showNotification('Translation failed. Please try again.', 'error');
                languageSelect.value = currentLanguage;
            }
        }, 100);
    }

    // Function to reset to English
    function resetToEnglish() {
        const selectElement = document.querySelector('.goog-te-combo');
        if (selectElement) {
            selectElement.value = 'en';
            selectElement.dispatchEvent(new Event('change'));
            isTranslated = false;
            showNotification('Switched to English', 'success');
        } else {
            // Reload page if Google Translate element not found
            location.reload();
        }
    }

    // Show notification
    function showNotification(message, type = 'info') {
        // Remove existing notification
        const existing = document.querySelector('.translate-notification');
        if (existing) {
            existing.remove();
        }

        const notification = document.createElement('div');
        notification.className = 'translate-notification';
        notification.textContent = message;
        document.body.appendChild(notification);

        const bgColors = {
            'info': 'linear-gradient(135deg, #4299e1 0%, #3182ce 100%)',
            'success': 'linear-gradient(135deg, #48bb78 0%, #38a169 100%)',
            'error': 'linear-gradient(135deg, #fc8181 0%, #f56565 100%)'
        };

        // Add styles
        notification.style.cssText = `
            position: fixed;
            top: 70px;
            right: 20px;
            background: ${bgColors[type]};
            color: white;
            padding: 12px 20px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 500;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
            z-index: 10001;
            animation: slideInRight 0.3s ease-out;
        `;

        // Add animation
        const styleSheet = document.createElement('style');
        styleSheet.textContent = `
            @keyframes slideInRight {
                from {
                    transform: translateX(100%);
                    opacity: 0;
                }
                to {
                    transform: translateX(0);
                    opacity: 1;
                }
            }
        `;
        if (!document.getElementById('notification-styles')) {
            styleSheet.id = 'notification-styles';
            document.head.appendChild(styleSheet);
        }

        // Remove after 3 seconds
        setTimeout(() => {
            notification.style.animation = 'slideInRight 0.3s ease-out reverse';
            setTimeout(() => notification.remove(), 300);
        }, 3000);
    }

    // Apply saved language on page load
    if (savedLanguage && savedLanguage !== 'en') {
        setTimeout(() => {
            translatePage(savedLanguage);
        }, 1500);
    }
});
