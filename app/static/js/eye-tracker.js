document.addEventListener('DOMContentLoaded', function() {
    const pupils = document.querySelectorAll('.pupil');
    const peekCharacter = document.querySelector('.peek-character');
    const inputFields = document.querySelectorAll('.form-control');
    const welcomeMessage = document.querySelector('.welcome-message');

    // Eye tracking functionality for all mascots (peek character + navbar/footer)
    document.addEventListener('mousemove', function(event) {
        const mouseX = event.clientX;
        const mouseY = event.clientY;

        pupils.forEach(pupil => {
            const eye = pupil.parentElement;

            const eyeRect = eye.getBoundingClientRect();
            const eyeCenterX = eyeRect.left + eyeRect.width / 2;
            const eyeCenterY = eyeRect.top + eyeRect.height / 2;

            const deltaX = mouseX - eyeCenterX;
            const deltaY = mouseY - eyeCenterY;

            const angle = Math.atan2(deltaY, deltaX);

            // Determine max distance based on parent container
            let maxDistance = 5;
            if (pupil.closest('.mascot-logo')) {
                maxDistance = 2; // Smaller movement for navbar mascot
            } else if (pupil.closest('.mascot-logo-small')) {
                maxDistance = 1.5; // Even smaller for footer mascot
            }

            const distance = Math.min(maxDistance, Math.sqrt(deltaX * deltaX + deltaY * deltaY) / 10);

            const pupilX = Math.cos(angle) * distance;
            const pupilY = Math.sin(angle) * distance;

            // Apply base offset for downward look (only for peek character)
            const baseOffsetX = 0;
            const baseOffsetY = pupil.closest('.peek-character') ? 3 : 0;

            pupil.style.transform = `translate(calc(-50% + ${baseOffsetX + pupilX}px), calc(-50% + ${baseOffsetY + pupilY}px))`;
        });
    });

    // Sunglasses on typing
    inputFields.forEach(input => {
        input.addEventListener('focus', function() {
            peekCharacter.classList.add('typing');
        });

        input.addEventListener('blur', function() {
            if (!this.value) {
                peekCharacter.classList.remove('typing');
            }
        });

        input.addEventListener('input', function() {
            if (this.value) {
                peekCharacter.classList.add('typing');
            } else {
                peekCharacter.classList.remove('typing');
            }
        });
    });

    // Welcome message on mascot click
    peekCharacter.addEventListener('click', function() {
        welcomeMessage.classList.add('show');

        // Hide the message after 2.5 seconds
        setTimeout(function() {
            welcomeMessage.classList.remove('show');
        }, 2500);
    });
});
