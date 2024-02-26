// Disable 'Create account' button until user agrees to t&c's
addEventListener('DOMContentLoaded', () => {
    // Get buttons
    const agreeButton = document.getElementById('agreeButton');
    const submitButton = document.getElementById('submitButton');

    // Disable button
    submitButton.disabled = true;

    // Enable button
    agreeButton.addEventListener('click', () => {
        submitButton.disabled = false;
    })
})