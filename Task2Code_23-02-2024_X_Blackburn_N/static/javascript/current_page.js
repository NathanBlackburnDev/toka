//  Underline current page in navbar
addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.nav-link').forEach(
        link => {
            // Add aria-current = page + active to current page
            if (link.href === window.location.href) {
                link.setAttribute('aria-current', 'page');
                link.classList.add('active');
            }
        }
    )
})