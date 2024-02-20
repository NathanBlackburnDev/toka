// Adjust the size of the page
addEventListener('DOMContentLoaded', () => {
    const range = document.getElementById('range');

    range.addEventListener('change', () => {
        // Save the size and set it
        document.documentElement.style.fontSize = range.value + 'px';
        localStorage.setItem('size', range.value);
        const getSize = localStorage.getItem('size');
        range.value = getSize;
        document.documentElement.style.fontSize = range.value + 'px';
    })
})