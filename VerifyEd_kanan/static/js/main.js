/* VerifyEd – Frontend JavaScript */

document.addEventListener('DOMContentLoaded', function () {

    // ================================================================
    // Auto-dismiss flash messages after 5 seconds
    // ================================================================
    const flashes = document.querySelectorAll('#flash-container .flash-msg');
    flashes.forEach(function (el, i) {
        setTimeout(function () {
            el.style.transition = 'opacity 0.4s, transform 0.4s';
            el.style.opacity = '0';
            el.style.transform = 'translateX(60px)';
            setTimeout(function () { el.remove(); }, 400);
        }, 5000 + i * 800);
    });

    // ================================================================
    // Mark single notification as read
    // ================================================================
    document.querySelectorAll('.notification-item').forEach(function (el) {
        el.addEventListener('click', function () {
            var id = el.getAttribute('data-id');
            fetch('/api/notifications/' + id + '/read', { method: 'POST' })
                .then(function () {
                    el.style.opacity = '0.4';
                });
        });
    });

    // ================================================================
    // Mark all notifications as read
    // ================================================================
    window.markAllRead = function () {
        fetch('/api/notifications/read-all', { method: 'POST' })
            .then(function () {
                document.querySelectorAll('.notification-item').forEach(function (el) {
                    el.style.opacity = '0.4';
                });
            });
    };

    // ================================================================
    // Doc type selection highlight (upload page)
    // ================================================================
    document.querySelectorAll('.doc-type-option input[type="radio"]').forEach(function (radio) {
        radio.addEventListener('change', function () {
            document.querySelectorAll('.doc-type-option > div').forEach(function (d) {
                d.classList.remove('border-brand-500', 'bg-brand-500/10');
            });
            if (radio.checked) {
                radio.nextElementSibling.classList.add('border-brand-500', 'bg-brand-500/10');
            }
        });
        // Init checked state
        if (radio.checked) {
            radio.nextElementSibling.classList.add('border-brand-500', 'bg-brand-500/10');
        }
    });

});
