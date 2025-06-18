document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.flashes .close-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const li = btn.closest('li');
            if (li) li.style.display = 'none';
        });
    });

    document.querySelectorAll('.send-button').forEach(button => {
        button.addEventListener('click', () => {
            const row = button.closest('tr');
            const nextRow = row?.nextElementSibling;
            if (nextRow?.classList.contains('send-form-row')) {
                document.querySelectorAll('.send-form-row.show').forEach(r => {
                    if (r !== nextRow) r.classList.remove('show');
                });
                nextRow.classList.toggle('show');
            }
        });
    });

    const headers = document.querySelectorAll('.file-table thead th');
    headers.forEach((th, idx) => {
        const label = th.textContent.trim();
        document.querySelectorAll('.file-table tbody tr').forEach(tr => {
            if (tr.children[idx]) {
                tr.children[idx].setAttribute('data-label', label);
            }
        });
    });
});
