function openPaymentModal(id, name, price, duration) {
    document.getElementById('paymentModal').style.display = 'flex';
    document.getElementById('modalPackageName').innerText = name;
    document.getElementById('modalPackagePrice').innerText = 'Rp ' + price.toLocaleString('id-ID');
    document.getElementById('inputPackageId').value = id;
    document.getElementById('modalQrisAmount').innerText = 'Rp ' + price.toLocaleString('id-ID');
    selectPaymentMethod('qris');
    // Harga dan durasi selalu diambil ulang dari database saat transaksi disimpan.
}
function closePaymentModal() {
    document.getElementById('paymentModal').style.display = 'none';
}
function selectPaymentMethod(type) {
    document.getElementById('qrisDetail').style.display = (type === 'qris') ? 'block' : 'none';
    document.getElementById('gopayDetail').style.display = (type === 'gopay_direct') ? 'block' : 'none';
    if(type === 'qris') document.getElementById('radioQris').checked = true;
    if(type === 'gopay_direct') document.getElementById('radioGopay').checked = true;
}

document.querySelectorAll('[data-package-id]').forEach(function (button) {
    button.addEventListener('click', function () {
        const pkg = button.dataset;
        openPaymentModal(Number(pkg.packageId), pkg.packageName,
            Number(pkg.packagePrice), Number(pkg.packageDuration));
    });
});

document.querySelector('[data-close-payment]').addEventListener('click', closePaymentModal);

document.querySelectorAll('[data-payment-method]').forEach(function (card) {
    card.addEventListener('click', function () {
        selectPaymentMethod(card.dataset.paymentMethod);
    });
});
