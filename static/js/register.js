(function () {
  var step = Number(document.currentScript.dataset.startStep);
  var TT = ['', 'Buat akun FIT HUB', 'Pilih paket membership', 'Bayar dan kirim bukti'];
  var DD = ['', 'Isi data dirimu. Email dan password ini dipakai untuk masuk ke akun member.',
    'Makin panjang durasinya, makin hemat biaya per bulan.',
    'Bayar sesuai total, lalu unggah bukti. Setelah mengirim, kamu langsung masuk ke area member.'];
  var $ = function (id) { return document.getElementById(id); };
  var f = $('f'), errBox = $('err');

  function show(n) {
    step = n;
    document.querySelectorAll('section[data-step]').forEach(function (s) { s.classList.toggle('on', +s.dataset.step === n); });
    document.querySelectorAll('.steps li').forEach(function (li) {
      var k = +li.dataset.s; li.classList.toggle('on', k === n); li.classList.toggle('done', k < n);
    });
    $('ttl').textContent = TT[n]; $('dsc').textContent = DD[n];
    $('back').hidden = n === 1; $('toLogin').hidden = n !== 1;
    $('next').hidden = n === 3; $('send').hidden = n !== 3;
    if (n === 3) fillSummary();
    window.scrollTo(0, 0);
  }
  function bad(id, msg) {
    var fld = $(id).closest('.fld'); fld.classList.add('bad'); fld.querySelector('.msg').textContent = msg;
  }
  function clearBad() { document.querySelectorAll('.fld.bad').forEach(function (x) { x.classList.remove('bad'); }); errBox.textContent = ''; }
  function chosen() { return f.querySelector('input[name=package_id]:checked'); }
  function fillSummary() {
    var c = chosen(); if (!c) return;
    $('sName').textContent = c.dataset.name; $('sPrice').textContent = 'Rp ' + c.dataset.price; $('sPrice2').textContent = 'Rp ' + c.dataset.price;
  }

  async function step1() {
    clearBad(); var ok = true, first = null;
    function need(id, cond, msg) { if (!cond) { bad(id, msg); ok = false; if (!first) first = id; } }
    var name = $('name').value.trim().replace(/\s+/g, ' ');
    need('name', name.length >= 2 && name.length <= 60 && !/[<>"'&`\\]/.test(name), 'Nama 2-60 karakter, tanpa tanda < > " \' & ` atau garis miring terbalik.');
    var em = $('email').value.trim();
    need('email', /^[^\s@<>"'&`\\]+@[^\s@<>"'&`\\]+\.[^\s@<>"'&`\\]+$/.test(em), 'Masukkan alamat email yang valid.');
    need('phone', /^\+?[0-9]{9,15}$/.test($('phone').value.replace(/[\s-]/g, '')), 'Nomor HP 9-15 angka.');
    need('pw', $('pw').value.length >= 8, 'Minimal 8 karakter.');
    need('pw2', $('pw2').value === $('pw').value && $('pw2').value !== '', 'Password tidak sama.');
    if (ok) {
      try {
        var r = await fetch('/daftar/cek-email?e=' + encodeURIComponent(em), { credentials: 'same-origin' });
        var j = await r.json();
        if (!j.ok) { bad('email', j.msg || 'Email ini sudah terdaftar. Coba masuk.'); ok = false; first = 'email'; }
      } catch (e) { /* server akan memeriksa ulang saat dikirim */ }
    }
    if (first) $(first).focus();
    return ok;
  }

  $('next').addEventListener('click', async function () {
    if (step === 1) { var b = this; b.disabled = true; var ok = await step1(); b.disabled = false; if (ok) show(2); }
    else if (step === 2) { if (!chosen()) { $('pkmsg').style.display = 'block'; return; } show(3); }
  });
  $('back').addEventListener('click', function () { show(step - 1); });
  f.addEventListener('input', function (e) { var fld = e.target.closest && e.target.closest('.fld'); if (fld) fld.classList.remove('bad'); });
  f.querySelectorAll('input[name=package_id]').forEach(function (r) { r.addEventListener('change', function () { $('pkmsg').style.display = 'none'; }); });
  $('show').addEventListener('change', function () { $('pw').type = $('pw2').type = this.checked ? 'text' : 'password'; });
  f.querySelectorAll('input[name=payment_method]').forEach(function (r) {
    r.addEventListener('change', function () { var q = f.querySelector('input[name=payment_method]:checked').value === 'qris'; $('payQris').hidden = !q; $('payGopay').hidden = q; });
  });
  $('proof').addEventListener('change', function () {
    var file = this.files[0], p = $('prev'); errBox.textContent = '';
    if (!file) { p.style.display = 'none'; return; }
    if (!/^image\/(png|jpeg|webp)$/.test(file.type) || file.size > 5 * 1024 * 1024) {
      errBox.textContent = 'Bukti harus berupa JPG, PNG, atau WebP maksimal 5 MB.'; this.value = ''; p.style.display = 'none'; return;
    }
    p.src = URL.createObjectURL(file); p.style.display = 'block';
  });
  f.addEventListener('keydown', function (e) { if (e.key === 'Enter' && e.target.tagName === 'INPUT' && e.target.type !== 'submit') { e.preventDefault(); if (!$('next').hidden) $('next').click(); } });
  f.addEventListener('submit', function (e) {
    if (!$('proof').files[0]) { e.preventDefault(); errBox.textContent = 'Unggah bukti pembayaran dulu.'; return; }
    var s = $('send'); s.disabled = true; s.textContent = 'Mengirim...';
  });
  show(step);
})();
