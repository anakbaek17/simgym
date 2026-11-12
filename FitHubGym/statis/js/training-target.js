(function() {
    var sel = document.getElementById('targetMember');
    function setVal(id, v) { document.getElementById(id).value = v || ''; }
    function fill() {
        var o = sel.options[sel.selectedIndex];
        if (!o) return;
        var d = o.dataset;
        setVal('startWeight', d.sw || d.lw);
        setVal('targetWeight', d.tw);
        setVal('startBodyFat', d.sbf || d.lbf);
        setVal('targetBodyFat', d.tbf);
        setVal('targetNotes', d.notes);
    }
    sel.addEventListener('change', fill);
    fill();
})();
