/* IT ELKHAWGA — مبدّل الوضع الليلي/النهاري (مشترك بين لوحة المدير وواجهة الموظف).
 * يُحمَّل في <head> بشكل متزامن حتى يُطبَّق الوضع قبل رسم الصفحة (بدون وميض). */
(function () {
  var KEY = 'itk_theme';
  var root = document.documentElement;

  function preferred() {
    try {
      var saved = localStorage.getItem(KEY);
      if (saved === 'dark' || saved === 'light') return saved;
    } catch (e) {}
    return (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) ? 'dark' : 'light';
  }

  function apply(theme) {
    root.setAttribute('data-theme', theme);
    var label = theme === 'dark' ? 'التبديل للوضع النهاري' : 'التبديل للوضع الليلي';
    var btns = document.querySelectorAll('[data-theme-toggle]');
    for (var i = 0; i < btns.length; i++) {
      btns[i].title = label;
      btns[i].setAttribute('aria-label', label);
    }
  }

  function toggle() {
    var next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    root.classList.add('theme-anim');
    apply(next);
    try { localStorage.setItem(KEY, next); } catch (e) {}
    clearTimeout(toggle._t);
    toggle._t = setTimeout(function () { root.classList.remove('theme-anim'); }, 450);
  }

  apply(preferred());

  document.addEventListener('click', function (e) {
    var btn = e.target.closest && e.target.closest('[data-theme-toggle]');
    if (btn) { e.preventDefault(); toggle(); }
  });
  document.addEventListener('DOMContentLoaded', function () { apply(root.getAttribute('data-theme') || 'light'); });

  window.itkTheme = { toggle: toggle, get: function () { return root.getAttribute('data-theme'); } };
})();
