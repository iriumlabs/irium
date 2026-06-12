(function () {
  function initNav() {
    var navLinks = document.getElementById('nav-links') || document.querySelector('.nav-links');
    if (!navLinks) return;

    var btn = document.getElementById('nav-hamburger');

    // Inject button if not already in the HTML
    if (!btn) {
      btn = document.createElement('button');
      btn.id = 'nav-hamburger';
      btn.className = 'nav-hamburger';
      btn.setAttribute('aria-label', 'Toggle navigation');
      btn.setAttribute('aria-expanded', 'false');
      for (var i = 0; i < 3; i++) btn.appendChild(document.createElement('span'));
      var container = navLinks.closest('.container') || navLinks.parentElement;
      container.insertBefore(btn, navLinks);
    }

    // Ensure nav-links has an id so CSS can target it
    if (!navLinks.id) navLinks.id = 'nav-links';

    // Clone to strip any existing inline listeners, then re-wire cleanly
    var freshBtn = btn.cloneNode(true);
    btn.parentNode.replaceChild(freshBtn, btn);
    btn = freshBtn;

    btn.addEventListener('click', function () {
      var open = navLinks.classList.toggle('is-open');
      btn.classList.toggle('is-open', open);
      btn.setAttribute('aria-expanded', open ? 'true' : 'false');
    });

    navLinks.querySelectorAll('a').forEach(function (a) {
      a.addEventListener('click', function () {
        navLinks.classList.remove('is-open');
        btn.classList.remove('is-open');
        btn.setAttribute('aria-expanded', 'false');
      });
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initNav);
  } else {
    initNav();
  }
})();
