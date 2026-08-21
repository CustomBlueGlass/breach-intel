// Point canonical + social URLs at whatever host is serving the page, and
// register the site search action for the current origin. Served as a same-
// origin static file (not inline) so the page can enforce a strict
// Content-Security-Policy with script-src 'self' and no 'unsafe-inline'.
(function () {
  try {
    var origin = window.location.origin;
    var page = origin + window.location.pathname;
    var canon = document.querySelector('link[rel="canonical"]');
    if (canon) canon.setAttribute('href', page);
    function meta(attr, key, val) {
      var el = document.querySelector('meta[' + attr + '="' + key + '"]');
      if (!el) { el = document.createElement('meta'); el.setAttribute(attr, key); document.head.appendChild(el); }
      el.setAttribute('content', val);
    }
    meta('property', 'og:url', page);
    meta('name', 'twitter:url', page);
    var ld = document.createElement('script');
    ld.type = 'application/ld+json';
    ld.textContent = JSON.stringify({
      '@context': 'https://schema.org',
      '@type': 'WebSite',
      name: 'Breach Intelligence Platform',
      url: origin + '/',
      potentialAction: {
        '@type': 'SearchAction',
        target: origin + '/?q={search_term_string}',
        'query-input': 'required name=search_term_string'
      }
    });
    document.head.appendChild(ld);
  } catch (e) { /* non-fatal */ }
})();
