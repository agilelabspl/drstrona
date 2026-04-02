/**
 * Cookie Consent — drstrona.pl
 * Samodzielny skrypt (zero zależności).
 * Tworzy gtag stub, baner RODO, panel ustawień, warunkowe ładowanie GA4.
 */
(function () {
    'use strict';

    /* ── 1. gtag stub ── */
    window.dataLayer = window.dataLayer || [];
    function gtag() { dataLayer.push(arguments); }
    window.gtag = gtag;

    /* ── 2. Konfiguracja ── */
    var STORAGE_KEY = 'drstrona_cookie_consent';
    var CONSENT_VERSION = 1;
    var GA_ID = 'G-S3NVC7K6R4';

    /* ── 3. Helpers ── */
    function loadScript(src) {
        var s = document.createElement('script');
        s.async = true;
        s.src = src;
        document.head.appendChild(s);
    }

    /* ── 4. Ładowanie skryptów wg kategorii ── */
    function loadAnalytics() {
        loadScript('https://www.googletagmanager.com/gtag/js?id=' + GA_ID);
        gtag('js', new Date());
        gtag('config', GA_ID);
    }

    function applyConsent(prefs) {
        if (prefs.analytics) loadAnalytics();
    }

    /* ── 5. Odczyt / zapis zgody ── */
    function getConsent() {
        try {
            var raw = localStorage.getItem(STORAGE_KEY);
            if (!raw) return null;
            var data = JSON.parse(raw);
            if (data && data.version === CONSENT_VERSION) return data;
            return null;
        } catch (e) {
            return null;
        }
    }

    function saveConsent(analytics) {
        var prefs = {
            analytics: !!analytics,
            timestamp: new Date().toISOString(),
            version: CONSENT_VERSION
        };
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(prefs));
        } catch (e) { /* brak localStorage */ }
        return prefs;
    }

    /* ── 6. CSS banera ── */
    var CSS = '' +
    '#cc-banner{position:fixed;bottom:0;left:0;right:0;z-index:99999;font-family:"DM Sans",system-ui,-apple-system,sans-serif;' +
        'background:#fff;border-top:1px solid #e2e8f0;box-shadow:0 -4px 24px rgba(0,0,0,0.1);' +
        'transform:translateY(100%);transition:transform .4s cubic-bezier(.4,0,.2,1);padding:0}' +
    '#cc-banner.cc-visible{transform:translateY(0)}' +
    '#cc-inner{max-width:960px;margin:0 auto;padding:0.9rem 1.1rem}' +
    '#cc-text{font-size:0.82rem;line-height:1.45;color:#334155;margin-bottom:0.7rem}' +
    '#cc-text a{color:#5b5ee8;text-decoration:underline;text-underline-offset:2px}' +
    '#cc-buttons{display:flex;gap:0.5rem;flex-wrap:wrap}' +
    '#cc-buttons button{flex:1 1 0;min-width:140px;padding:0.5rem 0.75rem;border-radius:8px;font-size:0.85rem;font-weight:600;cursor:pointer;' +
        'font-family:inherit;border:none;transition:background .2s,transform .1s}' +
    '#cc-buttons button:active{transform:scale(0.97)}' +
    '#cc-accept{background:#5b5ee8;color:#fff}' +
    '#cc-accept:hover{background:#4a4dd4}' +
    '#cc-reject{background:#e2e8f0;color:#334155}' +
    '#cc-reject:hover{background:#cbd5e1}' +
    '#cc-admin{font-size:0.72rem;color:#94a3b8;margin-top:0.5rem;line-height:1.3}' +
    '@media(max-width:640px){' +
        '#cc-buttons{flex-direction:column}' +
        '#cc-buttons button{min-width:0;width:100%;padding:0.4rem 0.5rem;font-size:0.8rem}' +
        '#cc-inner{padding:0.5rem 0.75rem}' +
        '#cc-text{font-size:0.75rem;margin-bottom:0.4rem}' +
    '}';

    /* ── 7. HTML banera ── */
    function buildBanner() {
        var banner = document.createElement('div');
        banner.id = 'cc-banner';
        banner.setAttribute('role', 'dialog');
        banner.setAttribute('aria-label', 'Ustawienia prywatności');

        banner.innerHTML = '' +
        '<div id="cc-inner">' +
            '<div id="cc-text">' +
                'Używamy cookies analitycznych (Google Analytics), żeby wiedzieć jak korzystasz ze strony. ' +
                'Niezbędne cookies działają zawsze. ' +
                '<a href="https://agilelabs.pl/polityka_prywatnosci" target="_blank" rel="noopener noreferrer">Polityka prywatności</a>' +
            '</div>' +
            '<div id="cc-buttons">' +
                '<button id="cc-accept" type="button">Akceptuj</button>' +
                '<button id="cc-reject" type="button">Tylko niezbędne</button>' +
            '</div>' +
            '<div id="cc-admin">Administrator danych: Agilelabs Mobi-net Paweł Lewiński, pomoc@agilelabs.pl</div>' +
        '</div>';

        return banner;
    }

    /* ── 8. Link "Ustawienia cookies" w footerze ── */
    function injectFooterLink() {
        var a = document.getElementById('footer-cookie-settings');
        if (!a) return;

        a.addEventListener('click', function (e) {
            e.preventDefault();
            showBanner();
        });
    }

    /* ── 9. Pokaż / ukryj baner ── */
    var bannerEl;
    var isBuilt = false;

    function ensureBannerBuilt() {
        if (isBuilt) return;
        isBuilt = true;

        var style = document.createElement('style');
        style.textContent = CSS;
        document.head.appendChild(style);

        bannerEl = buildBanner();
        document.body.appendChild(bannerEl);

        bannerEl.querySelector('#cc-accept').addEventListener('click', function () {
            var prefs = saveConsent(true);
            applyConsent(prefs);
            hideBanner();
        });

        bannerEl.querySelector('#cc-reject').addEventListener('click', function () {
            saveConsent(false);
            hideBanner();
        });
    }

    function showBanner() {
        ensureBannerBuilt();
        requestAnimationFrame(function () {
            bannerEl.classList.add('cc-visible');
        });
    }

    function hideBanner() {
        if (!bannerEl) return;
        bannerEl.classList.remove('cc-visible');
    }

    /* ── 10. Inicjalizacja ── */
    function init() {
        var consent = getConsent();
        if (consent) {
            applyConsent(consent);
        } else {
            showBanner();
        }
        injectFooterLink();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
