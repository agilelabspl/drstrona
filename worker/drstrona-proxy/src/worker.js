// ── RATE LIMITING (KV-based, per IP) ──
const RATE_LIMIT = 20;       // max requests
const RATE_WINDOW = 60;      // per 60 seconds

async function checkRateLimit(ip, kv) {
  const key = `rl:${ip}`;
  const data = await kv.get(key, 'json');
  const now = Date.now();
  if (data && (now - data.start) < RATE_WINDOW * 1000) {
    if (data.count >= RATE_LIMIT) return false;
    await kv.put(key, JSON.stringify({ start: data.start, count: data.count + 1 }), { expirationTtl: RATE_WINDOW });
    return true;
  }
  await kv.put(key, JSON.stringify({ start: now, count: 1 }), { expirationTtl: RATE_WINDOW });
  return true;
}

export default {
  async fetch(request, env) {
    const allowedOrigins = ['https://www.drstrona.pl', 'https://drstrona.pl', 'http://localhost:3000'];
    const reqOrigin = request.headers.get('Origin') || '';
    const origin = allowedOrigins.includes(reqOrigin) ? reqOrigin : allowedOrigins[0];

    const corsHeaders = {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);

    // ── USER API ──
    if (url.pathname === '/api/user' && request.method === 'POST') {
      return handleUserSave(request, env, corsHeaders);
    }
    if (url.pathname === '/api/users' && request.method === 'GET') {
      const token = request.headers.get('X-Admin-Token');
      if (!env.ADMIN_TOKEN || token !== env.ADMIN_TOKEN) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
          status: 401,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }
      return handleUsersList(env, corsHeaders);
    }

    const target = url.searchParams.get('url');

    if (!target) {
      return new Response(JSON.stringify({ error: 'Missing ?url= parameter' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    try {
      new URL(target);
    } catch {
      return new Response(JSON.stringify({ error: 'Invalid URL' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // ── RATE LIMIT CHECK ──
    const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
    const allowed = await checkRateLimit(clientIP, env.USERS);
    if (!allowed) {
      return new Response(JSON.stringify({ error: 'Rate limit exceeded. Try again in a minute.' }), {
        status: 429,
        headers: { ...corsHeaders, 'Content-Type': 'application/json', 'Retry-After': '60' },
      });
    }

    // ── REFERER/ORIGIN CHECK for proxy requests ──
    const referer = request.headers.get('Referer') || '';
    const isLegitRequest = allowedOrigins.includes(reqOrigin) || allowedOrigins.some(o => referer.startsWith(o));

    try {
      const chain = [target];
      let currentUrl = target;
      const maxRedirects = 10;

      for (let i = 0; i < maxRedirects; i++) {
        const resp = await fetch(currentUrl, {
          headers: {
            'User-Agent': 'Mozilla/5.0 (compatible; DrStrona/1.0)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'pl,en;q=0.5',
          },
          redirect: 'manual',
        });

        if (resp.status >= 300 && resp.status < 400) {
          const location = resp.headers.get('Location');
          if (!location) break;
          const nextUrl = new URL(location, currentUrl).href;
          chain.push(resp.status + ':' + nextUrl);
          currentUrl = nextUrl;
          continue;
        }

        // Final response
        let body = await resp.text();
        const xRobots = resp.headers.get('X-Robots-Tag') || '';
        const hsts = resp.headers.get('Strict-Transport-Security') || '';

        // Sprawdź czy HTML jest "pusty" (SPA/JS-heavy)
        // Browser rendering only for legitimate requests (costly operation)
        let renderedVia = 'fetch';
        if (isLegitRequest && isJSHeavy(body) && env.CF_ACCOUNT_ID && env.CF_BR_TOKEN) {
          try {
            const rendered = await renderWithBrowser(currentUrl, env);
            if (rendered && rendered.length > body.length) {
              body = rendered;
              renderedVia = 'browser';
            }
          } catch (e) {
            // fallback: zwróć oryginalny HTML
          }
        }

        return new Response(body, {
          status: resp.status,
          headers: {
            ...corsHeaders,
            'Content-Type': resp.headers.get('Content-Type') || 'text/html',
            'X-Proxy-Status': String(resp.status),
            'X-Proxy-Chain': JSON.stringify(chain),
            'X-Proxy-Final-Url': currentUrl,
            'X-Robots-Tag': xRobots,
            'X-Proxy-HSTS': hsts,
            'X-Proxy-Rendered': renderedVia,
            'Access-Control-Expose-Headers': 'X-Proxy-Chain, X-Proxy-Final-Url, X-Robots-Tag, X-Proxy-Status, X-Proxy-HSTS, X-Proxy-Rendered',
          },
        });
      }

      // Too many redirects
      return new Response(JSON.stringify({ error: 'Too many redirects' }), {
        status: 502,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), {
        status: 502,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }
  },
};

// Heurystyka: czy HTML wygląda na SPA/JS-heavy (mało treści, dużo skryptów)
function isJSHeavy(html) {
  const textOnly = html.replace(/<script[\s\S]*?<\/script>/gi, '')
                       .replace(/<style[\s\S]*?<\/style>/gi, '')
                       .replace(/<[^>]+>/g, '')
                       .replace(/\s+/g, ' ')
                       .trim();
  const wordCount = textOnly.split(/\s+/).filter(w => w.length > 1).length;
  const scriptCount = (html.match(/<script[\s ]/gi) || []).length;

  // Mało tekstu + dużo skryptów = JS-heavy
  if (wordCount < 80 && scriptCount >= 3) return true;

  // Znane frameworki SPA z pustym body
  const spaSignals = [
    '<div id="root"></div>',
    '<div id="app"></div>',
    '<div id="__next"></div>',
    '<div id="__nuxt">',
    'wix-thunderbolt',
  ];
  if (wordCount < 150 && spaSignals.some(s => html.includes(s))) return true;

  return false;
}

// Cloudflare Browser Rendering REST API
async function renderWithBrowser(targetUrl, env) {
  const endpoint = `https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/browser-rendering/content`;

  const resp = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${env.CF_BR_TOKEN}`,
    },
    body: JSON.stringify({
      url: targetUrl,
      gotoOptions: {
        waitUntil: 'networkidle0',
        timeout: 15000,
      },
    }),
  });

  if (!resp.ok) return null;
  return await resp.text();
}

// ── USER MANAGEMENT ──

const GOOGLE_CLIENT_ID = '359294549298-9mdj15320njchdvjl1gr31brgs19r5uq.apps.googleusercontent.com';

async function verifyGoogleToken(credential) {
  const resp = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${credential}`);
  if (!resp.ok) return null;
  const payload = await resp.json();
  if (payload.aud !== GOOGLE_CLIENT_ID) return null;
  return { email: payload.email, name: payload.given_name || payload.name };
}

async function handleUserSave(request, env, corsHeaders) {
  try {
    const { credential, scan_url, date } = await request.json();
    if (!credential) {
      return new Response(JSON.stringify({ error: 'Missing credential' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const verified = await verifyGoogleToken(credential);
    if (!verified) {
      return new Response(JSON.stringify({ error: 'Invalid Google token' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const key = `user:${verified.email}`;
    const existing = await env.USERS.get(key, 'json');

    const user = existing || { email: verified.email, name: verified.name, scans: [], created: date };
    user.name = verified.name || user.name;

    if (scan_url) {
      user.scans.push({ url: scan_url, date });
    }

    await env.USERS.put(key, JSON.stringify(user));

    return new Response(JSON.stringify({ ok: true }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
}

async function handleUsersList(env, corsHeaders) {
  const list = await env.USERS.list({ prefix: 'user:' });
  const users = [];
  for (const key of list.keys) {
    const data = await env.USERS.get(key.name, 'json');
    if (data) users.push(data);
  }
  return new Response(JSON.stringify(users), {
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}
