// An honest visitor for the start of a benchmark round. A live site always has
// visitors, and Kagami's shadow learns public pages and the app's answer to a
// failed form post from them. Without this, the shadow would only know what
// the attacker itself fetched before it was contained.
//
// The visitor follows the links and submits the forms the site's own pages
// show, from the home page. It never reads HTML comments, so it never meets
// Kagami's bait, and it sends hidden form fields back unchanged, as a browser
// does. Every request carries the header X-Bench-Warmup, which the report uses
// to leave these requests out of the round.

const BROWSER = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15';
const MAX_PAGES = 40;
/** Two different, harmless values for each kind of field, so each form is submitted twice. */
const SAMPLES = {
  email: ['jamie.hart@example.com', 'priya.nair@example.com'],
  password: ['not-my-password-1', 'not-my-password-2'],
  search: ['jacket', 'beanie'],
  text: ['hello', 'thanks'],
};

const attr = (tag, name) => new RegExp(`\\s${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i').exec(tag)?.slice(2).find((v) => v !== undefined);
const decode = (s) => s.replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>');

function sameOrigin(base, href) {
  try {
    const u = new URL(decode(href), base);
    return u.origin === new URL(base).origin ? u : null;
  } catch {
    return null;
  }
}

function forms(html) {
  const out = [];
  const re = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let m;
  while ((m = re.exec(html))) {
    const inputs = [...m[2].matchAll(/<(input|textarea|select)\b([^>]*)>/gi)].map((i) => ({
      name: attr(i[2], 'name'),
      type: (attr(i[2], 'type') ?? 'text').toLowerCase(),
      value: attr(i[2], 'value') ?? '',
    }));
    out.push({ method: (attr(m[1], 'method') ?? 'get').toUpperCase(), action: attr(m[1], 'action') ?? '', inputs: inputs.filter((i) => i.name) });
  }
  return out;
}

function fill(inputs, n) {
  const params = new URLSearchParams();
  for (const i of inputs) {
    if (i.type === 'hidden' || i.type === 'submit') params.set(i.name, decode(i.value));
    else if (i.type === 'email' || /mail/i.test(i.name)) params.set(i.name, SAMPLES.email[n]);
    else if (i.type === 'password') params.set(i.name, SAMPLES.password[n]);
    else if (i.type === 'search' || /^(q|query|search|s)$/i.test(i.name)) params.set(i.name, SAMPLES.search[n]);
    else params.set(i.name, SAMPLES.text[n]);
  }
  return params;
}

/** Browse the site at `base` as an honest visitor. Returns what was visited. */
export async function warmup(base) {
  const headers = { 'user-agent': BROWSER, accept: 'text/html,application/xhtml+xml', 'x-bench-warmup': '1' };
  const seen = new Set();
  const queue = [new URL('/', base)];
  const result = { requests: 0, pages: 0, form_posts: 0, form_gets: 0 };
  const fetchText = async (url, init = {}) => {
    result.requests++;
    const res = await fetch(url, { redirect: 'manual', ...init, headers: { ...headers, ...(init.headers ?? {}) } });
    return { status: res.status, type: res.headers.get('content-type') ?? '', text: await res.text() };
  };
  // Browsers ask for the icon on their own. Where a site has none, this is
  // also how the shadow learns the site's own 404 page.
  await fetchText(new URL('/favicon.ico', base), { headers: { accept: 'image/avif,image/webp,image/*,*/*;q=0.8' } });
  while (queue.length && result.pages < MAX_PAGES) {
    const url = queue.shift();
    const key = url.pathname + url.search;
    if (seen.has(key)) continue;
    seen.add(key);
    const page = await fetchText(url);
    result.pages++;
    if (!page.type.includes('html')) continue;
    for (const m of page.text.matchAll(/<a\b[^>]*\shref\s*=\s*("([^"]*)"|'([^']*)')/gi)) {
      const next = sameOrigin(url, m[2] ?? m[3]);
      if (next && !seen.has(next.pathname + next.search)) queue.push(next);
    }
    for (const form of forms(page.text)) {
      const target = sameOrigin(url, form.action || url.pathname);
      if (!target) continue;
      for (const n of [0, 1]) {
        const params = fill(form.inputs, n);
        if (form.method === 'GET') {
          const u = new URL(target);
          u.search = params.toString();
          if (!seen.has(u.pathname + u.search)) queue.push(u);
          result.form_gets++;
        } else {
          await fetchText(target, { method: form.method, headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: params.toString() });
          result.form_posts++;
        }
      }
    }
  }
  return result;
}
