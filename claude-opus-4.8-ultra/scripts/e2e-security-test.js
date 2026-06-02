'use strict';

/**
 * End-to-end security + functional smoke test. Run against a live dev server.
 * Not part of the app; lives in scripts/ for manual verification.
 */

const BASE = process.env.BASE || 'http://127.0.0.1:3100';

let passed = 0;
let failed = 0;
function check(name, cond, extra = '') {
  if (cond) {
    passed++;
    console.log(`  PASS  ${name}`);
  } else {
    failed++;
    console.log(`  FAIL  ${name} ${extra}`);
  }
}

// Minimal cookie jar.
function makeJar() {
  const cookies = {};
  return {
    header() {
      return Object.entries(cookies)
        .map(([k, v]) => `${k}=${v}`)
        .join('; ');
    },
    store(res) {
      const raw = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
      for (const c of raw) {
        const [pair] = c.split(';');
        const idx = pair.indexOf('=');
        cookies[pair.slice(0, idx)] = pair.slice(idx + 1);
      }
    },
  };
}

async function get(jar, path) {
  const res = await fetch(BASE + path, {
    headers: { cookie: jar.header() },
    redirect: 'manual',
  });
  jar.store(res);
  const body = await res.text();
  return { res, body };
}

async function post(jar, path, form, { follow = false } = {}) {
  const res = await fetch(BASE + path, {
    method: 'POST',
    headers: {
      cookie: jar.header(),
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams(form).toString(),
    redirect: follow ? 'follow' : 'manual',
  });
  jar.store(res);
  const body = await res.text();
  return { res, body };
}

function csrfFrom(html) {
  const m = html.match(/name="_csrf" value="([^"]+)"/);
  return m ? m[1] : null;
}

async function register(jar, username, password) {
  const { body } = await get(jar, '/register');
  const token = csrfFrom(body);
  return post(jar, '/register', { _csrf: token, username, password });
}

(async () => {
  console.log(`Testing ${BASE}\n`);

  // --- Security headers ---
  console.log('Security headers:');
  {
    const { res } = await get(makeJar(), '/login');
    check('Content-Security-Policy present', !!res.headers.get('content-security-policy'));
    check(
      "CSP forbids inline script (no 'unsafe-inline' in script-src)",
      !/script-src[^;]*unsafe-inline/.test(res.headers.get('content-security-policy') || '')
    );
    check('X-Content-Type-Options: nosniff', res.headers.get('x-content-type-options') === 'nosniff');
    check('X-Frame-Options or frame-ancestors set',
      !!res.headers.get('x-frame-options') ||
      /frame-ancestors/.test(res.headers.get('content-security-policy') || ''));
    check('No X-Powered-By header', !res.headers.get('x-powered-by'));
  }

  // --- Unauthenticated access is blocked ---
  console.log('\nAuthentication gate:');
  {
    const jar = makeJar();
    const { res } = await get(jar, '/notes');
    check('GET /notes unauthenticated redirects to /login',
      res.status === 302 && (res.headers.get('location') || '').includes('/login'),
      `(status ${res.status})`);
  }

  // --- CSRF protection ---
  console.log('\nCSRF protection:');
  {
    const jar = makeJar();
    await get(jar, '/register'); // establish session cookie
    const { res } = await post(jar, '/register', {
      username: 'csrfuser', password: 'longenoughpassword',
    }); // no _csrf token
    check('POST without CSRF token is rejected (403)', res.status === 403, `(status ${res.status})`);
  }

  // --- Weak password rejected ---
  console.log('\nInput validation:');
  {
    const jar = makeJar();
    const { res, body } = await register(jar, 'shortpw', 'short');
    check('Password < 12 chars rejected (400)', res.status === 400, `(status ${res.status})`);
    check('Validation message shown', /at least 12 characters/.test(body));
  }

  // --- Happy path: register, create, list ---
  console.log('\nCRUD + XSS escaping:');
  const alice = makeJar();
  let aliceNoteId = null;
  {
    const reg = await register(alice, 'alice', 'alicepassword123');
    check('Alice registers and is redirected', reg.res.status === 302);

    // Create a note with an XSS payload in the title.
    const list = await get(alice, '/notes');
    const token = csrfFrom(list.body);
    await post(alice, '/notes', {
      _csrf: token,
      title: '<script>alert(1)</script>',
      content: 'first note "body" <img src=x onerror=alert(1)>',
    });

    const after = await get(alice, '/notes');
    check('Note appears in list', /first note/.test(after.body));
    check('XSS payload is HTML-escaped (no raw <script>)',
      !/<script>alert\(1\)<\/script>/.test(after.body));
    check('XSS payload appears escaped (&lt;script&gt;)',
      /&lt;script&gt;/.test(after.body));

    const idMatch = after.body.match(/\/notes\/(\d+)\/edit/);
    aliceNoteId = idMatch ? idMatch[1] : null;
    check('Alice note id captured', !!aliceNoteId, `(got ${aliceNoteId})`);
  }

  // --- Authorization / IDOR: Bob cannot touch Alice's note ---
  console.log('\nAuthorization (IDOR):');
  {
    const bob = makeJar();
    await register(bob, 'bob', 'bobpassword12345');

    const edit = await get(bob, `/notes/${aliceNoteId}/edit`);
    check("Bob GET Alice's note edit -> 404", edit.res.status === 404, `(status ${edit.res.status})`);

    const list = await get(bob, '/notes');
    const token = csrfFrom(list.body);
    const upd = await post(bob, `/notes/${aliceNoteId}`, {
      _csrf: token, title: 'hacked', content: 'pwned',
    });
    check("Bob UPDATE Alice's note -> 404", upd.res.status === 404, `(status ${upd.res.status})`);

    const del = await post(bob, `/notes/${aliceNoteId}/delete`, { _csrf: token });
    check("Bob DELETE Alice's note -> redirect but no effect",
      del.res.status === 302);

    // Confirm Alice's note still exists & unchanged.
    const aliceList = await get(alice, '/notes');
    check("Alice's note survived Bob's attacks", /first note/.test(aliceList.body) &&
      !/hacked/.test(aliceList.body));
  }

  // --- SQL injection attempt in login ---
  console.log('\nSQL injection resistance:');
  {
    const jar = makeJar();
    const { body } = await get(jar, '/login');
    const token = csrfFrom(body);
    const inj = await post(jar, '/login', {
      _csrf: token,
      username: "alice' OR '1'='1",
      password: "anything' OR '1'='1",
    });
    check('SQLi login attempt does NOT authenticate',
      inj.res.status !== 302 || !(inj.res.headers.get('location') || '').includes('/notes'),
      `(status ${inj.res.status}, loc ${inj.res.headers.get('location')})`);
  }

  // --- Update + delete happy path ---
  console.log('\nUpdate & delete (owner):');
  {
    const editPage = await get(alice, `/notes/${aliceNoteId}/edit`);
    const token = csrfFrom(editPage.body);
    await post(alice, `/notes/${aliceNoteId}`, {
      _csrf: token, title: 'updated title', content: 'updated body',
    });
    const list1 = await get(alice, '/notes');
    check('Owner can update note', /updated title/.test(list1.body));

    const list1Token = csrfFrom(list1.body);
    await post(alice, `/notes/${aliceNoteId}/delete`, { _csrf: list1Token });
    const list2 = await get(alice, '/notes');
    check('Owner can delete note', !/updated title/.test(list2.body));
  }

  console.log(`\n==== ${passed} passed, ${failed} failed ====`);
  process.exit(failed ? 1 : 0);
})().catch((e) => {
  console.error('Test harness error:', e);
  process.exit(2);
});
