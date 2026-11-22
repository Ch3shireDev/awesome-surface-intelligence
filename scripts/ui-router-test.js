// Test routera panelu ASI (DEV-14): adres w pasku = widok + obiekt.
// Wymaga: node, Chrome/Chromium oraz dzialajacego panelu (make up albo ./asi server) i .env z kontem admina.
//   make test-router                 # panel 127.0.0.1:18090 z .env
//   BASE=http://127.0.0.1:8092 node scripts/ui-router-test.js
// Skrypt nie zmienia danych poza utworzeniem i usunieciem tymczasowego konta viewer na potrzeby testu rol.
const fs = require('fs');
let puppeteer;
try { puppeteer = require('puppeteer-core'); } catch { console.error('brak modułu puppeteer-core: npm i puppeteer-core (albo NODE_PATH=/tmp/uitest/node_modules)'); process.exit(2); }
const path = require('path');
const BASE = process.env.BASE || 'http://127.0.0.1:18090';
const ROOT = path.resolve(__dirname, '..');
const envFile = [path.join(ROOT, '.env'), path.join(process.env.HOME || '', 'asi', '.env')].find(f => fs.existsSync(f));
if (!envFile) { console.error('brak .env (make env) — potrzebne ASI_ADMIN_USER/ASI_ADMIN_PASSWORD'); process.exit(2); }
const env = fs.readFileSync(envFile, 'utf8');
const get = k => (env.match(new RegExp('^' + k + '=(.*)$', 'm')) || [])[1].trim();
const USER = get('ASI_ADMIN_USER'), PASS = get('ASI_ADMIN_PASSWORD');
const CHROME = process.env.CHROME || ['/usr/bin/google-chrome-stable', '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser'].find(p => fs.existsSync(p));
if (!CHROME) { console.error('brak Chrome/Chromium: ustaw CHROME=/sciezka/do/przegladarki'); process.exit(2); }
if (!USER || !PASS) { console.error('brak ASI_ADMIN_USER/ASI_ADMIN_PASSWORD w .env (make env)'); process.exit(2); }

let ok = 0, bad = 0;
const chk = (name, cond, extra = '') => { cond ? ok++ : bad++; console.log(`${cond ? 'OK  ' : 'FAIL'} ${name}${extra ? ' -> ' + extra : ''}`); };
const sleep = ms => new Promise(r => setTimeout(r, ms));

(async () => {
  const browser = await puppeteer.launch({ executablePath: CHROME, headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] });
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  page.on('console', m => { if (m.type() === 'error') errors.push('console: ' + m.text()); });

  const st = () => page.evaluate(() => ({
    url: location.pathname + location.search,
    view: ['dash', 'assets', 'targets', 'scans', 'account', 'admin'].find(v => !document.getElementById('p-' + v).classList.contains('hidden')) || '',
    drawer: !document.getElementById('drawer').classList.contains('hidden'),
    key: document.getElementById('drawer').dataset.key || '',
    run: document.getElementById('drawer').dataset.run || '',
    rows: document.querySelectorAll('#a-rows tr.click').length,
    title: document.title,
  }));
  const back = async () => { await page.evaluate(() => history.back()); await sleep(500); };

  // A. niezalogowany na deep linku /assets -> formularz logowania, adres zostaje
  await page.goto(BASE + '/assets', { waitUntil: 'networkidle2' });
  chk('A1 niezalogowany: formularz logowania', await page.$eval('#v-login', e => !e.classList.contains('hidden')));
  chk('A2 adres /assets zachowany', (await st()).url === '/assets');

  // B. logowanie -> wracamy do /assets (deep link po logowaniu)
  await page.type('#l-user', USER);
  await page.type('#l-pass', PASS);
  await page.click('#f-login button[type=submit]');
  await page.waitForSelector('#v-app:not(.hidden)', { timeout: 8000 });
  await sleep(700);
  let s = await st();
  chk('B1 po logowaniu widok Assety', s.view === 'assets', s.view);
  chk('B2 adres /assets', s.url === '/assets', s.url);
  chk('B3 lista assetów niepusta', s.rows > 0, String(s.rows));

  // C. menu: Dashboard -> /
  await page.click('#nav button[data-p="dash"]');
  await sleep(600);
  s = await st();
  chk('C1 dashboard pod /', s.view === 'dash' && s.url === '/', s.view + ' ' + s.url);
  chk('C2 tytuł dokumentu', /Dashboard/.test(s.title), s.title);

  // D. kafelek KPI -> /assets z filtrami w query
  await page.waitForSelector('#kpis .kpi');
  await page.click('#kpis .kpi[data-i="0"]');
  await sleep(700);
  s = await st();
  chk('D1 kafelek otwiera /assets z filtrem', s.view === 'assets' && /^\/assets\?/.test(s.url), s.url);
  chk('D2 filtr w adresie (state/kind)', /state=live/.test(s.url) && /kind=host/.test(s.url), s.url);
  chk('D3 filtr zastosowany do listy', s.rows > 0, String(s.rows));

  // E. klik w wiersz -> szuflada assetu z kluczem w ścieżce
  const rowKey = await page.$eval('#a-rows tr.click', tr => tr.dataset.k);
  await page.click('#a-rows tr.click');
  await sleep(800);
  s = await st();
  chk('E1 szuflada otwarta', s.drawer);
  chk('E2 klucz assetu w ścieżce', s.url.startsWith('/assets/' + encodeURIComponent(rowKey)), s.url);
  chk('E3 klucz w szufladzie zgodny', s.key === rowKey, s.key);
  chk('E4 filtry zachowane przy assercie', /state=live/.test(s.url), s.url);
  chk('E5 menu podświetla Assety', await page.$eval('#nav button.on', b => b.dataset.p) === 'assets');

  // F. wstecz zamyka szufladę, zostaje lista z filtrami
  await back();
  s = await st();
  chk('F1 wstecz zamyka szufladę', !s.drawer);
  chk('F2 wstecz wraca do listy z filtrami', s.view === 'assets' && s.url === '/assets?state=live&kind=host', s.url);

  // G. deep link do assetu (nowa karta, ta sama sesja)
  const deep = '/assets/' + encodeURIComponent(rowKey) + '?state=live&kind=host';
  const p2 = await browser.newPage();
  p2.on('pageerror', e => errors.push('p2: ' + e.message));
  await p2.goto(BASE + deep, { waitUntil: 'networkidle2' });
  await sleep(900);
  const s2 = await p2.evaluate(() => ({
    view: ['dash', 'assets', 'targets', 'scans', 'account', 'admin'].find(v => !document.getElementById('p-' + v).classList.contains('hidden')) || '',
    drawer: !document.getElementById('drawer').classList.contains('hidden'),
    key: document.getElementById('drawer').dataset.key || '',
    url: location.pathname + location.search,
    h3: (document.querySelector('#drawer h3') || {}).textContent || '',
  }));
  chk('G1 deep link: widok Assety', s2.view === 'assets', s2.view);
  chk('G2 deep link: szuflada otwarta', s2.drawer);
  chk('G3 deep link: właściwy asset', s2.key === rowKey && s2.h3 === rowKey, s2.key + '/' + s2.h3);
  chk('G4 deep link: adres bez zmian', s2.url === deep, s2.url);

  // H. Escape przy wejściu z linku tylko czyści adres (nie wychodzi z panelu)
  await p2.keyboard.press('Escape');
  await sleep(500);
  const s2b = await p2.evaluate(() => ({ drawer: !document.getElementById('drawer').classList.contains('hidden'), url: location.pathname + location.search, view: ['dash', 'assets', 'targets', 'scans', 'account', 'admin'].find(v => !document.getElementById('p-' + v).classList.contains('hidden')) }));
  chk('H1 Escape zamyka szufladę', !s2b.drawer);
  chk('H2 Escape czyści klucz z adresu', s2b.url.startsWith('/assets?') || s2b.url === '/assets', s2b.url);
  chk('H3 nadal w panelu', s2b.view === 'assets');
  await p2.close(); // dalej testujemy na pierwszej karcie

  // I. skany: przebieg w ścieżce
  await page.goto(BASE + '/scans', { waitUntil: 'networkidle2' });
  await sleep(900);
  s = await st();
  chk('I1 /scans otwiera widok Skany', s.view === 'scans' && s.url === '/scans', s.view + ' ' + s.url);
  const runId = await page.evaluate(() => document.querySelector('tr[data-run]').dataset.run);
  await page.evaluate(() => document.querySelector('tr[data-run]').click());
  await sleep(700);
  s = await st();
  chk('I2 przebieg w ścieżce', s.url === '/scans/' + encodeURIComponent(runId), s.url);
  chk('I3 szuflada przebiegu', s.drawer && s.run === runId, s.run);

  // J. z szuflady przebiegu klik w zmianę -> asset w zakładce Assety, wstecz wraca do przebiegu
  // (szukamy przebiegu, który ma zmiany)
  let hasEv = await page.evaluate(() => !!document.querySelector('#drawer tr.click'));
  const allRuns = await page.evaluate(() => [...document.querySelectorAll('tr[data-run]')].map(tr => tr.dataset.run));
  let runWithEvents = runId;
  for (const r of allRuns) {
    if (hasEv) break;
    await page.goto(BASE + '/scans/' + encodeURIComponent(r), { waitUntil: 'networkidle2' });
    await sleep(600);
    hasEv = await page.evaluate(() => !!document.querySelector('#drawer tr.click'));
    if (hasEv) runWithEvents = r;
  }
  if (hasEv) {
    await page.evaluate(() => document.querySelector('#drawer tr.click').click());
    await sleep(800);
    s = await st();
    chk('J1 zmiana z przebiegu otwiera asset', s.view === 'assets' && s.url.startsWith('/assets/'), s.url);
    await back();
    s = await st();
    chk('J2 wstecz wraca do przebiegu', s.view === 'scans' && s.url === '/scans/' + encodeURIComponent(runWithEvents) && s.drawer, s.url);
  } else { chk('J0 przebieg ma zmiany do kliknięcia', false, 'brak wierszy'); }

  // K. F5 na /scans/<id> odtwarza przebieg
  await page.goto(BASE + '/scans/' + encodeURIComponent(runId), { waitUntil: 'networkidle2' });
  await sleep(900);
  s = await st();
  chk('K1 odświeżenie /scans/<id> odtwarza szufladę', s.drawer && s.run === runId && s.view === 'scans', s.url);

  // L. filtry w adresie po F5
  await page.goto(BASE + '/assets?q=192.0.2.&state=live', { waitUntil: 'networkidle2' });
  await sleep(900);
  s = await st();
  const q = await page.$eval('#a-q', e => e.value), stv = await page.$eval('#a-state', e => e.value);
  chk('L1 filtry z adresu w polach', q === '192.0.2.' && stv === 'live', q + ' | ' + stv);
  chk('L2 lista przefiltrowana', s.rows > 0, String(s.rows));

  // M. nieistniejący asset: szuflada zamknięta, adres wraca do listy
  await page.goto(BASE + '/assets/192.0.2.99%2Ftcp%2F1234', { waitUntil: 'networkidle2' });
  await sleep(900);
  s = await st();
  chk('M1 nieistniejący asset: brak szuflady', !s.drawer);
  chk('M2 adres cofnięty do listy', s.url === '/assets', s.url);

  // N. pozostałe zakładki mają swoje ścieżki
  const views = [['/targets', 'targets'], ['/account', 'account'], ['/admin', 'admin']];
  for (const [u, v] of views) {
    await page.goto(BASE + u, { waitUntil: 'networkidle2' });
    await sleep(600);
    const t = await st();
    chk(`N ${u} -> ${v}`, t.view === v && t.url === u, t.view + ' ' + t.url);
  }

  // O. menu zmienia adres, wstecz wraca do poprzedniego widoku
  await page.goto(BASE + '/', { waitUntil: 'networkidle2' });
  await sleep(500);
  await page.click('#nav button[data-p="targets"]');
  await sleep(600);
  chk('O1 menu -> /targets', (await st()).url === '/targets');
  await back();
  chk('O2 wstecz -> /', (await st()).url === '/');

  // Q. klucz portu zawiera "/" -> musi przejść przez %2F i wrócić z serwera
  const portKey = await page.evaluate(async () => {
    const r = await fetch('/api/v1/assets?kind=port', { headers: { 'X-ASI': '1' }, credentials: 'same-origin' });
    const j = await r.json(); return j.length ? j[0].key : '';
  });
  const encPort = '/assets/' + encodeURIComponent(portKey);
  await page.goto(BASE + encPort, { waitUntil: 'networkidle2' });
  await sleep(900);
  s = await st();
  chk('Q1 link do portu (%2F) otwiera asset', s.drawer && s.key === portKey, s.key + ' vs ' + portKey);
  chk('Q2 adres zachowany', s.url === encPort, s.url);
  await page.evaluate(() => document.getElementById('dr-x').click());
  await sleep(500);
  s = await st();
  chk('Q3 zamknięcie szuflady czyści ścieżkę', !s.url.includes('%2F') && !s.drawer, s.url);

  // R. deep link bez sesji: po logowaniu wracamy do assetu
  const ctx = await browser.createBrowserContext();
  const p3 = await ctx.newPage();
  p3.on('pageerror', e => errors.push('p3: ' + e.message));
  await p3.goto(BASE + encPort, { waitUntil: 'networkidle2' });
  chk('R1 bez sesji: formularz logowania', await p3.$eval('#v-login', e => !e.classList.contains('hidden')));
  await p3.type('#l-user', USER); await p3.type('#l-pass', PASS);
  await p3.click('#f-login button[type=submit]');
  await p3.waitForSelector('#v-app:not(.hidden)', { timeout: 8000 });
  await sleep(900);
  const s3 = await p3.evaluate(() => ({ url: location.pathname + location.search, drawer: !document.getElementById('drawer').classList.contains('hidden'), key: document.getElementById('drawer').dataset.key || '', view: ['dash', 'assets', 'targets', 'scans', 'account', 'admin'].find(v => !document.getElementById('p-' + v).classList.contains('hidden')) }));
  chk('R2 po logowaniu wraca do assetu z linku', s3.drawer && s3.key === portKey && s3.view === 'assets' && s3.url === encPort, JSON.stringify(s3));

  // S. viewer nie wchodzi na /admin (przekierowanie na dashboard)
  const uname = 'routing-test-' + Date.now().toString().slice(-6), upass = 'routing-test-pass-123';
  const created = await page.evaluate(async (u, pw) => {
    const r = await fetch('/api/v1/users', { method: 'POST', headers: { 'X-ASI': '1', 'Content-Type': 'application/json' }, credentials: 'same-origin', body: JSON.stringify({ username: u, password: pw, role: 'viewer' }) });
    return r.status;
  }, uname, upass);
  chk('S0 konto testowe viewer utworzone', created === 200, String(created));
  const ctx2 = await browser.createBrowserContext();
  const p4 = await ctx2.newPage();
  p4.on('pageerror', e => errors.push('p4: ' + e.message));
  await p4.goto(BASE + '/admin', { waitUntil: 'networkidle2' });
  await p4.type('#l-user', uname); await p4.type('#l-pass', upass);
  await p4.click('#f-login button[type=submit]');
  await p4.waitForSelector('#v-app:not(.hidden)', { timeout: 8000 });
  await sleep(700);
  const s4 = await p4.evaluate(() => ({ url: location.pathname, view: ['dash', 'assets', 'targets', 'scans', 'account', 'admin'].find(v => !document.getElementById('p-' + v).classList.contains('hidden')), adminNavHidden: document.querySelector('#nav button[data-p="admin"]').classList.contains('hidden') }));
  chk('S1 viewer na /admin -> dashboard', s4.view === 'dash' && s4.url === '/', JSON.stringify(s4));
  chk('S2 viewer nie widzi zakładki Administracja', s4.adminNavHidden);
  await p4.goto(BASE + '/account', { waitUntil: 'networkidle2' });
  await sleep(600);
  chk('S3 viewer ma dostęp do Konta', await p4.evaluate(() => !document.getElementById('p-account').classList.contains('hidden')));
  const uid = await page.evaluate(async u => {
    const r = await fetch('/api/v1/users', { headers: { 'X-ASI': '1' }, credentials: 'same-origin' });
    const j = await r.json(); const x = j.find(v => v.username === u); return x ? x.id : 0;
  }, uname);
  if (uid) await page.evaluate(async id => { await fetch('/api/v1/users/' + id, { method: 'DELETE', headers: { 'X-ASI': '1' }, credentials: 'same-origin' }); }, uid);
  await ctx.close(); await ctx2.close();

  // P. brak błędów JS
  // 401 na /api/v1/me przed logowaniem i 404 faviconu to nie błędy aplikacji
  const real = errors.filter(e => !/status of 401/.test(e) && !/status of 404/.test(e));
  chk('P1 brak błędów JavaScript', real.length === 0, real.slice(0, 3).join(' | '));

  console.log(`\nWYNIK: OK=${ok} FAIL=${bad}`);
  await browser.close();
  process.exit(bad ? 1 : 0);
})().catch(e => { console.error('BŁĄD TESTU:', e); process.exit(2); });
