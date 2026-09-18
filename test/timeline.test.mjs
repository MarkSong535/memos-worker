import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const html = readFileSync(new URL('../src/public/index.html', import.meta.url), 'utf8');
const start = html.indexOf('async function loadAndRenderTimeline()');
const end = html.indexOf('const timelineData = await response.json();', start);
assert.ok(start >= 0 && end > start);
// Execute the actual request-building code, stopping before DOM rendering.
const requestCode = html.slice(start, end) + '\n} catch (error) { throw error; } } loadAndRenderTimeline();';

for (const timezone of ['UTC', 'America/New_York', 'America/Kentucky/Louisville', 'Etc/GMT+5']) {
  test(`timeline request preserves ${timezone} without encoded slashes`, async () => {
    let requestedUrl;
    await vm.runInNewContext(requestCode, {
      document: { getElementById: () => ({}) },
      Intl: { DateTimeFormat: () => ({ resolvedOptions: () => ({ timeZone: timezone }) }) },
      fetch: async (url) => { requestedUrl = url; return { ok: true }; },
    });
    const url = new URL(requestedUrl, 'https://n.markso.ng');
    assert.equal(url.pathname, '/api/notes/timeline');
    assert.equal(url.searchParams.get('timezone'), timezone);
    assert.doesNotMatch(requestedUrl, /%2f/i);
    assert.deepEqual([...url.searchParams.keys()], ['timezone']);
  });
}
