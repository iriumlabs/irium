'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const {
  createLatestRequestGate,
  createTipPoller,
  sameTip
} = require('../assets/js/explorer-live-tip.js');

class FakeScheduler {
  constructor() { this.delays = []; this.callback = null; this.currentDelay = 0; this.now = 0; }
  setTimeout(callback, delay) {
    this.delays.push(delay);
    this.callback = callback;
    this.currentDelay = delay;
    return callback;
  }
  clearTimeout(handle) { if (this.callback === handle) this.callback = null; }
  async runNext() {
    const callback = this.callback;
    const delay = this.currentDelay;
    this.callback = null;
    assert.ok(callback, 'expected a scheduled poll');
    this.now += delay;
    callback();
    await new Promise(resolve => setImmediate(resolve));
  }
}

class FakeVisibility {
  constructor() { this.hidden = false; this.listener = null; }
  addEventListener(_type, listener) { this.listener = listener; }
  removeEventListener(_type, listener) { if (this.listener === listener) this.listener = null; }
  setHidden(hidden) { this.hidden = hidden; if (this.listener) this.listener(); }
}

test('height and hash both participate in tip identity', () => {
  assert.equal(sameTip({ height: 10, hash: 'a' }, { height: 10, hash: 'a' }), true);
  assert.equal(sameTip({ height: 10, hash: 'a' }, { height: 10, hash: 'b' }), false);
  assert.equal(sameTip({ height: 10, hash: 'a' }, { height: 11, hash: 'a' }), false);
});

test('unchanged tips do not trigger a redundant recent-block refresh', async () => {
  const scheduler = new FakeScheduler();
  let refreshes = 0;
  const poller = createTipPoller({
    scheduler,
    fetchTip: async () => ({ height: 10, hash: 'a' }),
    onTipChange: async () => { refreshes += 1; }
  });
  poller.start();
  await scheduler.runNext();
  await scheduler.runNext();
  assert.equal(refreshes, 1, 'only the initial page load should fetch recent blocks');
  poller.stop();
});

test('same-height hash replacement triggers a refresh', async () => {
  const scheduler = new FakeScheduler();
  let tip = { height: 10, hash: 'a' };
  const seen = [];
  const poller = createTipPoller({
    scheduler,
    fetchTip: async () => tip,
    onTipChange: async next => { seen.push(next.hash); }
  });
  poller.start();
  await scheduler.runNext();
  tip = { height: 10, hash: 'b' };
  await scheduler.runNext();
  assert.deepEqual(seen, ['a', 'b']);
  poller.stop();
});

test('a new height is rendered on the next visible two-second poll', async () => {
  const scheduler = new FakeScheduler();
  let tip = { height: 10, hash: 'a' };
  const renders = [];
  const poller = createTipPoller({
    scheduler,
    fetchTip: async () => tip,
    onTipChange: async next => { renders.push({ height: next.height, at: scheduler.now }); }
  });
  poller.start();
  await scheduler.runNext();
  const acceptedAt = scheduler.now;
  tip = { height: 11, hash: 'b' };
  await scheduler.runNext();

  assert.deepEqual(renders.map(item => item.height), [10, 11]);
  assert.equal(renders[1].at - acceptedAt, 2000);
  poller.stop();
});

test('polls immediately after a hidden tab becomes visible', async () => {
  const scheduler = new FakeScheduler();
  const visibility = new FakeVisibility();
  const poller = createTipPoller({
    scheduler,
    visibility,
    fetchTip: async () => ({ height: 10, hash: 'a' }),
    onTipChange: async () => {}
  });
  poller.start();
  await scheduler.runNext();
  visibility.setHidden(true);
  assert.equal(scheduler.delays.at(-1), 30000);
  visibility.setHidden(false);
  assert.equal(scheduler.delays.at(-1), 0);
  poller.stop();
});

test('backs off after failure and automatically recovers', async () => {
  const scheduler = new FakeScheduler();
  let attempts = 0;
  const poller = createTipPoller({
    scheduler,
    fetchTip: async () => {
      attempts += 1;
      if (attempts < 3) throw new Error('offline');
      return { height: 10, hash: 'a' };
    },
    onTipChange: async () => {}
  });
  poller.start();
  await scheduler.runNext();
  assert.equal(scheduler.delays.at(-1), 1000);
  await scheduler.runNext();
  assert.equal(scheduler.delays.at(-1), 2000);
  await scheduler.runNext();
  assert.equal(scheduler.delays.at(-1), 2000);
  poller.stop();
});

test('does not overlap polls and queues one immediate recovery poll', async () => {
  const scheduler = new FakeScheduler();
  let resolveFetch;
  let calls = 0;
  const poller = createTipPoller({
    scheduler,
    fetchTip: () => {
      calls += 1;
      return new Promise(resolve => { resolveFetch = resolve; });
    },
    onTipChange: async () => {}
  });
  poller.start();
  const first = scheduler.callback;
  scheduler.callback = null;
  first();
  await new Promise(resolve => setImmediate(resolve));
  poller.refreshNow();
  assert.equal(calls, 1);
  resolveFetch({ height: 10, hash: 'a' });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(scheduler.delays.at(-1), 0);
  poller.stop();
});

test('an older delayed response cannot replace newer data', async () => {
  const gate = createLatestRequestGate();
  const first = gate.begin();
  const second = gate.begin();
  const rendered = [];

  async function renderWhenCurrent(request, result) {
    const value = await result;
    if (gate.isLatest(request)) rendered.push(value);
  }

  let resolveFirst;
  const older = renderWhenCurrent(first, new Promise(resolve => { resolveFirst = resolve; }));
  await renderWhenCurrent(second, Promise.resolve('newer'));
  resolveFirst('older');
  await older;

  assert.deepEqual(rendered, ['newer']);
  assert.equal(first.signal.aborted, true);
});

test('live tip and recent-block requests bypass cache while historical pages do not', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'explorer', 'index.html'), 'utf8');
  assert.match(html, /get\(API \+ '\/status\?_=' \+ t, null, true\)/);
  assert.match(html, /var live = st\.offset === 0;/);
  assert.match(html, /cacheBust = live \? '&_=' \+ Date\.now\(\) : '';/);
  assert.match(html, /request\.signal, live\)/);
});

test('retired pool is not polled or advertised as live', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'explorer', 'index.html'), 'utf8');
  assert.match(html, /Pool Retired/);
  assert.match(html, /STRATUM ENDPOINTS ARE OFFLINE/);
  assert.doesNotMatch(html, /loadPoolStats/);
  assert.doesNotMatch(html, /api\.irium\.org\/pool-stats/);
});

test('network hashrate and proposer eligibility come from live chain endpoints', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'explorer', 'index.html'), 'utf8');
  assert.match(html, /API \+ '\/rpc\/mining_metrics\?_=' \+ t/);
  assert.match(html, /status\.poawx_proposer_eligible_count/);
  assert.match(html, /Round-0 VRF odds/);
});
