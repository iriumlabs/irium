(function (root, factory) {
  'use strict';
  var api = factory(root);
  if (typeof module === 'object' && module.exports) module.exports = api;
  root.IriumLiveTip = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function (root) {
  'use strict';

  function sameTip(a, b) {
    return !!a && !!b && a.height === b.height && a.hash === b.hash;
  }

  function validateTip(tip) {
    if (!tip || typeof tip.height !== 'number' || typeof tip.hash !== 'string' || !tip.hash) {
      throw new Error('invalid live tip response');
    }
    return tip;
  }

  function createLatestRequestGate() {
    var latest = 0;
    var controller = null;
    return {
      begin: function () {
        latest += 1;
        if (controller) controller.abort();
        controller = typeof root.AbortController !== 'undefined' ? new root.AbortController() : null;
        return { id: latest, signal: controller ? controller.signal : null };
      },
      isLatest: function (request) {
        return !!request && request.id === latest;
      },
      cancel: function () {
        latest += 1;
        if (controller) controller.abort();
        controller = null;
      }
    };
  }

  function createTipPoller(options) {
    var scheduler = options.scheduler || root;
    var visibility = options.visibility || (root.document || null);
    var visibleInterval = options.visibleIntervalMs || 2000;
    var hiddenInterval = options.hiddenIntervalMs || 30000;
    var retryBase = options.retryBaseMs || 1000;
    var retryMax = options.retryMaxMs || 30000;
    var timer = null;
    var running = false;
    var inFlight = false;
    var pollAgain = false;
    var failures = 0;
    var currentTip = options.initialTip || null;

    function clearTimer() {
      if (timer !== null) scheduler.clearTimeout(timer);
      timer = null;
    }

    function schedule(delay) {
      if (!running) return;
      clearTimer();
      timer = scheduler.setTimeout(function () {
        timer = null;
        poll();
      }, delay);
    }

    function nextDelay() {
      if (failures > 0) {
        var retry = Math.min(retryBase * Math.pow(2, failures - 1), retryMax);
        return visibility && visibility.hidden ? Math.max(retry, hiddenInterval) : retry;
      }
      return visibility && visibility.hidden ? hiddenInterval : visibleInterval;
    }

    function poll() {
      if (!running) return Promise.resolve();
      if (inFlight) {
        pollAgain = true;
        return Promise.resolve();
      }
      inFlight = true;

      return Promise.resolve()
        .then(options.fetchTip)
        .then(validateTip)
        .then(function (nextTip) {
          var previousTip = currentTip;
          if (options.onTip) options.onTip(nextTip, previousTip);
          if (!previousTip || !sameTip(previousTip, nextTip)) {
            return Promise.resolve(options.onTipChange(nextTip, previousTip)).then(function () {
              currentTip = nextTip;
            });
          }
          currentTip = nextTip;
        })
        .then(function () {
          failures = 0;
        })
        .catch(function (error) {
          failures += 1;
          if (options.onError) options.onError(error, failures);
        })
        .then(function () {
          inFlight = false;
          var immediate = pollAgain;
          pollAgain = false;
          schedule(immediate ? 0 : nextDelay());
        });
    }

    function onVisibilityChange() {
      if (!running) return;
      if (visibility && visibility.hidden) {
        if (!inFlight) schedule(hiddenInterval);
      } else if (inFlight) {
        pollAgain = true;
      } else {
        schedule(0);
      }
    }

    return {
      start: function () {
        if (running) return;
        running = true;
        if (visibility && visibility.addEventListener) {
          visibility.addEventListener('visibilitychange', onVisibilityChange);
        }
        schedule(0);
      },
      stop: function () {
        if (!running) return;
        running = false;
        clearTimer();
        if (visibility && visibility.removeEventListener) {
          visibility.removeEventListener('visibilitychange', onVisibilityChange);
        }
      },
      refreshNow: function () {
        if (inFlight) pollAgain = true;
        else schedule(0);
      },
      isInFlight: function () { return inFlight; },
      currentTip: function () { return currentTip; }
    };
  }

  return {
    createLatestRequestGate: createLatestRequestGate,
    createTipPoller: createTipPoller,
    sameTip: sameTip
  };
}));
