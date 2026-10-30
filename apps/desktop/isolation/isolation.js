// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//
// IPC gatekeeper. This script runs in a sandboxed frame and sees every message the window sends
// to the app. A message is passed on only if it names a known command and carries exactly the
// arguments that command takes, in the allowed ranges. Anything else is turned into an unknown
// command, which the app rejects with an error the window can show. The app checks the same
// things again, so this is a second lock and not the only one.
(function () {
  'use strict';

  var MAX_PROMPT_BYTES = 8192;
  var REFUSED = '__refused__';

  var utf8Length = function (text) {
    return new TextEncoder().encode(text).length;
  };

  // Each command lists its arguments and a check for each. No argument means none are allowed.
  var COMMANDS = Object.assign(Object.create(null), {
    app_info: {},
    status: {},
    models: {},
    transcript: {},
    last_proof: {},
    clear_chat: {},
    ask: {
      prompt: function (v) {
        return typeof v === 'string' && v.trim().length > 0 && utf8Length(v) <= MAX_PROMPT_BYTES && v.indexOf('\u0000') === -1;
      },
    },
    select_model: {
      name: function (v) {
        return typeof v === 'string' && /^[a-z0-9._-]{1,64}$/.test(v);
      },
    },
    set_temperature: {
      value: function (v) {
        return typeof v === 'number' && isFinite(v) && v >= 0 && v <= 2;
      },
    },
    set_max_tokens: {
      value: function (v) {
        return typeof v === 'number' && Math.floor(v) === v && v >= 1 && v <= 256;
      },
    },
  });

  var isPlainObject = function (v) {
    return v !== null && typeof v === 'object' && !Array.isArray(v);
  };

  var allowed = function (message) {
    if (!isPlainObject(message) || typeof message.cmd !== 'string') return false;
    var rules = COMMANDS[message.cmd];
    if (!rules) return false;
    var args = message.payload === undefined ? {} : message.payload;
    if (!isPlainObject(args)) return false;
    if (message.options !== undefined && (!isPlainObject(message.options) || Object.keys(message.options).length > 0)) {
      return false;
    }
    var expected = Object.keys(rules);
    var given = Object.keys(args);
    if (given.length !== expected.length) return false;
    for (var i = 0; i < given.length; i++) {
      var name = given[i];
      if (!Object.prototype.hasOwnProperty.call(rules, name) || !rules[name](args[name])) return false;
    }
    return true;
  };

  var gatekeeper = function (message) {
    if (allowed(message)) return message;
    // Keep the reply routes so the window gets an error back instead of waiting forever.
    var refused = {
      cmd: REFUSED,
      callback: isPlainObject(message) ? message.callback : undefined,
      error: isPlainObject(message) ? message.error : undefined,
      payload: {},
    };
    return refused;
  };

  window.__TAURI_ISOLATION_HOOK__ = gatekeeper;
  if (typeof module !== 'undefined' && module.exports) module.exports = { gatekeeper: gatekeeper, REFUSED: REFUSED };
})();
