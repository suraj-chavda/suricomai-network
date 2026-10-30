// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//
// DESIGN PREVIEW ONLY. This stands in for the app's backend so the interface can be rendered and
// screenshotted without a window. Every value here is sample data. It is never loaded by the app:
// `tauri.conf.json` serves only `ui/`, and this file lives outside it.
(function () {
  var sleep = function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); };
  var lines = [];
  var proof = null;
  var active = (window.__PREVIEW__ && window.__PREVIEW__.model) || 'suricomai-tiny-v1';
  var temperature = 0;
  var tokens = 16;
  var turns = 0;
  var preset = (window.__PREVIEW__ && window.__PREVIEW__.chat) || false;

  function models() {
    return [
      { id: 'suricomai-tiny-v1', standing: 'approved', privacy: 'lab-untrusted', params_millions: 1, license: 'MIT', digest_prefix: '3f9a1c7be204', installed: true, active: active === 'suricomai-tiny-v1' },
      { id: 'smollm2-135m-instruct', standing: 'approved', privacy: 'not-private', params_millions: 135, license: 'Apache-2.0', digest_prefix: '9c04d8e1a7b3', installed: true, active: active === 'smollm2-135m-instruct' },
      { id: 'example-revoked-model', standing: 'revoked', privacy: 'not-private', params_millions: 7000, license: 'Apache-2.0', digest_prefix: '51e0b6aa90cd', installed: false, active: false },
    ];
  }
  function reply(text) {
    var hex = active === 'suricomai-tiny-v1';
    var content = hex ? '4a6f7e2c1b09d8a53c1e90f7a2b4d6c8e1f03a5b7c9d2e4f6a8b0c1d3e5f7091' : 'Hello! I am a small model running on this computer. I can answer short questions.';
    lines.push({ role: 'you', text: text });
    lines.push({ role: 'model', text: content });
    lines.push({ role: 'detail', text: 'proof 1,835 bytes · under 1 second · sealed 4,423 bytes, and your text was not in that ciphertext' });
    turns += 1;
    proof = { id: 'b81d04c9e27f55a013d6c8e9f1a2b3c4', bytes: 1835, token_bucket: 32, elapsed_secs: 0, privacy: hex ? 'lab-untrusted' : 'not-private' };
  }
  if (preset) { reply('Hello, are you there?'); }

  var handlers = {
    app_info: function () { return { name: 'SuriComAI Network', version: '0.1.0', build: 'development', license: 'Proprietary, all rights reserved', quote_kind: 'lab-untrusted', max_prompt_bytes: 8192 }; },
    status: function () {
      var m = models();
      return { privacy: active === 'suricomai-tiny-v1' ? 'lab-untrusted' : 'not-private', hardware_p2: false, model: active, temperature: temperature, max_tokens: tokens, turns: turns,
        models_approved: m.filter(function (x) { return x.installed && x.standing === 'approved'; }).length, models_total: m.length, text_model_installed: true, network: 'local' };
    },
    models: models,
    transcript: function () { return lines.slice(); },
    last_proof: function () { return proof; },
    ask: function (a) { return sleep((window.__PREVIEW__ && window.__PREVIEW__.delay) || 900).then(function () { reply(a.prompt); }); },
    select_model: function (a) { active = a.name; lines = []; proof = null; turns = 0; return null; },
    set_temperature: function (a) { temperature = a.value; return null; },
    set_max_tokens: function (a) { tokens = a.value; return null; },
    clear_chat: function () { lines = []; proof = null; turns = 0; return null; },
  };

  window.__TAURI__ = { core: { invoke: function (cmd, args) {
    var fn = handlers[cmd];
    if (!fn) return Promise.reject('unknown_command');
    return Promise.resolve().then(function () { return fn(args || {}); });
  } } };
})();
