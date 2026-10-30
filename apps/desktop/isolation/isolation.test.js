// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
// Run with: node --test isolation/
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');

global.window = {};
const { gatekeeper, REFUSED } = require('./isolation.js');

const msg = (cmd, payload, extra) => Object.assign({ cmd, callback: 1, error: 2, payload }, extra);
const passes = (m) => gatekeeper(m) === m;
const refused = (m) => {
  const out = gatekeeper(m);
  return out.cmd === REFUSED && Object.keys(out.payload).length === 0;
};

test('every real command passes with exactly its own arguments', () => {
  for (const cmd of ['app_info', 'status', 'models', 'transcript', 'last_proof', 'clear_chat']) {
    assert.ok(passes(msg(cmd, {})), cmd);
    assert.ok(passes({ cmd, callback: 1, error: 2 }), `${cmd} without a payload`);
  }
  assert.ok(passes(msg('ask', { prompt: 'hello' })));
  assert.ok(passes(msg('select_model', { name: 'suricomai-tiny-v1' })));
  assert.ok(passes(msg('set_temperature', { value: 0 })));
  assert.ok(passes(msg('set_temperature', { value: 2 })));
  assert.ok(passes(msg('set_max_tokens', { value: 1 })));
  assert.ok(passes(msg('set_max_tokens', { value: 256 })));
});

test('an unknown command, a plugin command or a prototype trick is refused', () => {
  const names = ['', 'nope', 'plugin:fs|read_file', 'plugin:shell|execute', 'ASK', 'ask ', '__proto__', 'constructor', 'toString', 'hasOwnProperty', 'tauri'];
  for (const cmd of names) assert.ok(refused(msg(cmd, {})), JSON.stringify(cmd));
  for (const cmd of [null, undefined, 5, {}, [], true]) assert.ok(refused({ callback: 1, error: 2, cmd, payload: {} }));
});

test('a refused message keeps its reply routes so the window gets an error', () => {
  const out = gatekeeper(msg('nope', {}, { callback: 77, error: 88 }));
  assert.equal(out.cmd, REFUSED);
  assert.equal(out.callback, 77);
  assert.equal(out.error, 88);
});

test('arguments must match exactly: none missing, none extra, none misnamed', () => {
  assert.ok(refused(msg('ask', {})));
  assert.ok(refused(msg('ask', { prompt: 'x', extra: 1 })));
  assert.ok(refused(msg('ask', { text: 'x' })));
  assert.ok(refused(msg('status', { anything: 1 })));
  assert.ok(refused(msg('clear_chat', { force: true })));
  assert.ok(refused(msg('select_model', { name: 'a', value: 1 })));
});

test('a message is refused when its payload is not a plain object', () => {
  for (const payload of [null, [], 'ask', 5, true]) assert.ok(refused(msg('ask', payload)), JSON.stringify(payload));
  assert.ok(refused(null));
  assert.ok(refused(undefined));
  assert.ok(refused('ask'));
  assert.ok(refused([]));
});

test('options on a message are refused unless empty', () => {
  assert.ok(passes(msg('status', {}, { options: {} })));
  assert.ok(refused(msg('status', {}, { options: { headers: { a: 'b' } } })));
  assert.ok(refused(msg('status', {}, { options: [] })));
  assert.ok(refused(msg('status', {}, { options: 'x' })));
});

test('the prompt is checked for type, emptiness, size and NUL', () => {
  for (const prompt of [undefined, null, 5, {}, [], '', '   ', '\n\t', 'a\u0000b', 'a'.repeat(8193)]) {
    assert.ok(refused(msg('ask', { prompt })), String(JSON.stringify(prompt)).slice(0, 30));
  }
  assert.ok(passes(msg('ask', { prompt: 'a'.repeat(8192) })), 'the longest allowed message');
  // Size is counted in bytes, not characters.
  assert.ok(refused(msg('ask', { prompt: 'é'.repeat(4097) })), '4097 two-byte characters');
  assert.ok(passes(msg('ask', { prompt: 'é'.repeat(4096) })));
  assert.ok(passes(msg('ask', { prompt: '/clear' })), 'a command-looking message is just a message');
});

test('model names must look like catalog names', () => {
  for (const name of ['', 'A', 'a b', '../x', 'a/b', 'x\u0000', 'a'.repeat(65), 'modèl', 5, null, undefined, {}]) {
    assert.ok(refused(msg('select_model', { name })), JSON.stringify(name));
  }
  for (const name of ['a', 'suricomai-tiny-v1', 'smollm2-135m-instruct', 'a.b_c-d', 'a'.repeat(64)]) {
    assert.ok(passes(msg('select_model', { name })), name);
  }
});

test('settings must be finite numbers in range', () => {
  for (const value of [-0.01, 2.01, NaN, Infinity, -Infinity, '1', null, undefined, {}, [1]]) {
    assert.ok(refused(msg('set_temperature', { value })), String(value));
  }
  for (const value of [0, 257, -1, 1.5, NaN, Infinity, '16', null, undefined, 1e9]) {
    assert.ok(refused(msg('set_max_tokens', { value })), String(value));
  }
});

test('an inherited property cannot stand in for an argument', () => {
  const sneaky = Object.create({ prompt: 'inherited' });
  assert.ok(refused(msg('ask', sneaky)));
  const proto = JSON.parse('{"__proto__": {"prompt": "x"}}');
  assert.ok(refused(msg('ask', proto)));
});
