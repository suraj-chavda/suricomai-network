// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
// The Ask page. It is built once when opened and updated in place, so what is being typed and
// where the cursor is never get thrown away when the state refreshes.
import { h, clear, num, utf8Length } from './dom.js';
import { icon } from './icons.js';
import { privacyChip } from './views.js';

const SUGGESTIONS = ['Hello, are you there?', 'Describe what you do in one sentence.'];

export function createAsk(state, actions) {
  const max = state.info.max_prompt_bytes;

  const select = h('select', { id: 'model-select', 'aria-label': 'Model', onchange: () => actions.useModel(select.value, () => syncSelect()) });
  const log = h('div', { class: 'log', role: 'log', 'aria-live': 'polite', 'aria-label': 'Conversation' });
  const input = h('textarea', {
    id: 'prompt', rows: '1', placeholder: 'Type a message', 'aria-label': 'Message', maxlength: '100000',
    oninput: () => { resize(); paintComposer(); },
    onkeydown: (e) => {
      if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
        e.preventDefault();
        submit();
      }
    },
  });
  const counter = h('span', {});
  const sendBtn = h('button', { class: 'btn primary', type: 'submit' }, icon('send', 16), 'Send');
  const form = h('form', { class: 'composer', onsubmit: (e) => { e.preventDefault(); submit(); } },
    h('div', { class: 'composer-box' }, input, sendBtn),
    h('div', { class: 'composer-meta' }, h('span', {}, 'Enter to send, Shift+Enter for a new line'), counter));

  // Options popover: temperature and answer length.
  const tempOut = h('output', {});
  const tempIn = h('input', { type: 'range', min: '0', max: '2', step: '0.1',
    oninput: () => { tempOut.textContent = Number(tempIn.value).toFixed(1); },
    onchange: () => actions.setTemperature(Number(tempIn.value)) });
  const tokIn = h('input', { type: 'number', min: '1', max: '256', step: '1', onchange: () => actions.setMaxTokens(Number(tokIn.value)) });
  const panel = h('div', { class: 'options-panel', role: 'group', 'aria-label': 'Message options', hidden: true },
    h('label', { class: 'field' }, h('span', {}, 'Temperature ', tempOut), tempIn),
    h('label', { class: 'field' }, h('span', {}, 'Answer length'), h('span', { class: 'hint' }, '1 to 256 tokens'), tokIn));
  const optBtn = h('button', { class: 'btn', type: 'button', 'aria-expanded': 'false', 'aria-haspopup': 'true', onclick: () => togglePanel() }, icon('sliders', 16), 'Options');
  const closeOnOutside = (e) => { if (!panel.hidden && !panel.contains(e.target) && !optBtn.contains(e.target)) togglePanel(false); };
  const closeOnEscape = (e) => { if (e.key === 'Escape' && !panel.hidden) { togglePanel(false); optBtn.focus(); } };

  function togglePanel(force) {
    const open = force === undefined ? panel.hidden : force;
    panel.hidden = !open;
    optBtn.setAttribute('aria-expanded', String(open));
    if (open) {
      document.addEventListener('mousedown', closeOnOutside);
      document.addEventListener('keydown', closeOnEscape);
    } else {
      document.removeEventListener('mousedown', closeOnOutside);
      document.removeEventListener('keydown', closeOnEscape);
    }
  }

  const root = h('div', { class: 'ask-wrap' },
    h('div', { class: 'page-head' },
      h('div', {}, h('h1', {}, 'Ask'), h('p', {}, 'Sealed on this computer, run by the local node, and the proof is checked.')),
      h('div', { class: 'actions' },
        select,
        h('div', { class: 'options' }, optBtn, panel),
        h('button', { class: 'btn', type: 'button', onclick: () => actions.clearChat() }, icon('trash', 16), 'New chat'))),
    log,
    form);

  function resize() {
    input.style.height = 'auto';
    input.style.height = `${Math.min(input.scrollHeight + 2, 170)}px`;
  }

  function bytes() { return utf8Length(input.value); }

  function paintComposer() {
    const used = bytes();
    const empty = input.value.trim().length === 0;
    const over = used > max;
    counter.textContent = `${num(used)} of ${num(max)} bytes`;
    counter.className = over ? 'over' : '';
    sendBtn.disabled = state.busy || empty || over;
    input.disabled = state.busy;
  }

  async function submit() {
    if (sendBtn.disabled) return;
    const text = input.value;
    input.value = '';
    resize();
    paintComposer();
    const ok = await actions.send(text);
    if (!ok) { input.value = text; resize(); }
    paintComposer();
    input.focus();
  }

  function syncSelect() {
    clear(select).append(...state.models.map((m) =>
      h('option', { value: m.id, disabled: !m.installed, selected: m.active }, m.installed ? m.id : `${m.id} (not installed)`)));
    select.disabled = state.busy;
  }

  function turn(role, label, body, extra) {
    return h('div', { class: `turn ${role}` }, h('div', { class: 'turn-label' }, label, extra), body);
  }

  function paintLog() {
    const atEnd = log.scrollHeight - log.scrollTop - log.clientHeight < 80;
    clear(log);
    const hex = state.status.privacy === 'lab-untrusted';
    const chip = privacyChip(state.status.privacy);
    if (state.lines.length === 0 && !state.pending) {
      log.append(h('div', { class: 'empty' },
        h('div', { class: 'icon-wrap' }, icon('ask', 20)),
        h('h2', {}, 'Ask the local node a question'),
        h('p', {}, hex
          ? 'The built-in test model answers in hex. It exists to test sealing and proofs. Install the optional SmolLM2 model for readable answers.'
          : 'This model runs on this computer\'s processor, so it can read what you type.'),
        h('div', { class: 'suggest' }, SUGGESTIONS.map((t) =>
          h('button', { class: 'btn small', type: 'button', onclick: () => { input.value = t; resize(); paintComposer(); input.focus(); } }, t)))));
    } else {
      for (const line of state.lines) {
        if (line.role === 'you') log.append(turn('you', 'You', h('div', { class: 'bubble', text: line.text })));
        else if (line.role === 'model') log.append(turn('model', `Model · ${state.status.model}`, h('div', { class: `bubble${hex ? ' hex' : ''}`, text: line.text }), chip));
        else log.append(h('div', { class: 'detail', text: line.text }));
      }
      if (state.pending) log.append(turn('you', 'You', h('div', { class: 'bubble', text: state.pending })));
      if (state.busy) log.append(h('div', { class: 'busy-line' }, h('span', { class: 'spinner', 'aria-hidden': 'true' }), 'Sealing the message, running the model, checking the proof...'));
    }
    if (atEnd || state.busy) log.scrollTop = log.scrollHeight;
  }

  function update() {
    syncSelect();
    tempIn.value = String(state.status.temperature);
    tempOut.textContent = state.status.temperature.toFixed(1);
    tokIn.value = String(state.status.max_tokens);
    paintLog();
    paintComposer();
  }

  function destroy() { togglePanel(false); }

  update();
  resize();
  return { root, update, destroy, focus: () => input.focus() };
}
