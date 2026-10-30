// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
// The pages that show state. Each takes the current state and returns a fresh page.
import { h, byteCount, elapsed, num } from './dom.js';
import { icon } from './icons.js';
import { getTheme } from './store.js';

const head = (title, sub, ...actions) =>
  h('div', { class: 'page-head' },
    h('div', {}, h('h1', {}, title), sub ? h('p', {}, sub) : null),
    actions.length ? h('div', { class: 'actions' }, actions) : null);

const standingKind = (standing) => (standing === 'approved' ? 'ok' : standing === 'revoked' ? 'bad' : standing === 'unknown' ? '' : 'warn');

export const privacyChip = (label) => h('span', { class: 'chip warn', title: 'Who could read this' }, label);

function stat(title, value, sub) {
  return h('div', { class: 'card card-pad tilt' }, h('div', { class: 'card-title' }, title), h('div', { class: 'stat-value' }, value), h('div', { class: 'stat-sub' }, sub));
}

function readiness(ok, title, sub) {
  return h('div', { class: 'row' },
    h('span', { class: `state ${ok ? 'ok' : 'todo'}`, title: ok ? 'Working' : 'Not built yet' }, icon(ok ? 'check' : 'open', 18)),
    h('div', {}, h('div', { class: 'row-title' }, title), h('div', { class: 'row-sub' }, sub)));
}

export function overview(state, go) {
  const s = state.status;
  const p = state.proof;
  return h('div', { class: 'page' },
    head('Overview', 'Your local SuriComAI node.',
      h('button', { class: 'btn primary', type: 'button', onclick: () => go('ask') }, icon('ask', 16), 'Ask a question')),
    h('div', { class: 'grid stats' },
      stat('Local node', [h('span', { class: 'dot ok' }), 'Running'], 'Inside this app. Software quote, not hardware.'),
      stat('Privacy label', privacyChip(s.privacy),
        s.privacy === 'not-private' ? "This computer's processor runs the model and can read your messages." : 'Nothing here is private against this computer.'),
      stat('Models', `${s.models_approved} approved`,
        `${s.models_total} in the catalog${s.text_model_installed ? '' : '. SmolLM2 is not installed.'}`),
      stat('Network', [h('span', { class: 'dot warn' }), 'Local only'], 'Not connected to other computers yet.')),
    h('div', { class: 'grid two' },
      h('section', { class: 'card' },
        h('div', { class: 'card-head' }, h('h2', {}, 'Latest job')),
        p
          ? h('div', { class: 'card-body' }, h('dl', { class: 'facts' },
              h('dt', {}, 'Receipt'), h('dd', { class: 'mono' }, p.id.slice(0, 16)),
              h('dt', {}, 'Proof size'), h('dd', {}, byteCount(p.bytes)),
              h('dt', {}, 'Output size class'), h('dd', {}, num(p.token_bucket)),
              h('dt', {}, 'Time'), h('dd', {}, elapsed(p.elapsed_secs)),
              h('dt', {}, 'Privacy'), h('dd', {}, privacyChip(p.privacy))))
          : h('div', { class: 'empty' },
              h('div', { class: 'icon-wrap' }, icon('ask', 20)),
              h('h2', {}, 'No jobs yet'),
              h('p', {}, 'Ask a question to run your first sealed job. The receipt appears here.'),
              h('button', { class: 'btn', type: 'button', onclick: () => go('ask') }, 'Ask a question'))),
      h('section', { class: 'card' },
        h('div', { class: 'card-head' }, h('h2', {}, 'What works today')),
        h('div', { class: 'card-body rows' },
          readiness(true, 'Sealed jobs and proofs', 'Your message is sealed, run, and a proof is checked, on this computer.'),
          readiness(true, 'Model approvals', 'Signed approvals, with expiry and revocation, decide which models are used.'),
          readiness(false, 'Hardware-backed privacy', 'Not built yet. Answers are not private against this computer.'),
          readiness(false, 'Public network', 'Not built yet. This app does not connect to other computers.'),
          readiness(false, 'Wallet and payments', 'Not built yet. No money moves and there is no token.')))));
}

export function models(state, actions) {
  const rows = state.models;
  return h('div', { class: 'page' },
    head('Models', 'The models this node knows about, and where each one stands.'),
    h('div', { class: 'callout' }, icon('info', 18),
      h('div', {}, 'A model is used only while it has a valid signed approval. A revoked or expired model is refused, even if its files are on this computer.')),
    h('section', { class: 'card' },
      h('table', { class: 'table' },
        h('thead', {}, h('tr', {}, ['Model', 'Approval', 'Privacy', 'Status', ''].map((t) => h('th', {}, t)))),
        h('tbody', {}, rows.map((m) =>
          h('tr', {},
            h('td', {}, h('div', { class: 'name' }, m.id),
              h('div', { class: 'sub' }, `${num(m.params_millions)}M parameters · ${m.license}${m.digest_prefix ? ' · ' : ''}`,
                m.digest_prefix ? h('span', { class: 'mono', title: 'First 12 characters of the model fingerprint' }, m.digest_prefix) : null)),
            h('td', {}, h('span', { class: `chip ${standingKind(m.standing)}` }, m.standing)),
            h('td', {}, privacyChip(m.privacy)),
            h('td', {}, m.active ? h('span', { class: 'chip info' }, 'In use') : m.installed ? h('span', { class: 'muted' }, 'Installed') : h('span', { class: 'faint' }, 'Not installed')),
            h('td', {}, m.installed && !m.active && m.standing === 'approved'
              ? h('button', { class: 'btn small', type: 'button', onclick: () => actions.useModel(m.id) }, 'Use this model')
              : null)))))),
    state.status.text_model_installed
      ? null
      : h('div', { class: 'callout warn' }, icon('alert', 18),
          h('div', {}, 'The SmolLM2 model is not installed, so it cannot be used. The README explains how to add its two files. It is optional.')));
}

export function network(state) {
  return h('div', { class: 'page' },
    head('Network', 'How this node connects to other computers.'),
    h('section', { class: 'card card-pad' },
      h('div', { class: 'stat-value' }, h('span', { class: 'dot warn' }), 'Not connected'),
      h('p', { class: 'stat-sub' }, 'SuriComAI is running here, inside this app, and nothing leaves this computer. A public network does not exist yet.')),
    h('section', { class: 'card' },
      h('div', { class: 'card-head' }, h('h2', {}, 'Connections')),
      h('div', { class: 'card-body' }, h('dl', { class: 'facts' },
        h('dt', {}, 'Mode'), h('dd', {}, 'Local, in this app only'),
        h('dt', {}, 'Directory'), h('dd', { class: 'muted' }, 'None'),
        h('dt', {}, 'Relays'), h('dd', { class: 'muted' }, 'None'),
        h('dt', {}, 'Hosting for others'), h('dd', { class: 'muted' }, 'Off'),
        h('dt', {}, 'Wallet'), h('dd', { class: 'muted' }, 'Not available')))),
    h('div', { class: 'callout' }, icon('info', 18),
      h('div', {}, 'Directories, relays and nodes already work from the command line, between computers you run yourself. They are not in this app yet. When they are, their state will appear here.')),
    h('p', { class: 'faint' }, `Everything on this page is read from the local node. Network mode: ${state.status.network}.`));
}

export function settings(state, actions) {
  const s = state.status;
  const theme = getTheme();
  const seg = (value, label) =>
    h('button', { type: 'button', 'aria-pressed': String(theme === value), onclick: () => actions.setTheme(value) }, label);
  const temp = h('output', {}, s.temperature.toFixed(1));
  return h('div', { class: 'page' },
    head('Settings', 'Look, defaults, and what this app can and cannot do.'),
    h('section', { class: 'card' },
      h('div', { class: 'split' },
        h('div', {}, h('h3', {}, 'Appearance'), h('p', {}, 'Follow the system, or choose a theme.')),
        h('div', { class: 'seg', role: 'group', 'aria-label': 'Theme' }, seg('system', 'System'), seg('light', 'Light'), seg('dark', 'Dark'))),
      h('div', { class: 'split' },
        h('div', {}, h('h3', {}, 'Chat defaults'), h('p', {}, 'Apply to the next message. Lower temperature gives steadier answers.')),
        h('div', { class: 'stack' },
          h('label', { class: 'field' }, h('span', {}, 'Temperature ', temp),
            h('input', { type: 'range', min: '0', max: '2', step: '0.1', value: String(s.temperature),
              oninput: (e) => { temp.textContent = Number(e.target.value).toFixed(1); },
              onchange: (e) => actions.setTemperature(Number(e.target.value)) })),
          h('label', { class: 'field' }, h('span', {}, 'Answer length'), h('span', { class: 'hint' }, '1 to 256 tokens'),
            h('input', { type: 'number', min: '1', max: '256', step: '1', value: String(s.max_tokens),
              onchange: (e) => actions.setMaxTokens(Number(e.target.value)) }))))),
    h('section', { class: 'card' },
      h('div', { class: 'card-head' }, h('h2', {}, 'Privacy and security')),
      h('div', { class: 'split' },
        h('div', {}, h('h3', {}, 'What the labels mean')),
        h('dl', { class: 'facts' },
          h('dt', {}, privacyChip('lab-untrusted')), h('dd', {}, 'Sealed, but this computer\'s software can read it.'),
          h('dt', {}, privacyChip('not-private')), h('dd', {}, 'The model runs on this computer\'s processor.'),
          h('dt', {}, h('span', { class: 'chip' }, 'hardware-private')), h('dd', { class: 'muted' }, 'Not available. It needs a hardware check that is not built yet.'))),
      h('div', { class: 'split' },
        h('div', {}, h('h3', {}, 'This app')),
        h('ul', { class: 'plain-list muted' },
          h('li', {}, 'Keeps no chat on disk. A chat exists only in memory.'),
          h('li', {}, 'Cannot read your files, run programs or open network connections.'),
          h('li', {}, 'Shows only its own pages. Links and redirects to outside content are refused.'),
          h('li', {}, 'Never lets a typed message act as a command.')))),
    h('section', { class: 'card' },
      h('div', { class: 'card-head' }, h('h2', {}, 'About')),
      h('div', { class: 'card-body' }, h('dl', { class: 'facts' },
        h('dt', {}, 'Version'), h('dd', {}, state.info.version),
        h('dt', {}, 'Build'), h('dd', {}, 'Development build'),
        h('dt', {}, 'Quote'), h('dd', {}, h('span', { class: 'mono' }, state.info.quote_kind), ' (software, not hardware)'),
        h('dt', {}, 'License'), h('dd', {}, state.info.license),
        h('dt', {}, 'Contact'), h('dd', {}, 'To license, buy or take over the project, contact the owner through github.com/suraj-chavda.')))));
}
