// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
// The parts of the window that stay in place: navigation, status bar, first-run guide, messages.
import { h, clear } from './dom.js';
import { icon } from './icons.js';
import { markGuideSeen } from './store.js';

export const ROUTES = [
  { id: 'overview', label: 'Overview', icon: 'overview' },
  { id: 'ask', label: 'Ask', icon: 'ask' },
  { id: 'models', label: 'Models', icon: 'models' },
  { id: 'network', label: 'Network', icon: 'network' },
  { id: 'settings', label: 'Settings', icon: 'settings' },
];

export function renderNav(root, current, go, help) {
  clear(root).append(
    h('div', { class: 'brand' },
      h('span', { class: 'brand-mark', role: 'img', 'aria-label': 'SuriComAI' }),
      h('span', { class: 'brand-name' }, 'SuriComAI', h('small', {}, 'Network'))),
    ...ROUTES.map((route, i) =>
      h('button', {
        class: 'nav-item', type: 'button', title: `${route.label} (Alt+${i + 1})`,
        'aria-current': route.id === current ? 'page' : false,
        onclick: () => go(route.id),
      }, icon(route.icon, 18), h('span', { class: 'nav-label' }, route.label))),
    h('div', { class: 'nav-spacer' }),
    h('div', { class: 'nav-foot' },
      h('button', { type: 'button', onclick: help }, 'How this works'),
      h('div', {}, 'Proprietary. All rights reserved.')),
  );
}

export function renderStatusbar(root, state, go, explainPrivacy) {
  const s = state.status;
  const info = state.info;
  clear(root);
  if (!s || !info) {
    root.append(h('span', { class: 'sb-item' }, 'Starting the local node...'));
    return;
  }
  root.append(
    h('span', { class: 'sb-item', title: 'The node runs inside this app.' }, h('span', { class: 'dot ok' }), h('span', { class: 'sb-long' }, 'Local node running'), h('span', { class: 'sb-short' }, 'Node')),
    h('span', { class: 'sb-sep' }),
    h('button', { class: 'sb-item', type: 'button', title: 'Open the network page', onclick: () => go('network') },
      h('span', { class: 'dot warn' }), h('span', { class: 'sb-long' }, 'Network: not connected'), h('span', { class: 'sb-short' }, 'Offline')),
    h('span', { class: 'sb-sep' }),
    h('button', { class: 'sb-item', type: 'button', title: 'What does this label mean?', onclick: explainPrivacy },
      icon('shield', 14), 'Privacy: ', h('span', { class: 'mono' }, s.privacy)),
    ...(state.busy
      ? [h('span', { class: 'sb-sep' }), h('span', { class: 'sb-item' }, h('span', { class: 'spinner', 'aria-hidden': 'true' }), 'Running a job')]
      : []),
    h('span', { class: 'sb-fill' }),
    h('span', { class: 'sb-item sb-hide', title: 'The model the next message goes to' }, 'Model: ', h('span', { class: 'mono' }, s.model)),
    h('span', { class: 'sb-sep sb-hide' }),
    h('span', { class: 'sb-item' }, `v${info.version}`),
  );
}

let toastTimer = 0;
export function toast(message, isError = false) {
  const el = document.getElementById('toast');
  el.className = isError ? 'toast error' : 'toast';
  el.textContent = message;
  el.hidden = false;
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => { el.hidden = true; }, isError ? 6000 : 3500);
}

const STEPS = [
  {
    title: 'Welcome to SuriComAI',
    lead: 'SuriComAI Network is an early prototype of a decentralized network for private AI. This app runs a node on your computer so you can see how it works.',
    points: [
      'Everything happens inside this app, on this computer.',
      'There is no wallet, no payment and no token yet.',
      'Treat it as a development build, not a finished product.',
    ],
  },
  {
    title: 'Ask your first question',
    lead: 'Open Ask and type a message. The app seals it, the node runs the model, and the app checks a proof that the right model ran.',
    points: [
      'The built-in test model answers in hex. It exists to test the sealing, not to hold a conversation.',
      'For readable answers, install the optional SmolLM2 model. The README explains how.',
      'Nothing you type is saved. A chat disappears when you clear it or close the app.',
    ],
  },
  {
    title: 'Read the privacy label',
    lead: 'Every answer carries a label that says who could read it. The label comes from checks the app made, and it is never set by a model.',
    points: [
      'lab-untrusted: the message is sealed, but this computer\'s own software can still read it. Nothing here is private against this computer.',
      'not-private: the model runs on this computer\'s processor, so it can read your message.',
      'A hardware-private label will appear only after a real hardware check exists. It does not exist yet.',
    ],
  },
];

export function openGuide(start = 0) {
  const dlg = document.getElementById('guide');
  let step = Math.max(0, Math.min(start, STEPS.length - 1));
  const paint = () => {
    const s = STEPS[step];
    const last = step === STEPS.length - 1;
    clear(dlg).append(
      h('div', { class: 'dlg' },
        h('h2', { id: 'guide-title' }, s.title),
        h('p', {}, s.lead),
        h('ul', {}, s.points.map((p) => h('li', {}, p))),
        h('div', { class: 'dlg-foot' },
          h('div', { class: 'steps', 'aria-label': `Step ${step + 1} of ${STEPS.length}` },
            STEPS.map((_, i) => h('i', { class: i === step ? 'on' : '' }))),
          h('div', { class: 'actions' },
            step > 0 ? h('button', { class: 'btn', type: 'button', onclick: () => { step -= 1; paint(); } }, 'Back') : null,
            h('button', { class: 'btn primary', type: 'button', onclick: () => { if (last) dlg.close(); else { step += 1; paint(); } } },
              last ? 'Get started' : 'Next')))),
    );
  };
  paint();
  dlg.addEventListener('close', markGuideSeen, { once: true });
  if (!dlg.open) dlg.showModal();
}
