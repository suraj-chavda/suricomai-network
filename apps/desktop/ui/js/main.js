// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
import { api, explain, insideApp } from './api.js';
import { h, clear } from './dom.js';
import { ROUTES, renderNav, renderStatusbar, toast, openGuide } from './chrome.js';
import { state, refresh, getTheme, setTheme, guideSeen } from './store.js';
import * as pages from './views.js';
import { createAsk } from './ask.js';
import { applyPlatform } from './platform.js';
import { installDepth } from './fx.js';

const view = document.getElementById('view');
const nav = document.getElementById('nav');
const statusbar = document.getElementById('statusbar');

let route = 'overview';
let ask = null;

const routeFromHash = () => {
  const id = window.location.hash.replace(/^#\/?/, '');
  return ROUTES.some((r) => r.id === id) ? id : 'overview';
};

function go(id) {
  if (window.location.hash !== `#/${id}`) window.location.hash = `#/${id}`;
  else render();
}

/** Run an app command, then re-read everything. Returns true when it worked. */
async function run(command, { quiet = false } = {}) {
  try {
    await command();
    return true;
  } catch (error) {
    toast(explain(error), true);
    return false;
  } finally {
    try {
      await refresh();
    } catch (error) {
      toast(explain(error), true);
    }
    if (!quiet) render();
  }
}

const actions = {
  async send(text) {
    state.busy = true;
    state.pending = text;
    render();
    const ok = await run(() => api.ask(text), { quiet: true });
    state.busy = false;
    state.pending = null;
    render();
    return ok;
  },
  async useModel(name, revert) {
    const ok = await run(() => api.selectModel(name));
    if (ok) toast(`Now using ${name}. A new chat has started.`);
    else if (revert) revert();
  },
  setTemperature: (value) => run(() => api.setTemperature(value)),
  setMaxTokens: (value) => run(() => api.setMaxTokens(value)),
  clearChat: () => run(() => api.clearChat()),
  setTheme(theme) {
    setTheme(theme);
    render();
  },
};

function render() {
  if (!state.loaded) return;
  renderNav(nav, route, go, () => openGuide(0));
  renderStatusbar(statusbar, state, go, () => openGuide(2));
  const leavingAsk = ask && route !== 'ask';
  if (leavingAsk) {
    ask.destroy();
    ask = null;
  }
  view.classList.toggle('ask-mode', route === 'ask');
  if (route === 'ask') {
    if (!ask) {
      ask = createAsk(state, actions);
      clear(view).append(ask.root);
    }
    ask.update();
    return;
  }
  const page = {
    overview: () => pages.overview(state, go),
    models: () => pages.models(state, actions),
    network: () => pages.network(state),
    settings: () => pages.settings(state, actions),
  }[route]();
  clear(view).append(page);
}

function onHash() {
  route = routeFromHash();
  render();
  view.scrollTop = 0;
}

document.addEventListener('keydown', (event) => {
  if (!event.altKey || event.ctrlKey || event.metaKey) return;
  const tag = (event.target && event.target.tagName) || '';
  if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
  const index = Number(event.code.replace('Digit', '')) - 1;
  if (index >= 0 && index < ROUTES.length) {
    event.preventDefault();
    go(ROUTES[index].id);
  }
});

async function start() {
  applyPlatform();
  installDepth(view);
  setTheme(getTheme());
  if (!insideApp) {
    clear(view).append(h('div', { class: 'page' }, h('div', { class: 'callout warn' },
      h('div', {}, 'This page works only inside the SuriComAI app. Open the app instead of this file.'))));
    return;
  }
  try {
    await refresh();
  } catch (error) {
    clear(view).append(h('div', { class: 'page' }, h('div', { class: 'callout warn' },
      h('div', {}, `The local node did not start. ${explain(error)}`))));
    return;
  }
  window.addEventListener('hashchange', onHash);
  route = routeFromHash();
  render();
  if (!guideSeen()) openGuide(0);
}

start();
