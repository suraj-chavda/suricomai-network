// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
import { api } from './api.js';

export const state = {
  info: null,
  status: null,
  models: [],
  lines: [],
  proof: null,
  busy: false,
  pending: null,
  loaded: false,
};

/** Read everything the screens show from the app. Each part is independent. */
export async function refresh() {
  const [info, status, models, lines, proof] = await Promise.all([
    state.info ? state.info : api.appInfo(),
    api.status(),
    api.models(),
    api.transcript(),
    api.lastProof(),
  ]);
  Object.assign(state, { info, status, models, lines, proof, loaded: true });
}

// Per-person preferences live in the browser's own storage. They hold no chat and no secret, and
// the page works without them if storage is blocked.
const THEME_KEY = 'suricomai.theme';
const GUIDE_KEY = 'suricomai.guide.v1';

function read(key) {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function write(key, value) {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    /* storage is blocked: the choice lasts until the app closes */
  }
}

export const getTheme = () => {
  const v = read(THEME_KEY);
  return v === 'light' || v === 'dark' ? v : 'system';
};

export function setTheme(theme) {
  const root = document.documentElement;
  if (theme === 'light' || theme === 'dark') root.dataset.theme = theme;
  else delete root.dataset.theme;
  write(THEME_KEY, theme);
}

export const guideSeen = () => read(GUIDE_KEY) === 'seen';
export const markGuideSeen = () => write(GUIDE_KEY, 'seen');
