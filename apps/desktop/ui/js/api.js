// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
// The only door to the app. Every call is one of the commands the window is allowed to make.

const core = window.__TAURI__ && window.__TAURI__.core;
export const insideApp = Boolean(core);

const call = (cmd, args) => core.invoke(cmd, args);

export const api = {
  appInfo: () => call('app_info'),
  status: () => call('status'),
  models: () => call('models'),
  transcript: () => call('transcript'),
  lastProof: () => call('last_proof'),
  ask: (prompt) => call('ask', { prompt }),
  selectModel: (name) => call('select_model', { name }),
  setTemperature: (value) => call('set_temperature', { value }),
  setMaxTokens: (value) => call('set_max_tokens', { value }),
  clearChat: () => call('clear_chat'),
};

// The app answers with fixed codes. This turns each into a sentence a person can act on.
const MESSAGES = {
  empty_prompt: 'Type a message first.',
  prompt_too_long: 'That message is too long. The limit is 8,192 bytes.',
  bad_prompt: 'That message contains a character that cannot be sent.',
  bad_model: 'That is not a valid model name.',
  unknown_model: 'That model is not in the catalog.',
  model_unavailable: "That model's files are not installed on this computer.",
  model_not_approved: 'That model has no valid approval, so it was not used.',
  approval_window: "That model's approval has ended or was revoked, so it was not used.",
  bad_request: 'That value is outside the allowed range.',
  session_unavailable: 'The local node stopped working. Close the app and open it again.',
  task_failed: 'The job did not finish. Try again.',
  text_failed: 'The model could not produce an answer. Try a shorter message.',
};

export function explain(error) {
  const text = typeof error === 'string' ? error : '';
  if (MESSAGES[text]) return MESSAGES[text];
  if (text.includes('__refused__')) return 'The app refused that request because it did not look valid.';
  return `Something went wrong${text && text.length < 60 ? ` (${text})` : ''}. Try again.`;
}
