// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
// Builds elements without ever parsing a string as HTML. Text always goes in as text, so nothing
// that comes from a model or from the person typing can become markup or a script.

export function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === false || value === null || value === undefined) continue;
    if (key === 'class') el.className = value;
    else if (key === 'text') el.textContent = value;
    else if (key.startsWith('on') && typeof value === 'function') el.addEventListener(key.slice(2).toLowerCase(), value);
    else el.setAttribute(key, value === true ? '' : String(value));
  }
  append(el, kids);
  return el;
}

export function append(el, kids) {
  for (const kid of kids.flat(Infinity)) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

export function clear(el) {
  el.replaceChildren();
  return el;
}

const nf = new Intl.NumberFormat('en-US');
export const num = (n) => nf.format(n);
export const byteCount = (n) => `${nf.format(n)} ${n === 1 ? 'byte' : 'bytes'}`;
export const utf8Length = (text) => new TextEncoder().encode(text).length;

export function elapsed(seconds) {
  if (seconds < 1) return 'under 1 second';
  if (seconds < 60) return `${seconds} ${seconds === 1 ? 'second' : 'seconds'}`;
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${m} ${m === 1 ? 'minute' : 'minutes'}${s ? ` ${s} s` : ''}`;
}
