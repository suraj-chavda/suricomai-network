// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
// Small line icons, drawn from path data. They take their colour from the text around them.

const SPECS = {
  overview: [['path', 'M4 5.5h7v6H4z M13 5.5h7v3.5h-7z M13 11h7v7.5h-7z M4 13.5h7v5H4z']],
  ask: [['path', 'M5 5.5h14a1.5 1.5 0 0 1 1.5 1.5v8a1.5 1.5 0 0 1-1.5 1.5H11l-4 3v-3H5A1.5 1.5 0 0 1 3.5 15V7A1.5 1.5 0 0 1 5 5.5z']],
  models: [['path', 'M12 3.5l8 4.2v8.6l-8 4.2-8-4.2V7.7z M4.2 7.9L12 12l7.8-4.1 M12 12v8.3']],
  network: [['circle', 12, 5.5, 2.3], ['circle', 5, 18, 2.3], ['circle', 19, 18, 2.3], ['path', 'M10.9 7.4L6.1 15.8 M13.1 7.4l4.8 8.4 M7.4 18h9.2']],
  settings: [['path', 'M4 7h8.5 M17 7h3 M4 17h3 M11.5 17H20'], ['circle', 14.8, 7, 2.1], ['circle', 9.2, 17, 2.1]],
  check: [['path', 'M5 12.5l4.5 4.5L19 7.5']],
  open: [['circle', 12, 12, 7.5]],
  info: [['circle', 12, 12, 9], ['path', 'M12 11v5.2 M12 7.7v.3']],
  alert: [['path', 'M12 4l9.2 16H2.8z M12 10v4.4 M12 17.2v.2']],
  send: [['path', 'M5 12h13.5 M13.5 6.5L19 12l-5.5 5.5']],
  plus: [['path', 'M12 5v14 M5 12h14']],
  shield: [['path', 'M12 3.5l7 2.8v5.4c0 4.2-2.8 7.6-7 9-4.2-1.4-7-4.8-7-9V6.3z']],
  help: [['circle', 12, 12, 9], ['path', 'M9.6 9.6a2.5 2.5 0 1 1 3.7 2.2c-.8.4-1.3 1-1.3 1.9 M12 16.9v.2']],
  trash: [['path', 'M5 7h14 M9.5 7V4.5h5V7 M7 7l.8 12.5h8.4L17 7']],
  sliders: [['path', 'M4 8h6 M14 8h6 M4 16h10 M18 16h2'], ['circle', 12, 8, 2], ['circle', 16, 16, 2]],
  copy: [['path', 'M9 8.5h10.5V20H9z M5 15.5V4h10.5']],
};

const NS = 'http://www.w3.org/2000/svg';

export function icon(name, size = 18) {
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width', String(size));
  svg.setAttribute('height', String(size));
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '1.7');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('focusable', 'false');
  for (const [kind, ...args] of SPECS[name] || []) {
    if (kind === 'path') {
      const path = document.createElementNS(NS, 'path');
      path.setAttribute('d', args[0]);
      svg.append(path);
    } else {
      const c = document.createElementNS(NS, 'circle');
      c.setAttribute('cx', String(args[0]));
      c.setAttribute('cy', String(args[1]));
      c.setAttribute('r', String(args[2]));
      svg.append(c);
    }
  }
  return svg;
}
