// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
// Depth effects: cards tilt toward the pointer and catch a moving highlight. Purely visual, off
// when the person asks for reduced motion, and never attached to controls that take input.

const MAX_TILT = 7;

export function installDepth(root) {
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)');
  let frame = 0;
  let active = null;

  const paint = (card, event) => {
    const box = card.getBoundingClientRect();
    if (box.width === 0 || box.height === 0) return;
    const px = Math.min(1, Math.max(0, (event.clientX - box.left) / box.width));
    const py = Math.min(1, Math.max(0, (event.clientY - box.top) / box.height));
    card.style.setProperty('--ry', `${((px - 0.5) * 2 * MAX_TILT).toFixed(2)}deg`);
    card.style.setProperty('--rx', `${((0.5 - py) * 2 * MAX_TILT).toFixed(2)}deg`);
    card.style.setProperty('--mx', `${(px * 100).toFixed(1)}%`);
    card.style.setProperty('--my', `${(py * 100).toFixed(1)}%`);
  };

  const reset = (card) => {
    for (const name of ['--rx', '--ry', '--mx', '--my']) card.style.removeProperty(name);
  };

  root.addEventListener('pointermove', (event) => {
    if (reduce.matches || event.pointerType === 'touch') return;
    const card = event.target instanceof Element ? event.target.closest('.tilt') : null;
    if (active && active !== card) reset(active);
    active = card;
    if (!card) return;
    cancelAnimationFrame(frame);
    frame = requestAnimationFrame(() => paint(card, event));
  });
  root.addEventListener('pointerleave', () => {
    cancelAnimationFrame(frame);
    if (active) reset(active);
    active = null;
  });
}
