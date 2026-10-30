// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
// Picks the look that matches the computer the app runs on. It only chooses a stylesheet branch
// (html[data-os]); it never changes what the app can do.

export function detectOs() {
  const hint = String(
    (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || navigator.userAgent || '',
  ).toLowerCase();
  if (hint.includes('win')) return 'windows';
  if (hint.includes('mac') || hint.includes('iphone') || hint.includes('ipad')) return 'macos';
  if (hint.includes('linux') || hint.includes('x11') || hint.includes('bsd')) return 'linux';
  return 'macos';
}

export function applyPlatform() {
  document.documentElement.dataset.os = detectOs();
}
