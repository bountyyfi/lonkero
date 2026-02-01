// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Lonkero DevTools Panel Creator
 * Creates the Lonkero panel in Chrome DevTools
 */

chrome.devtools.panels.create(
  'Lonkero',
  '/icons/icon16.png',
  '/devtools/panel.html',
  (panel) => {
    console.log('[Lonkero] DevTools panel created');

    panel.onShown.addListener((window) => {
      // Panel is now visible
      if (window.lonkeroPanel) {
        window.lonkeroPanel.onPanelShown();
      }
    });

    panel.onHidden.addListener(() => {
      // Panel is hidden
    });
  }
);
