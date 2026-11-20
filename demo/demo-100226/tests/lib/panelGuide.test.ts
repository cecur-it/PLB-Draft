import test from 'node:test';
import assert from 'node:assert/strict';
import { getPanelGuide, PANEL_GUIDE_TOPICS } from '../../src/components/PanelGuide';

test('every operational navigation pane has actionable guidance and terminology', () => {
  for (const panel of ['overview', 'incidents', 'cecur', 'activtrak', 'sensors', 'fusion', 'errow', 'audit', 'executive']) {
    const guide = getPanelGuide(panel);
    assert.equal(guide.title.length > 0, true, `${panel} title`);
    assert.equal(guide.purpose.length > 40, true, `${panel} purpose`);
    assert.equal(guide.sections.length >= 2, true, `${panel} workflow sections`);
    assert.equal(guide.terms.length >= 2, true, `${panel} terminology`);
  }
});

test('guide navigation exposes complete operator checks and valid related topics', () => {
  assert.equal(new Set(PANEL_GUIDE_TOPICS).size, PANEL_GUIDE_TOPICS.length);
  for (const panel of PANEL_GUIDE_TOPICS) {
    const guide = getPanelGuide(panel);
    assert.equal(guide.operatorChecks.length >= 3, true, `${panel} operator checks`);
    assert.equal(guide.relatedPanels.length >= 2, true, `${panel} related guides`);
    for (const relatedPanel of guide.relatedPanels) {
      assert.equal(PANEL_GUIDE_TOPICS.includes(relatedPanel as typeof PANEL_GUIDE_TOPICS[number]), true, `${panel} related topic ${relatedPanel}`);
      assert.notEqual(relatedPanel, panel, `${panel} should link to a different topic`);
    }
  }
});

test('unknown panes use the Command Center guide rather than rendering empty help', () => {
  assert.equal(getPanelGuide('not-a-panel').title, 'Command Center');
  assert.equal(getPanelGuide('not-a-panel').operatorChecks.length >= 3, true);
});
