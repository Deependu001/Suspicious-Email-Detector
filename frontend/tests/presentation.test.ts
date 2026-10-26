import assert from 'node:assert/strict'
import test from 'node:test'

import {
  getReplyToPresentation,
  getRiskPresentation,
  getRuleStatusLabel,
} from '../src/presentation.js'

test('low scores are presented as Lower Risk, never verified', () => {
  const presentation = getRiskPresentation(24.9)

  assert.equal(presentation.label, 'Lower Risk')
  assert.doesNotMatch(presentation.label, /verified/i)
})

test('risk presentation uses the documented score boundaries', () => {
  assert.equal(getRiskPresentation(0).label, 'Lower Risk')
  assert.equal(getRiskPresentation(24.9).label, 'Lower Risk')
  assert.equal(getRiskPresentation(25).label, 'Elevated Risk')
  assert.equal(getRiskPresentation(44.9).label, 'Elevated Risk')
  assert.equal(getRiskPresentation(45).label, 'High Risk')
  assert.equal(getRiskPresentation(64.9).label, 'High Risk')
  assert.equal(getRiskPresentation(65).label, 'Critical Risk')
  assert.equal(getRiskPresentation(100).label, 'Critical Risk')
  assert.equal(getRiskPresentation(undefined).label, 'Risk Unavailable')
  assert.equal(getRiskPresentation(Number.NaN).label, 'Risk Unavailable')
})

test('missing Reply-To is not represented as identical', () => {
  const presentation = getReplyToPresentation(null)

  assert.equal(presentation, 'Not available in parsed email')
  assert.doesNotMatch(presentation, /identical/i)
})

test('a parsed Reply-To address remains visible for mismatch findings', () => {
  assert.equal(
    getReplyToPresentation('account-support@unrelated-example.test'),
    'account-support@unrelated-example.test',
  )
})

test('an untriggered rule has an unambiguous presentation status', () => {
  assert.equal(getRuleStatusLabel(false), 'Not triggered')
  assert.equal(getRuleStatusLabel(true), 'Triggered')
})

test('presentation helpers do not transform API risk or ML values', () => {
  const apiResult = {
    risk_score: 23.6,
    ml_phishing_probability: 0.337,
  }

  const presentation = getRiskPresentation(apiResult.risk_score)

  assert.equal(presentation.label, 'Lower Risk')
  assert.equal(apiResult.risk_score, 23.6)
  assert.equal(apiResult.ml_phishing_probability, 0.337)
})
