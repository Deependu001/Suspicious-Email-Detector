export type RiskBand =
  | 'lower'
  | 'elevated'
  | 'high'
  | 'critical'
  | 'unavailable'

export interface RiskPresentation {
  band: RiskBand
  label: string
  explanation: string
}

export function getRiskPresentation(
  score: number | null | undefined,
): RiskPresentation {
  if (
    typeof score !== 'number' ||
    !Number.isFinite(score) ||
    score < 0 ||
    score > 100
  ) {
    return {
      band: 'unavailable',
      label: 'Risk Unavailable',
      explanation: 'A valid combined risk score was not returned.',
    }
  }

  if (score >= 65) {
    return {
      band: 'critical',
      label: 'Critical Risk',
      explanation: 'Critical-risk indicators were detected by the configured analysis pipeline.',
    }
  }

  if (score >= 45) {
    return {
      band: 'high',
      label: 'High Risk',
      explanation: 'Multiple or strong risk indicators warrant careful review.',
    }
  }

  if (score >= 25) {
    return {
      band: 'elevated',
      label: 'Elevated Risk',
      explanation: 'Some risk indicators were detected and should be reviewed.',
    }
  }

  return {
    band: 'lower',
    label: 'Lower Risk',
    explanation: 'A lower score is not a guarantee that the email is safe.',
  }
}

export function getReplyToPresentation(
  replyTo: string | null | undefined,
): string {
  const parsedAddress = replyTo?.trim()

  return parsedAddress || 'Not available in parsed email'
}

export function getRuleStatusLabel(triggered: boolean): string {
  return triggered ? 'Triggered' : 'Not triggered'
}
