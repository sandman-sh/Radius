const slackWebhookUrl = String(process.env.SLACK_WEBHOOK_URL || '').trim();

export function notificationConfig() {
  return { slack: { configured: Boolean(slackWebhookUrl), provider: 'Slack incoming webhook' } };
}

export async function notifySlack({ title, text, findings = [], repository = '' }) {
  if (!slackWebhookUrl) return { provider: 'slack', status: 'not_configured' };
  const summary = findings.slice(0, 8).map((finding) => `• ${finding.id} · ${finding.package}@${finding.version}`).join('\n');
  const message = [text, repository ? `Repository: ${repository}` : '', summary ? `Advisories:\n${summary}` : ''].filter(Boolean).join('\n');
  const response = await fetch(slackWebhookUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text: `${title}\n${message}`, blocks: [{ type: 'header', text: { type: 'plain_text', text: title.slice(0, 150) } }, { type: 'section', text: { type: 'mrkdwn', text: message.slice(0, 2900) } }] }),
    signal: AbortSignal.timeout(10000)
  });
  if (!response.ok) throw new Error(`Slack returned ${response.status}.`);
  return { provider: 'slack', status: 'delivered' };
}
