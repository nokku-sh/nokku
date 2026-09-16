// timeAgo formats an ISO timestamp as a short relative age.
// Returns "" when the input is missing or unparseable.
export function timeAgo(iso: string | undefined): string {
	if (!iso) return '';
	const ts = new Date(iso);
	if (Number.isNaN(ts.getTime())) return '';

	const seconds = Math.max(0, (Date.now() - ts.getTime()) / 1000);
	if (seconds < 60) return 'just now';
	const minutes = Math.floor(seconds / 60);
	if (minutes < 60) return `${minutes}m ago`;
	const hours = Math.floor(minutes / 60);
	if (hours < 24) return `${hours}h ago`;
	return `${Math.floor(hours / 24)}d ago`;
}
