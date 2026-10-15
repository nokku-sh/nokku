/** Status colors. Names match the ext Badge variants, so `<Badge variant={tone}>` works. */
export type Tone = 'success' | 'warning' | 'info' | 'destructive' | 'muted';

const statusWords: Record<string, Tone> = {
	active: 'success',
	online: 'success',
	connected: 'success',
	accepted: 'success',
	succeeded: 'success',
	enabled: 'success',
	complete: 'success',
	truncated: 'warning',
	pending: 'warning',
	connecting: 'warning',
	expiring: 'warning',
	recording: 'destructive',
	error: 'destructive',
	failed: 'destructive',
	denied: 'destructive',
	offline: 'warning',
	expired: 'destructive'
};

/** Maps a free-form status word to a tone. Unknown words are muted. */
export function statusTone(status: string | undefined): Tone {
	return statusWords[status?.toLowerCase() ?? ''] ?? 'muted';
}

export const toneBg: Record<Tone, string> = {
	success: 'bg-success',
	warning: 'bg-warning',
	info: 'bg-info',
	destructive: 'bg-destructive',
	muted: 'bg-muted-foreground/50'
};

export const toneText: Record<Tone, string> = {
	success: 'text-success',
	warning: 'text-warning',
	info: 'text-info',
	destructive: 'text-destructive',
	muted: 'text-muted-foreground'
};

/** Tinted background with matching text, for icon badges. */
export const toneSoft: Record<Tone, string> = {
	success: 'bg-success/15 text-success',
	warning: 'bg-warning/15 text-warning',
	info: 'bg-info/15 text-info',
	destructive: 'bg-destructive/15 text-destructive',
	muted: 'bg-muted text-muted-foreground'
};
