<script lang="ts">
	import { formatTs } from '#lib/utils.js';
	import { timestampDate, type Timestamp } from '@bufbuild/protobuf/wkt';

	type Props = {
		ts: Timestamp | null | undefined;
		fallback?: string;
		emphasize?: 'absolute' | 'relative';
		/** Audit grade time with seconds, in mono. */
		precise?: boolean;
		utc?: boolean;
		/** Tints an end date this many days ahead, and a passed one. For expiry columns. */
		warnWithin?: number;
	};

	let {
		ts,
		fallback = '-',
		emphasize = 'absolute',
		precise = false,
		utc = false,
		warnWithin
	}: Props = $props();

	const DAY = 24 * 3600_000;
	const urgency = $derived.by(() => {
		if (!ts || warnWithin === undefined) return '';
		const left = timestampDate(ts).getTime() - Date.now();
		return left < 0 ? 'text-destructive' : left < warnWithin * DAY ? 'text-warning' : '';
	});

	const absoluteText = $derived(
		formatTs(ts, precise ? (utc ? 'precise-utc' : 'precise') : 'long', fallback)
	);
	const relativeText = $derived(ts ? formatTs(ts, 'relative') : '');

	const primaryText = $derived(emphasize === 'absolute' ? absoluteText : relativeText);
	const secondaryText = $derived(emphasize === 'absolute' ? relativeText : absoluteText);
</script>

<div class="flex flex-col items-start whitespace-nowrap">
	{#if !ts}
		<span class="text-sm text-muted-foreground">{fallback}</span>
	{:else}
		<span
			class={['truncate text-xs', precise ? 'font-mono tabular-nums' : 'font-medium', urgency]}
			title={secondaryText}
		>
			{primaryText}
		</span>
		{#if secondaryText}
			<span class="truncate text-2xs text-muted-foreground" title={primaryText}>
				{secondaryText}
			</span>
		{/if}
	{/if}
</div>
