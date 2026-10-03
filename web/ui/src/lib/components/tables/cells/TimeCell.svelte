<script lang="ts">
	import { formatTs } from '#lib/utils.js';
	import type { Timestamp } from '@bufbuild/protobuf/wkt';

	type Props = {
		ts: Timestamp | null | undefined;
		fallback?: string;
		emphasize?: 'absolute' | 'relative';
		align?: 'left' | 'right';
		/** Audit grade time with seconds, in mono. */
		precise?: boolean;
		utc?: boolean;
	};

	let {
		ts,
		fallback = '-',
		emphasize = 'absolute',
		align = 'left',
		precise = false,
		utc = false
	}: Props = $props();

	const absoluteText = $derived(
		formatTs(ts, precise ? (utc ? 'precise-utc' : 'precise') : 'long', fallback)
	);
	const relativeText = $derived(ts ? formatTs(ts, 'relative') : '');

	const primaryText = $derived(emphasize === 'absolute' ? absoluteText : relativeText);
	const secondaryText = $derived(emphasize === 'absolute' ? relativeText : absoluteText);
</script>

<div
	class={[
		'flex flex-col whitespace-nowrap',
		align === 'right' ? 'items-end text-right' : 'items-start'
	]}
>
	{#if !ts}
		<span class="text-sm text-muted-foreground">{fallback}</span>
	{:else}
		<span
			class={['truncate text-xs', precise ? 'font-mono tabular-nums' : 'font-medium']}
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
