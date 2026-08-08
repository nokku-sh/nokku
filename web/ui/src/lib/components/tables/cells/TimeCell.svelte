<script lang="ts">
	import { formatTs } from '$lib/utils';
	import type { Timestamp } from '@bufbuild/protobuf/wkt';

	type Props = {
		ts: Timestamp | null | undefined;
		fallback?: string;
		emphasize?: 'absolute' | 'relative';
		align?: 'left' | 'right';
	};

	let {
		ts,
		fallback = '-',
		emphasize = 'absolute',
		align = 'left',
		...restProps
	}: Props = $props();

	// Calculate both formats reactively
	let absoluteText = $derived(formatTs(ts, 'long', fallback));
	// Only calculate relative if TS exists, otherwise leave empty so we don't render a sub-label
	let relativeText = $derived(ts ? formatTs(ts, 'relative') : '');

	// Flip the primary/secondary labels based on the emphasize prop
	let primaryText = $derived(emphasize === 'absolute' ? absoluteText : relativeText);
	let secondaryText = $derived(emphasize === 'absolute' ? relativeText : absoluteText);
</script>

<div
	class="flex flex-col"
	class:items-start={align === 'left'}
	class:items-end={align === 'right'}
	class:text-right={align === 'right'}
	{...restProps}
>
	{#if !ts}
		<span class="text-sm text-muted-foreground">{fallback}</span>
	{:else}
		<!-- Primary Label -->
		<span class="truncate text-xs font-medium text-foreground" title={secondaryText}>
			{primaryText}
		</span>

		<!-- Secondary Label -->
		{#if secondaryText}
			<span class="truncate text-[11px] text-muted-foreground" title={primaryText}>
				{secondaryText}
			</span>
		{/if}
	{/if}
</div>
