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

	let absoluteText = $derived(formatTs(ts, 'long', fallback));
	let relativeText = $derived(ts ? formatTs(ts, 'relative') : '');

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
		<span class="truncate text-xs font-medium text-foreground" title={secondaryText}>
			{primaryText}
		</span>

		{#if secondaryText}
			<span class="truncate text-[11px] text-muted-foreground" title={primaryText}>
				{secondaryText}
			</span>
		{/if}
	{/if}
</div>
