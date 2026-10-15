<script lang="ts" module>
	export type Detail = {
		label: string;
		value?: string;
		mono?: boolean;
		copy?: boolean;
		href?: string;
		/** Takes the full row, for long values like keys. */
		wide?: boolean;
	};
</script>

<script lang="ts">
	import CopyText from '#lib/components/blocks/CopyText.svelte';
	import { cn } from '#lib/utils.js';

	interface Props {
		items: Detail[];
		class?: string;
	}

	let { items, class: className }: Props = $props();

	// A lone half-width tile would leave a gap, so it stretches instead.
	const tiles = $derived.by(() => {
		const shown = items.filter((i) => i.value);
		let column = 0;
		return shown.map((item, i) => {
			const next = shown[i + 1];
			const nextWide = !next || !!next.wide;
			const wide = item.wide || (column === 0 && nextWide);
			column = wide ? 0 : (column + 1) % 2;
			return { ...item, wide };
		});
	});
</script>

{#if tiles.length}
	<dl
		class={cn(
			'grid grid-cols-2 gap-px overflow-hidden rounded-lg border bg-border text-sm',
			className
		)}
	>
		{#each tiles as item (item.label)}
			<div class={cn('flex min-w-0 flex-col gap-0.5 bg-card px-3 py-2', item.wide && 'col-span-2')}>
				<dt class="spec-label">
					{item.label}
				</dt>
				<dd class={cn('flex min-h-5 min-w-0 items-center', item.mono && 'font-mono text-xs')}>
					{#if item.copy && item.value}
						<CopyText value={item.value} mono={item.mono} />
					{:else if item.href}
						<a href={item.href} class="truncate hover:underline">{item.value}</a>
					{:else}
						<span class="truncate" title={item.value}>{item.value}</span>
					{/if}
				</dd>
			</div>
		{/each}
	</dl>
{/if}
