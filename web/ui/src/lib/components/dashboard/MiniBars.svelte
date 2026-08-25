<script lang="ts">
	import { cn } from '$lib/utils';

	interface Props {
		values: number[];
		labels?: string[];
		class?: string;
	}

	let { values, labels = [], class: className }: Props = $props();

	const max = $derived(Math.max(1, ...values));
</script>

<div class={cn('flex h-6 min-w-28 items-end gap-[3px]', className)}>
	{#each values as v, i (i)}
		<div
			class="min-h-0.5 flex-1 rounded-xs bg-primary/50"
			style:height="{Math.max(6, Math.round((v / max) * 100))}%"
			title={labels[i] ?? String(v)}
		></div>
	{/each}
</div>
