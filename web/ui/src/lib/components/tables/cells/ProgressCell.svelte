<script lang="ts">
	import { Progress } from '$lib/components/ui/progress';

	type Props = {
		value: number;
		max?: number;
		label?: string; // Optional custom label, e.g., "45 / 100 GB"
	};
	let { value, max = 100, label, ...restProps }: Props = $props();

	let percentage = $derived(Math.min(100, Math.max(0, (value / max) * 100)));
</script>

<div class="flex w-full items-center gap-3" {...restProps}>
	<Progress value={percentage} class="h-2 w-15 sm:w-20" />
	<span class="w-12 text-right text-xs text-muted-foreground tabular-nums">
		{#if label}
			{label}
		{:else}
			{Math.round(percentage)}%
		{/if}
	</span>
</div>
