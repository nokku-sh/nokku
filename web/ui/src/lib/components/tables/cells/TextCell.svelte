<script lang="ts">
	type Props = {
		label: string;
		subLabel: string;
	};
	let { label, subLabel }: Props = $props();
</script>

<div class="flex max-w-32 min-w-0 flex-col overflow-hidden">
	<div class="truncate text-sm font-medium" title={label}>
		{label}
	</div>

	{#if subLabel}
		<span class="truncate text-xs text-muted-foreground" title={subLabel}>
			{subLabel}
		</span>
	{/if}
</div>
