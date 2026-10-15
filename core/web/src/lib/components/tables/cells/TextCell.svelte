<script lang="ts">
	type Props = {
		label: string;
		subLabel?: string;
	};
	let { label, subLabel }: Props = $props();
</script>

<!-- Prose values. Machine values go in MachineCell. -->
<div class="flex max-w-64 min-w-0 flex-col">
	<span class="truncate text-sm font-medium" title={label}>{label}</span>
	{#if subLabel}
		<span class="truncate text-xs text-muted-foreground" title={subLabel}>{subLabel}</span>
	{/if}
</div>
