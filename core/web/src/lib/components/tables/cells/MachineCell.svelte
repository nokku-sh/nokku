<script lang="ts">
	import CopyText from '#lib/components/blocks/CopyText.svelte';

	type Props = {
		/** A machine value: an address, an account, a key type. */
		value?: string;
		/** Shown muted when there is no value. */
		fallback?: string;
		/** Click to copy. For values people paste somewhere else. */
		copy?: boolean;
	};
	let { value, fallback = '-', copy = false }: Props = $props();
</script>

<div class="flex max-w-64 min-w-0">
	{#if !value}
		<span class="text-sm text-muted-foreground">{fallback}</span>
	{:else if copy}
		<CopyText {value} mono />
	{:else}
		<span class="truncate font-mono text-xs" title={value}>{value}</span>
	{/if}
</div>
