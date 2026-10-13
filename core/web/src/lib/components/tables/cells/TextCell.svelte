<script lang="ts">
	type Props = {
		label: string;
		subLabel?: string;
		/** For machine values like IPs, usernames and fingerprints. */
		mono?: boolean;
	};
	let { label, subLabel, mono = false }: Props = $props();
</script>

<div class="flex max-w-32 min-w-0 flex-col overflow-hidden">
	<div class={['truncate text-sm', mono ? 'font-mono' : 'font-medium']} title={label}>
		{label}
	</div>

	{#if subLabel}
		<span class="truncate text-xs text-muted-foreground" title={subLabel}>
			{subLabel}
		</span>
	{/if}
</div>
