<script lang="ts">
	import Monogram from '#lib/components/blocks/Monogram.svelte';
	import { Badge } from '#lib/components/ext/badge/index.js';

	type Props = {
		name: string;
		/** A short muted label after the name, like "Default". */
		tag?: string;
		/** What tells it apart: a host, an address, a description. */
		detail?: string;
		/** Set the detail in mono, for hosts and other machine values. */
		mono?: boolean;
	};
	let { name, tag, detail, mono = false }: Props = $props();
</script>

<div class="flex max-w-80 min-w-0 items-center gap-3">
	<Monogram {name} />
	<div class="flex min-w-0 flex-col">
		<div class="flex min-w-0 items-center gap-1.5">
			<span class="truncate text-sm font-medium" title={name}>{name}</span>
			{#if tag}<Badge variant="muted" class="shrink-0">{tag}</Badge>{/if}
		</div>
		{#if detail}
			<span class={['truncate text-xs text-muted-foreground', mono && 'font-mono']} title={detail}>
				{detail}
			</span>
		{/if}
	</div>
</div>
