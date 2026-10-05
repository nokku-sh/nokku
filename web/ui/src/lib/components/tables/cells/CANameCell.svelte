<script lang="ts">
	import type { CertificateAuthority } from '#lib/gen/nokku/v1/certificates_pb.js';
	import { Star } from '@lucide/svelte';

	type Props = {
		ca: CertificateAuthority;
	};
	let { ca }: Props = $props();
</script>

<div class="flex max-w-48 min-w-0 flex-col overflow-hidden">
	<div class="flex items-center gap-1.5">
		<span class="truncate text-sm font-medium">{ca.name}</span>
		{#if ca.isDefault}
			<Star size={12} class="shrink-0 fill-warning text-warning" aria-label="Default" />
		{/if}
	</div>
	{#if ca.description}
		<span class="truncate text-xs text-muted-foreground" title={ca.description}>
			{ca.description}
		</span>
	{/if}
</div>
