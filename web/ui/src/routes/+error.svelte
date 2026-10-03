<script lang="ts">
	import { page } from '$app/state';
	import AuthCard from '#lib/components/blocks/AuthCard.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Empty from '#lib/components/ext/empty/index.js';
	import { House, SquareTerminal, TriangleAlert } from '@lucide/svelte';

	const missing = $derived(page.status === 404);
	const command = $derived(page.url.pathname.split('/').filter(Boolean).join(' ') || 'nokku');
</script>

<main class="flex min-h-dvh items-center justify-center p-4">
	<AuthCard
		title={missing ? 'Page not found' : 'Something went wrong'}
		description={missing
			? 'That page does not exist, or it moved.'
			: (page.error?.message ?? `The server answered ${page.status}.`)}
		icon={missing ? SquareTerminal : TriangleAlert}
		tone={missing ? undefined : 'destructive'}
	>
		{#if missing}
			<Empty.Command class="self-center">{command}: command not found</Empty.Command>
		{/if}
		<Button href="/" class="w-full">
			<House data-icon="inline-start" />
			Back to the dashboard
		</Button>
	</AuthCard>
</main>
