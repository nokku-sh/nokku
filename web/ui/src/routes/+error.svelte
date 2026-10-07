<script lang="ts">
	import { page } from '$app/state';
	import { connection } from '#lib/api/connection.svelte.js';
	import AuthCard from '#lib/components/blocks/AuthCard.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Empty from '#lib/components/ext/empty/index.js';
	import { ArrowLeft, CloudOff, House, SquareTerminal, TriangleAlert } from '@lucide/svelte';

	const missing = $derived(page.status === 404);
	const command = $derived(page.url.pathname.split('/').filter(Boolean).join(' ') || 'nokku');
</script>

<main class="flex min-h-dvh items-center justify-center p-4">
	{#if missing}
		<AuthCard
			title="Page not found"
			description="That page does not exist, or it moved."
			icon={SquareTerminal}
		>
			<Empty.Command class="self-center">{command}: command not found</Empty.Command>
			<Button href="/" class="w-full">
				<House data-icon="inline-start" />
				Back to the dashboard
			</Button>
		</AuthCard>
	{:else}
		<!-- With the server gone, a page that was never opened has no code to show. -->
		<AuthCard
			title={connection.down ? "Can't reach Nokku" : 'Something went wrong'}
			description={connection.down
				? 'This page was not loaded before the server went away. The pages you had open still work.'
				: (page.error?.message ?? `The server answered ${page.status}.`)}
			icon={connection.down ? CloudOff : TriangleAlert}
			tone={connection.down ? 'warning' : 'destructive'}
		>
			<Button class="w-full" onclick={() => history.back()}>
				<ArrowLeft data-icon="inline-start" />
				Go back
			</Button>
			<Button href="/" variant="outline" class="w-full">
				<House data-icon="inline-start" />
				Back to the dashboard
			</Button>
		</AuthCard>
	{/if}
</main>
