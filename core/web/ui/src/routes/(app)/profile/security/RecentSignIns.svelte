<script lang="ts">
	import EventRow from '#lib/components/audit/EventRow.svelte';
	import { user } from '#lib/api/user.svelte.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { formatTs } from '#lib/utils.js';
	import { MonitorSmartphone } from '@lucide/svelte';

	const me = user.self();

	// The first page of the personal log holds the recent sign-ins.
	const feed = user.activityFeed(() => !!me.data?.id);
	const signIns = $derived(
		(feed.data?.pages[0]?.logs ?? [])
			.filter((e) => e.action === 'Login' || e.action === 'LoginDenied')
			.slice(0, 5)
	);
</script>

<Card.Root>
	<Card.Header>
		<Card.Title>Recent sign-ins</Card.Title>
		<Card.Description>The latest attempts on your account.</Card.Description>
		<Card.Action>
			<Button size="sm" variant="ghost" href="/profile/activity?view=signins">View all</Button>
		</Card.Action>
	</Card.Header>
	<Card.Content>
		{#if feed.isLoading}
			<Skeleton class="h-24 w-full" />
		{:else if signIns.length}
			<div class="divide-y overflow-hidden rounded-lg border">
				{#each signIns as e (e.id)}
					<EventRow
						log={e}
						title={e.ok ? 'Signed in' : 'Sign-in denied'}
						meta={formatTs(e.timestamp, 'relative')}
					/>
				{/each}
			</div>
		{:else}
			<p class="flex items-center gap-2 text-sm text-muted-foreground">
				<MonitorSmartphone class="size-4" /> No sign-ins recorded yet.
			</p>
		{/if}
	</Card.Content>
</Card.Root>
