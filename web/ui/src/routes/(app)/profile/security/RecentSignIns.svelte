<script lang="ts">
	import EventRow from '$lib/components/audit/EventRow.svelte';
	import { user } from '$lib/api/user.svelte';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import { Skeleton } from '$lib/components/ui/skeleton';
	import { AuditOutcome } from '$lib/gen/nokku/v1/util_pb';
	import { formatTs } from '$lib/utils';
	import { MonitorSmartphone } from '@lucide/svelte';

	const me = user.self();

	const recentSignIns = user.activity(() => ({
		enabled: !!me.data?.id,
		limit: 5,
		filter: { actions: ['Login', 'LoginDenied'], outcome: AuditOutcome.UNSPECIFIED }
	}));
</script>

<Card.Root>
	<Card.Header>
		<Card.Title>Recent sign-ins</Card.Title>
		<Card.Description>The last five attempts on your account.</Card.Description>
		<Card.Action>
			<Button size="sm" variant="ghost" href="/profile/activity?view=signins">View all</Button>
		</Card.Action>
	</Card.Header>
	<Card.Content>
		{#if recentSignIns.isLoading}
			<Skeleton class="h-24 w-full" />
		{:else if recentSignIns.data?.logs.length}
			<div class="divide-y overflow-hidden rounded-lg border">
				{#each recentSignIns.data.logs as e (e.id)}
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
