<script lang="ts">
	import StatusDot from '$lib/components/blocks/StatusDot.svelte';
	import { Badge } from '$lib/components/ui/badge';
	import * as Card from '$lib/components/ui/card';
	import * as Item from '$lib/components/ui/item';
	import { Skeleton } from '$lib/components/ui/skeleton';
	import type { LiveSession } from '$lib/gen/nokku/v1/dashboard_pb';
	import { formatTs } from '$lib/utils';

	let { sessions, loading }: { sessions: LiveSession[]; loading: boolean } = $props();
</script>

<Card.Root class="gap-3">
	<Card.Header>
		<Card.Title class="flex items-center gap-2">
			Live now
			{#if sessions.length}<Badge variant="success">{sessions.length}</Badge>{/if}
		</Card.Title>
		<Card.Description>Shells open on your servers right now.</Card.Description>
	</Card.Header>
	<Card.Content>
		{#if loading}
			<Skeleton class="h-20 w-full" />
		{:else if !sessions.length}
			<p class="font-mono text-xs text-muted-foreground">
				<span class="text-primary">$</span> who <br />
				<span class="text-muted-foreground/70">nobody is connected</span>
			</p>
		{:else}
			<Item.Group class="divide-y rounded-lg border">
				{#each sessions as s (s.id)}
					<Item.Root size="xs" class="rounded-none">
						{#snippet child({ props })}
							<a {...props} href={s.web ? '/sessions' : '/recordings'}>
								<Item.Media
									><StatusDot tone={s.recording ? 'destructive' : 'success'} live /></Item.Media
								>
								<Item.Content class="min-w-0">
									<Item.Title class="truncate font-mono text-xs">
										{s.username}@{s.daemonName}
									</Item.Title>
									<Item.Description class="text-xs">
										{s.web ? 'browser' : 'ssh'}{s.startedAt
											? ` · ${formatTs(s.startedAt, 'relative-short')}`
											: ''}
									</Item.Description>
								</Item.Content>
								{#if s.recording}
									<Item.Actions><Badge variant="destructive">REC</Badge></Item.Actions>
								{/if}
							</a>
						{/snippet}
					</Item.Root>
				{/each}
			</Item.Group>
		{/if}
	</Card.Content>
</Card.Root>
