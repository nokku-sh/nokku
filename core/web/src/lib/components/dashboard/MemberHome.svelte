<script lang="ts">
	import { describeAgent } from '#lib/agent.js';
	import { accessRequests } from '#lib/api/access-requests.svelte.js';
	import { useServers } from '#lib/api/connect.svelte.js';
	import { session } from '#lib/api/session.svelte.js';
	import { useFeatures } from '#lib/api/workspaces.svelte.js';
	import { lasting, requestState } from '#lib/components/access/requests.svelte.js';
	import CodeSnippet from '#lib/components/blocks/CodeSnippet.svelte';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Item from '#lib/components/ui/item/index.js';
	import { AccessRequestStatus } from '#lib/gen/nokku/v1/access_request_pb.js';
	import { statusTone } from '#lib/tone.js';
	import { formatTs } from '#lib/utils.js';
	import { CircleCheck, Hand, SquareTerminal } from '@lucide/svelte';
	import NkLogin from './NkLogin.svelte';
	import YourServers from './YourServers.svelte';

	let { inactive = false }: { inactive?: boolean } = $props();

	const RECENT = 4;

	const has = useFeatures();
	const servers = useServers();
	const sessions = session.list();
	// What nk login leaves behind, the newest first.
	const terminals = $derived(
		(sessions.data ?? [])
			.filter((s) => s.kind === 'cli')
			.toSorted((a, b) => Number(b.lastSeenAt?.seconds ?? 0) - Number(a.lastSeenAt?.seconds ?? 0))
	);
	const terminal = $derived(terminals[0]);

	const first = $derived(servers.list[0]);
	const sshLine = $derived(
		first?.usernames[0] ? `ssh ${first.usernames[0]}@${first.name}` : 'ssh user@server'
	);
	const requestLine = $derived(
		first?.usernames[0]
			? `nk request ${first.name} ${first.usernames[0]} --for 1h --reason "..."`
			: 'nk request <server> <account> --for 1h --reason "..."'
	);

	const canAsk = $derived(has('access_requests') === true);
	// Only the newest few, and no poll, they change when an admin answers.
	const requests = accessRequests.list({ limit: RECENT }, { when: () => canAsk, live: false });
	const mine = $derived(requests.data?.requests ?? []);
</script>

<section aria-label="Ways in" class="grid gap-4 md:grid-cols-3">
	<Card.Root>
		<Card.Header>
			<span class="spec-label">In the browser</span>
			<Card.Title><h2>Nothing to install</h2></Card.Title>
			<Card.Description>
				Pick a server and a shell opens right here. It runs through Nokku, which sees what is on the
				screen.
			</Card.Description>
		</Card.Header>
		<Card.Footer class="mt-auto">
			<Button href="/shell" disabled={inactive}>
				<SquareTerminal data-icon="inline-start" />
				Open a shell
			</Button>
		</Card.Footer>
	</Card.Root>

	<Card.Root>
		<Card.Header>
			<span class="flex items-center justify-between gap-2">
				<span class="spec-label">Your terminal</span>
				{#if terminal}
					<Badge variant="success">
						<CircleCheck data-icon="inline-start" />
						Set up
					</Badge>
				{/if}
			</span>
			<Card.Title><h2>Plain ssh, like always</h2></Card.Title>
			{#if terminal}
				<Card.Description>
					nk is signed in ({describeAgent(terminal.userAgent)}), last seen {formatTs(
						terminal.lastSeenAt,
						'relative'
					)}.
				</Card.Description>
			{/if}
		</Card.Header>
		<Card.Content class="flex flex-col gap-2">
			{#if terminal}
				<CodeSnippet code={sshLine} language="bash" />
			{:else}
				<NkLogin />
			{/if}
		</Card.Content>
	</Card.Root>

	<Card.Root>
		<Card.Header>
			<span class="spec-label">Need more</span>
			<Card.Title><h2>Ask for a while</h2></Card.Title>
			<Card.Description>
				{canAsk
					? 'An admin approves it and it ends by itself. Ask here or from your terminal.'
					: 'Ask an admin of this workspace for an account on the server you need.'}
			</Card.Description>
		</Card.Header>
		{#if canAsk}
			<Card.Content>
				<CodeSnippet code={requestLine} language="bash" />
			</Card.Content>
			<Card.Footer class="mt-auto">
				<Button variant="outline" href="/access/requests">
					<Hand data-icon="inline-start" />
					Ask for access
				</Button>
			</Card.Footer>
		{/if}
	</Card.Root>
</section>

<YourServers />

{#if mine.length}
	<Card.Root class="gap-3">
		<Card.Header>
			<Card.Title><h2>Your requests</h2></Card.Title>
			<Card.Action>
				<Button size="sm" variant="ghost" href="/access/requests">All requests</Button>
			</Card.Action>
		</Card.Header>
		<Card.Content>
			<Item.Group class="gap-2">
				{#each mine as r (r.id)}
					<Item.Root variant="outline" size="sm">
						<Item.Content>
							<Item.Title class="flex-wrap">
								<span class="font-mono">{r.username}@{r.targetName}</span>
								<span class="text-muted-foreground">for {lasting(r)}</span>
								<Badge variant={statusTone(AccessRequestStatus[r.status])}>{requestState(r)}</Badge>
							</Item.Title>
							<Item.Description>
								{r.status === AccessRequestStatus.PENDING
									? `Asked ${formatTs(r.createdAt, 'relative')}. An admin gets to it soon.`
									: r.deciderName
										? `${requestState(r)} by ${r.deciderName}`
										: `Asked ${formatTs(r.createdAt, 'relative')}`}
							</Item.Description>
						</Item.Content>
					</Item.Root>
				{/each}
			</Item.Group>
		</Card.Content>
	</Card.Root>
{/if}
