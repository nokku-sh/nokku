<script lang="ts">
	import { plural } from '#lib/api/bulk.js';
	import { daemon, useDaemonReview } from '#lib/api/daemons.svelte.js';
	import CopyCommand from '#lib/components/blocks/CopyCommand.svelte';
	import StatusDot from '#lib/components/blocks/StatusDot.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import * as Item from '#lib/components/ui/item/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { lasting, requester, useRequestAnswers } from '#lib/components/access/requests.svelte.js';
	import type { AccessRequest } from '#lib/gen/nokku/v1/access_request_pb.js';
	import { DaemonStatus, type Daemon } from '#lib/gen/nokku/v1/daemon_pb.js';
	import { confirm } from '#lib/hooks/index.js';
	import { formatTs } from '#lib/utils.js';
	import { Check, ChevronRight, CircleCheck, Hand } from '@lucide/svelte';
	import type { Issue } from './issues';

	// A row names this many servers, the rest are behind its link.
	const SERVERS_SHOWN = 8;

	interface Props {
		issues: Issue[];
		/** Requests waiting for an answer, only for those who may give one. */
		requests?: AccessRequest[];
		loading: boolean;
		canEdit: boolean;
	}

	let { issues, requests = [], loading, canEdit }: Props = $props();

	const answer = useRequestAnswers();

	const review = useDaemonReview();
	const approveMany = daemon.approveMany();

	const approveAll = (daemons: Daemon[]) =>
		confirm({
			title: `Approve ${plural(daemons.length, 'server')}?`,
			description: 'Check that you expect each host. People can log in to them once approved.',
			confirmText: 'Approve all',
			destructive: false,
			onConfirm: () =>
				approveMany.mutateAsync(daemons.map((d) => ({ id: d.id, status: DaemonStatus.ACCEPTED })))
		});
</script>

<Card.Root class="gap-3">
	<Card.Header>
		<Card.Title><h2>Needs you</h2></Card.Title>
		<Card.Description>Requests, servers and anything else someone has to act on.</Card.Description>
	</Card.Header>
	<Card.Content>
		{#if loading}
			<div class="flex flex-col gap-2">
				<Skeleton class="h-14 w-full" />
				<Skeleton class="h-14 w-full" />
			</div>
		{:else if !issues.length && !requests.length}
			<Empty.Root class="gap-3 p-4">
				<Empty.Header>
					<Empty.Media variant="icon" class="bg-success/15 text-success"
						><CircleCheck /></Empty.Media
					>
					<Empty.Title>Nothing needs you</Empty.Title>
					<Empty.Description>
						No requests wait, daemons are up, the CA is fresh, no failure spikes.
					</Empty.Description>
				</Empty.Header>
			</Empty.Root>
		{:else}
			<Item.Group class="gap-2">
				{#each requests as r (r.id)}
					<Item.Root variant="outline" size="sm" class="items-start">
						<Item.Media class="pt-1"><Hand class="size-4 text-muted-foreground" /></Item.Media>
						<Item.Content>
							<Item.Title class="flex-wrap">
								<span>
									{requester(r)} wants <span class="font-mono">{r.username}</span> on
									<span class="font-mono">{r.targetName}</span> for {lasting(r)}
								</span>
								{#if r.username === 'root'}<Badge variant="warning">Superuser</Badge>{/if}
							</Item.Title>
							<Item.Description class="line-clamp-none">{r.reason}</Item.Description>
							<p class="text-xs text-muted-foreground">{formatTs(r.createdAt, 'relative')}</p>
							<div class="mt-2 flex flex-wrap gap-1.5">
								<Button
									size="xs"
									variant="outline"
									disabled={answer.pending}
									onclick={() => answer.deny(r)}
								>
									Deny
								</Button>
								<Button size="xs" disabled={answer.pending} onclick={() => answer.approve(r)}>
									Approve {lasting(r)}
								</Button>
							</div>
						</Item.Content>
					</Item.Root>
				{/each}
				{#each issues as issue (issue.id)}
					<Item.Root variant="outline" size="sm" class="items-start">
						<Item.Media class="pt-1.5"><StatusDot tone={issue.tone} /></Item.Media>
						<Item.Content>
							<Item.Title>{issue.title}</Item.Title>
							<Item.Description>{issue.detail}</Item.Description>
							{#if issue.command}
								<CopyCommand command={issue.command} class="mt-1 self-start" />
							{/if}
							{#if issue.servers}
								<div class="mt-2 flex flex-wrap gap-1.5">
									{#each issue.servers.slice(0, SERVERS_SHOWN) as s (s.id)}
										<Button size="xs" variant="outline" href={`/servers?id=${s.id}`}>
											<span class="font-mono">{s.name}</span>
										</Button>
									{/each}
									{#if issue.servers.length > SERVERS_SHOWN}
										<Button size="xs" variant="ghost" href={issue.href}>
											{issue.servers.length - SERVERS_SHOWN} more
										</Button>
									{/if}
								</div>
							{/if}
							{#if issue.approve && canEdit}
								{@const waiting = issue.approve}
								<div class="mt-2 flex flex-wrap gap-1.5">
									{#each waiting as d (d.id)}
										<Button
											size="xs"
											variant="outline"
											disabled={review.pending || approveMany.isPending}
											onclick={() => review.approve(d)}
										>
											{#if review.approving(d.id)}
												<Spinner data-icon="inline-start" />
											{:else}
												<Check data-icon="inline-start" />
											{/if}
											<span class="font-mono">{d.name}</span>
										</Button>
									{/each}
									{#if waiting.length > 1}
										<Button
											size="xs"
											disabled={review.pending || approveMany.isPending}
											onclick={() => approveAll(waiting)}
										>
											Approve all {waiting.length}
										</Button>
									{/if}
								</div>
							{/if}
						</Item.Content>
						<Item.Actions>
							<Button
								size="icon-sm"
								variant="ghost"
								href={issue.href}
								aria-label={`Open: ${issue.title}`}
							>
								<ChevronRight />
							</Button>
						</Item.Actions>
					</Item.Root>
				{/each}
			</Item.Group>
		{/if}
	</Card.Content>
</Card.Root>
