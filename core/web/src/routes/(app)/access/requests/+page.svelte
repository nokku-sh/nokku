<script lang="ts">
	import { accessRequests } from '#lib/api/access-requests.svelte.js';
	import { target as targetApi } from '#lib/api/targets.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import { useFeatures, util, workspace } from '#lib/api/workspaces.svelte.js';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import * as Item from '#lib/components/ui/item/index.js';
	import * as Tabs from '#lib/components/ui/tabs/index.js';
	import { TagsInput } from '#lib/components/ui/tags-input/index.js';
	import { AccessRequestStatus, type AccessRequest } from '#lib/gen/nokku/v1/access_request_pb.js';
	import { confirm } from '#lib/hooks/index.js';
	import PlanBadge from '#lib/components/blocks/PlanBadge.svelte';
	import { usePlans } from '#lib/plans.js';
	import { statusTone } from '#lib/tone.js';
	import { enumLabel, formatHours, formatTs } from '#lib/utils.js';
	import { durationMs } from '@bufbuild/protobuf/wkt';
	import { ArrowRight, Hand, Inbox } from '@lucide/svelte';
	import RequestModal from './RequestModal.svelte';

	const me = user.self();
	const can = user.can();
	const has = useFeatures();
	const available = $derived(has('access_requests'));
	const ws = workspace.get();
	const tags = $derived(ws.data?.requestableTags ?? []);
	const filters = targetApi.filters(() => can.admin);
	const info = util.instanceInfo();
	const plans = usePlans();

	let view = $state<'waiting' | 'answered'>('waiting');
	let asking = $state(false);

	const requests = accessRequests.list();
	const waiting = $derived(
		(requests.data?.requests ?? []).filter((r) => r.status === AccessRequestStatus.PENDING)
	);
	const shown = $derived(
		view === 'waiting'
			? waiting
			: (requests.data?.requests ?? []).filter((r) => r.status !== AccessRequestStatus.PENDING)
	);

	const approve = accessRequests.approve();
	const deny = accessRequests.deny();
	const cancel = accessRequests.cancel();
	const setTags = accessRequests.setTags();

	const statusLabel = (r: AccessRequest) => enumLabel(AccessRequestStatus[r.status]);
	const lasting = (r: AccessRequest) =>
		formatHours(r.duration ? durationMs(r.duration) / 3_600_000 : 0);

	function askApprove(r: AccessRequest) {
		void confirm({
			title: `Approve ${r.username} on ${r.targetName}?`,
			description: `${r.requesterName || r.requesterEmail} can log in for ${lasting(r)} from now. It ends by itself.`,
			confirmText: 'Approve',
			destructive: false,
			onConfirm: () => approve.mutateAsync({ id: r.id })
		});
	}

	function askDeny(r: AccessRequest) {
		void confirm({
			title: 'Deny this request?',
			description: `${r.requesterName || r.requesterEmail} gets an email that it was denied.`,
			confirmText: 'Deny',
			onConfirm: () => deny.mutateAsync({ id: r.id })
		});
	}
</script>

<RequestModal bind:open={asking} />

<PageHeader
	title="Access requests"
	description="Ask for an account for a while. An admin approves it, and it ends by itself."
>
	{#if available}
		<Button onclick={() => (asking = true)} disabled={!tags.length}>
			<Hand data-icon="inline-start" />
			Request access
		</Button>
	{/if}
</PageHeader>

{#if available === false}
	<Card.Root class="mb-4">
		<Card.Header>
			<Card.Title class="flex items-center gap-2">
				Access requests
				<PlanBadge feature="access_requests" />
			</Card.Title>
			<Card.Description>
				People ask for an account when they need it, and an admin approves it for a few hours or
				days. Requests already made can still be answered or cancelled.
			</Card.Description>
		</Card.Header>
		{#if can.admin}
			{@const upgrade = plans.upgradeLink('access_requests', info.data?.mode)}
			<Card.Footer>
				<Button
					variant="outline"
					size="sm"
					href={upgrade.href}
					target={upgrade.external ? '_blank' : undefined}
					rel={upgrade.external ? 'noopener' : undefined}
				>
					{upgrade.label}
					<ArrowRight data-icon="inline-end" />
				</Button>
			</Card.Footer>
		{/if}
	</Card.Root>
{/if}

{#if can.admin && (available || tags.length)}
	<Card.Root class="mb-4">
		<Card.Header>
			<Card.Title>Servers people may ask for</Card.Title>
			<Card.Description>
				Members only see servers with one of these tags. Everything else stays hidden from them.
			</Card.Description>
		</Card.Header>
		<Card.Content>
			<TagsInput
				value={tags}
				suggestions={filters.data?.tags}
				onValueChange={(next) => setTags.mutate({ tags: next })}
				disabled={!available && tags.length === 0}
			/>
		</Card.Content>
	</Card.Root>
{/if}

<Tabs.Root bind:value={view} class="gap-4">
	<Tabs.List>
		<Tabs.Trigger value="waiting">
			Waiting
			{#if waiting.length}<Badge variant="muted">{waiting.length}</Badge>{/if}
		</Tabs.Trigger>
		<Tabs.Trigger value="answered">Answered</Tabs.Trigger>
	</Tabs.List>
</Tabs.Root>

<Item.Group class="mt-4 gap-2">
	{#each shown as r (r.id)}
		{@const own = r.requesterId === me.data?.id}
		<Item.Root variant="outline">
			<Item.Content>
				<Item.Title class="flex flex-wrap items-center gap-2">
					<span class="font-mono">{r.username}@{r.targetName}</span>
					<span class="text-muted-foreground">for {lasting(r)}</span>
					{#if r.status !== AccessRequestStatus.PENDING}
						<Badge variant={statusTone(AccessRequestStatus[r.status])}>{statusLabel(r)}</Badge>
					{/if}
				</Item.Title>
				<Item.Description>
					{own ? 'You' : r.requesterName || r.requesterEmail}, {formatTs(r.createdAt, 'relative')}:
					{r.reason}
				</Item.Description>
				{#if r.grantedUntil && r.status === AccessRequestStatus.APPROVED}
					<Item.Description>
						Approved by {r.deciderName}, until {formatTs(r.grantedUntil, 'withTime')}
					</Item.Description>
				{:else if r.deciderName}
					<Item.Description>{statusLabel(r)} by {r.deciderName}</Item.Description>
				{/if}
			</Item.Content>
			{#if r.status === AccessRequestStatus.PENDING}
				<Item.Actions>
					{#if own}
						<Button variant="ghost" size="sm" onclick={() => cancel.mutate({ id: r.id })}>
							Cancel
						</Button>
					{:else if can.admin}
						<Button variant="ghost" size="sm" onclick={() => askDeny(r)}>Deny</Button>
						<Button size="sm" onclick={() => askApprove(r)} disabled={!available}>Approve</Button>
					{/if}
				</Item.Actions>
			{/if}
		</Item.Root>
	{:else}
		{#if !requests.isLoading}
			<Empty.Root class="border border-dashed">
				<Empty.Header>
					<Empty.Media variant="icon"><Inbox /></Empty.Media>
					<Empty.Title>
						{view === 'waiting' ? 'Nothing waits for an answer' : 'No answered requests yet'}
					</Empty.Title>
					<Empty.Description>
						{available && tags.length
							? 'Ask for an account with Request access, or with nk request in a terminal.'
							: 'No server is open for requests yet.'}
					</Empty.Description>
				</Empty.Header>
			</Empty.Root>
		{/if}
	{/each}
</Item.Group>
