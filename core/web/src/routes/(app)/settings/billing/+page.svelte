<script lang="ts">
	import { billing } from '#lib/api/billing.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import { util } from '#lib/api/workspaces.svelte.js';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { WorkspaceRole } from '#lib/gen/nokku/v1/access_pb.js';
	import { RotateCw, TriangleAlert } from '@lucide/svelte';
	import LicenseCard from './LicenseCard.svelte';
	import PlanCard from './PlanCard.svelte';
	import UsageCard from './UsageCard.svelte';

	const data = billing.get();
	const info = util.instanceInfo();
	const me = user.self();

	// The instance knows its mode even when billing fails, so a hosted workspace never sees the license card.
	const mode = $derived(info.data?.mode ?? data.data?.mode);
	const isOwner = $derived(me.data?.role === WorkspaceRole.OWNER);
</script>

<PageHeader title="Billing" description="Your plan, what it includes, and how much of it you use" />

{#if data.isError}
	<Empty.Root class="h-[25vh] rounded-xl border bg-card text-card-foreground">
		<Empty.Header>
			<Empty.Media variant="icon" class="bg-destructive/10 text-destructive">
				<TriangleAlert />
			</Empty.Media>
			<Empty.Title>Billing did not load</Empty.Title>
			<Empty.Description>Your plan and its limits are unchanged.</Empty.Description>
		</Empty.Header>
		<Empty.Content>
			<Button variant="outline" size="sm" onclick={() => data.refetch()}>
				<RotateCw data-icon="inline-start" />
				Try again
			</Button>
		</Empty.Content>
	</Empty.Root>
{:else if !data.data || !mode || !me.data}
	<div class="grid gap-4 md:grid-cols-2 md:items-start">
		<Skeleton class="h-56 w-full rounded-xl" />
		<Skeleton class="h-80 w-full rounded-xl" />
	</div>
{:else}
	<div class="grid gap-4 md:grid-cols-2 md:items-start">
		{#if mode === 'saas'}
			<PlanCard billing={data.data} {isOwner} />
		{:else}
			<LicenseCard {isOwner} />
		{/if}
		<UsageCard billing={data.data} {mode} />
	</div>
{/if}
