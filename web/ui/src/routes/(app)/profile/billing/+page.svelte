<script lang="ts">
	import { billing } from '$lib/api/billing.svelte';
	import PageHeader from '$lib/components/layout/PageHeader.svelte';
	import * as Empty from '$lib/components/ui/empty';
	import { Skeleton } from '$lib/components/ui/skeleton';
	import { workspaceID } from '$lib/store.svelte';
	import { Layers2 } from '@lucide/svelte';
	import LicenseCard from './LicenseCard.svelte';
	import PlanCard from './PlanCard.svelte';
	import UsageCard from './UsageCard.svelte';

	const data = billing.get();
</script>

<PageHeader title="Billing" description="Your plan, what it includes, and how much of it you use" />

<div class="mx-auto flex w-full max-w-2xl flex-col gap-4">
	{#if !workspaceID.current}
		<Empty.Root class="border border-dashed">
			<Empty.Header>
				<Empty.Media variant="icon"><Layers2 /></Empty.Media>
				<Empty.Title>Pick a workspace first</Empty.Title>
				<Empty.Description>Plans and quotas belong to a workspace.</Empty.Description>
			</Empty.Header>
		</Empty.Root>
	{:else if data.isLoading}
		<Skeleton class="h-40 w-full rounded-xl" />
		<Skeleton class="h-56 w-full rounded-xl" />
	{:else if data.data?.mode === 'saas'}
		<PlanCard billing={data.data} />
		<UsageCard billing={data.data} />
	{:else}
		<LicenseCard />
	{/if}
</div>
