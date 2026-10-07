<script lang="ts">
	import { billing } from '#lib/api/billing.svelte.js';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import LicenseCard from './LicenseCard.svelte';
	import PlanCard from './PlanCard.svelte';
	import UsageCard from './UsageCard.svelte';

	const data = billing.get();
</script>

<PageHeader title="Billing" description="Your plan, what it includes, and how much of it you use" />

<div class="mx-auto flex w-full max-w-2xl flex-col gap-4">
	{#if data.isLoading}
		<Skeleton class="h-40 w-full rounded-xl" />
		<Skeleton class="h-56 w-full rounded-xl" />
	{:else if data.data?.mode === 'saas'}
		<PlanCard billing={data.data} />
		<UsageCard billing={data.data} />
	{:else}
		<LicenseCard />
	{/if}
</div>
