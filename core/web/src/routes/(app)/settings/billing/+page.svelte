<script lang="ts">
	import { billing } from '#lib/api/billing.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import LoadError from '#lib/components/blocks/LoadError.svelte';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import LicenseCard from './LicenseCard.svelte';
	import UsageCard from './UsageCard.svelte';

	const data = billing.get();
	const me = user.self();
	const can = user.can();
</script>

<PageHeader title="Billing" description="Your plan, what it includes, and how much of it you use" />

{#if data.isError}
	<LoadError
		title="Billing did not load"
		description="Your plan and its limits are unchanged."
		onRetry={() => data.refetch()}
		class="h-[25vh] rounded-xl border-solid bg-card text-card-foreground"
	/>
{:else if !data.data || !me.data}
	<div class="grid gap-4 md:grid-cols-2 md:items-start">
		<Skeleton class="h-56 w-full rounded-xl" />
		<Skeleton class="h-80 w-full rounded-xl" />
	</div>
{:else}
	<div class="grid gap-4 md:grid-cols-2 md:items-start">
		<LicenseCard billing={data.data} isOwner={can.own} />
		<UsageCard billing={data.data} />
	</div>
{/if}
