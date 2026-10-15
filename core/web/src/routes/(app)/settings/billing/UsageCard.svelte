<script lang="ts">
	import { Badge } from '#lib/components/ui/badge/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import { Progress } from '#lib/components/ui/progress/index.js';
	import type { GetBillingResponse } from '#lib/gen/nokku/v1/billing_pb.js';
	import { catalog, requiredPlan } from '#lib/plans.js';
	import { formatBytes } from '#lib/utils.js';
	import { Check, Lock } from '@lucide/svelte';

	let { billing, mode }: { billing: GetBillingResponse; mode: string } = $props();

	// -1 is unlimited. int64 fields arrive as number | bigint.
	const seats = $derived({
		used: Number(billing.userCount ?? 0),
		cap: Number(billing.quotas?.seats ?? -1)
	});
	const seatPct = $derived(seats.cap > 0 ? Math.min((seats.used / seats.cap) * 100, 100) : 0);
	// On a paid hosted plan the cap is the number of seats bought.
	const paidSeats = $derived(mode === 'saas' && seats.cap > 0 && billing.plan !== 'community');
	const retentionDays = $derived(Number(billing.quotas?.retentionDays ?? 7));
	const storageBytes = $derived(Number(billing.quotas?.recordingStorageBytes ?? -1));
	const resources = $derived({
		used: Number(billing.resourceCount ?? 0),
		cap: Number(billing.quotas?.resourceCap ?? -1)
	});
	const full = $derived(seats.cap > 0 && seats.used >= seats.cap);
</script>

<Card.Root>
	<Card.Header>
		<Card.Title><h2>Limits and features</h2></Card.Title>
		<Card.Description>What this plan includes, and how much of it you use.</Card.Description>
	</Card.Header>
	<Card.Content class="flex flex-col gap-5">
		<div class="flex flex-col gap-2">
			<div class="flex items-center justify-between text-sm">
				<span id="seats-label">{paidSeats ? 'Seats in use' : 'Members'}</span>
				<span class="font-medium tabular-nums">
					{seats.used}<span class="text-muted-foreground"
						>{seats.cap < 0 ? ', no cap' : ` of ${seats.cap}`}</span
					>
				</span>
			</div>
			{#if seats.cap > 0}
				<Progress
					value={seatPct}
					aria-labelledby="seats-label"
					aria-valuetext={`${seats.used} of ${seats.cap}`}
					class={[
						seatPct >= 100 && '**:data-[slot=progress-indicator]:bg-destructive',
						seatPct >= 90 && seatPct < 100 && '**:data-[slot=progress-indicator]:bg-warning'
					]}
				/>
			{/if}
			{#if full}
				<p class="text-xs text-muted-foreground">
					{paidSeats
						? 'Every seat is taken. Add seats under Manage plan and payment to invite more people.'
						: mode === 'saas'
							? 'The plan is full. Upgrade to Pro to invite more people.'
							: 'The plan is full. An Enterprise license lifts the cap.'}
				</p>
			{/if}
		</div>

		<dl class="flex flex-col divide-y rounded-lg border text-sm">
			<div class="flex items-center justify-between gap-4 px-3 py-2.5">
				<dt class="text-muted-foreground">Audit log and recordings kept</dt>
				<dd class="font-medium tabular-nums">{retentionDays} days</dd>
			</div>
			{#if resources.cap >= 0}
				<div class="flex items-center justify-between gap-4 px-3 py-2.5">
					<dt class="flex flex-col">
						<span class="text-muted-foreground">Resources</span>
						<span class="text-xs text-muted-foreground"
							>Targets, teams, service accounts and CAs</span
						>
					</dt>
					<dd class="font-medium tabular-nums">{resources.used} of {resources.cap}</dd>
				</div>
			{/if}
			{#if storageBytes >= 0}
				<div class="flex items-center justify-between gap-4 px-3 py-2.5">
					<dt class="text-muted-foreground">Recording storage</dt>
					<dd class="font-medium tabular-nums">up to {formatBytes(storageBytes)}</dd>
				</div>
			{/if}
		</dl>

		<div class="flex flex-col gap-2">
			<h3 class="text-sm font-medium">Features</h3>
			<ul class="flex flex-col gap-2">
				{#each catalog as f (f.key)}
					{@const enabled = billing.features?.[f.key] === true}
					<li class="flex items-center gap-2.5 text-sm">
						{#if enabled}
							<Check class="size-4 shrink-0 text-success" aria-hidden="true" />
						{:else}
							<Lock class="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
						{/if}
						<span class={enabled ? undefined : 'text-muted-foreground'}>
							{f.label}<span class="sr-only">{enabled ? ', included' : ', not included'}</span>
						</span>
						{#if !enabled}
							<Badge variant="outline" class="ml-auto">{requiredPlan(f.key, mode)}</Badge>
						{/if}
					</li>
				{/each}
			</ul>
		</div>
	</Card.Content>
</Card.Root>
