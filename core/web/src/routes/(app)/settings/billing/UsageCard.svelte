<script lang="ts">
	import { Badge } from '#lib/components/ui/badge/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import { Progress } from '#lib/components/ui/progress/index.js';
	import type { GetBillingResponse } from '#lib/gen/nokku/v1/billing_pb.js';
	import { catalog, requiredPlan } from '#lib/plans.js';
	import { formatBytes, formatTs } from '#lib/utils.js';
	import { Check, Lock } from '@lucide/svelte';

	let { billing, mode }: { billing: GetBillingResponse; mode: string } = $props();

	// -1 is unlimited. int64 fields arrive as number | bigint.
	const seats = $derived({
		used: Number(billing.userCount ?? 0),
		cap: Number(billing.quotas?.seats ?? -1)
	});
	const seatPct = $derived(seats.cap > 0 ? Math.min((seats.used / seats.cap) * 100, 100) : 0);
	// On a paid plan, hosted or licensed, the cap is the number of seats bought.
	const paidSeats = $derived(
		seats.cap > 0 && (billing.plan === 'pro' || billing.plan === 'enterprise')
	);
	const auditDays = $derived(Number(billing.quotas?.auditRetentionDays ?? 30));
	const recordingDays = $derived(Number(billing.quotas?.recordingRetentionDays ?? 7));
	const storageBytes = $derived(Number(billing.quotas?.recordingStorageBytes ?? -1));
	// An ended plan keeps its larger data limits until heldUntil, then the ones above apply.
	const held = $derived(billing.heldQuotas);
	const heldUntil = $derived(formatTs(billing.heldUntil));
	const resources = $derived({
		used: Number(billing.resourceCount ?? 0),
		cap: Number(billing.quotas?.resourceCap ?? -1)
	});
	const full = $derived(seats.cap > 0 && seats.used >= seats.cap);
</script>

{#snippet limit(now: string, until: string | undefined)}
	<dd class="flex flex-col items-end text-right font-medium tabular-nums">
		{until ?? now}
		{#if until}
			<span class="text-xs font-normal text-muted-foreground">{now} from {heldUntil}</span>
		{/if}
	</dd>
{/snippet}

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
						>{seats.cap < 0 ? ', no cap' : seats.cap > 0 ? ` of ${seats.cap}` : ''}</span
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
					{!paidSeats
						? 'The plan is full. Pro lifts the cap.'
						: mode === 'saas'
							? 'Every seat is taken. Add seats under Manage plan and payment to invite more people.'
							: 'Every seat is taken. A license with more seats lets you invite more people.'}
				</p>
			{/if}
		</div>

		<dl class="flex flex-col divide-y rounded-lg border text-sm">
			<div class="flex items-center justify-between gap-4 px-3 py-2.5">
				<dt class="text-muted-foreground">Audit log kept</dt>
				{@render limit(`${auditDays} days`, held && `${held.auditRetentionDays} days`)}
			</div>
			<div class="flex items-center justify-between gap-4 px-3 py-2.5">
				<dt class="text-muted-foreground">Recordings kept</dt>
				{@render limit(`${recordingDays} days`, held && `${held.recordingRetentionDays} days`)}
			</div>
			{#if resources.cap > 0}
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
					{@render limit(
						`up to ${formatBytes(storageBytes)}`,
						held && `up to ${formatBytes(Number(held.recordingStorageBytes))}`
					)}
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
							<Badge variant="outline" class="ml-auto">{requiredPlan(f.key)}</Badge>
						{/if}
					</li>
				{/each}
			</ul>
		</div>
	</Card.Content>
</Card.Root>
