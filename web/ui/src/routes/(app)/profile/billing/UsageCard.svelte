<script lang="ts">
	import StatTile from '$lib/components/blocks/StatTile.svelte';
	import { Badge } from '$lib/components/ui/badge';
	import * as Card from '$lib/components/ui/card';
	import * as Item from '$lib/components/ui/item';
	import { Progress } from '$lib/components/ui/progress';
	import type { GetBillingResponse } from '$lib/gen/nokku/v1/billing_pb';
	import { formatBytes } from '$lib/utils';
	import { Boxes, Check, Clock, Database, Lock } from '@lucide/svelte';

	let { billing }: { billing: GetBillingResponse } = $props();

	// -1 is unlimited. int64 fields arrive as number | bigint.
	const seats = $derived({
		used: Number(billing.memberCount ?? 0),
		cap: Number(billing.quotas?.seats ?? -1)
	});
	const seatPct = $derived(seats.cap > 0 ? Math.min((seats.used / seats.cap) * 100, 100) : 0);
	const retentionDays = $derived(Number(billing.quotas?.retentionDays ?? 7));
	const storageBytes = $derived(Number(billing.quotas?.recordingStorageBytes ?? -1));
	const resources = $derived({
		used: Number(billing.resourceCount ?? 0),
		cap: Number(billing.quotas?.resourceCap ?? -1)
	});

	const features = [
		{ key: 'oidc', label: 'OIDC SSO', unlocks: null },
		{ key: 'enforce_sso', label: 'Enforced SSO', unlocks: 'Pro' },
		{ key: 'saml', label: 'SAML SSO', unlocks: 'Pro' },
		{ key: 'audit_export', label: 'Audit log export', unlocks: 'Pro' },
		{ key: 'external_kms', label: 'External KMS', unlocks: 'Enterprise' }
	];
</script>

<Card.Root>
	<Card.Header>
		<Card.Title>Usage and quotas</Card.Title>
		<Card.Description>What your plan includes, and how much you use.</Card.Description>
	</Card.Header>
	<Card.Content class="flex flex-col gap-4">
		<div class="flex flex-col gap-2">
			<div class="flex items-center justify-between text-sm">
				<span class="text-muted-foreground">Members</span>
				<span class="font-medium tabular-nums">
					{seats.used}<span class="text-muted-foreground"
						>{seats.cap < 0 ? ' · billed per seat' : `/${seats.cap}`}</span
					>
				</span>
			</div>
			{#if seats.cap > 0}
				<Progress
					value={seatPct}
					class={[
						seatPct >= 100 && '**:data-[slot=progress-indicator]:bg-destructive',
						seatPct >= 90 && seatPct < 100 && '**:data-[slot=progress-indicator]:bg-warning'
					]}
				/>
			{/if}
		</div>
		<div class="grid grid-cols-2 gap-3 sm:grid-cols-3">
			<StatTile label="Retention" icon={Clock} value={`${retentionDays} days`} />
			<StatTile
				label="Recording storage"
				icon={Database}
				value={storageBytes < 0 ? 'Unlimited' : formatBytes(storageBytes)}
			/>
			<StatTile
				label="Resources"
				icon={Boxes}
				value={resources.cap < 0 ? 'Unlimited' : `${resources.used}/${resources.cap}`}
			/>
		</div>
		<Item.Group class="divide-y rounded-lg border">
			{#each features as f (f.key)}
				{@const enabled = billing.features?.[f.key] === true}
				<Item.Root size="xs" class="rounded-none">
					<Item.Media variant="icon" class={enabled ? 'text-success' : 'text-muted-foreground'}>
						{#if enabled}<Check />{:else}<Lock />{/if}
					</Item.Media>
					<Item.Content>
						<Item.Title class={enabled ? undefined : 'text-muted-foreground'}>{f.label}</Item.Title>
					</Item.Content>
					{#if !enabled && f.unlocks}
						<Item.Actions><Badge variant="outline">{f.unlocks}</Badge></Item.Actions>
					{/if}
				</Item.Root>
			{/each}
		</Item.Group>
	</Card.Content>
</Card.Root>
