<script lang="ts">
	import { billing as billingApi } from '#lib/api/billing.svelte.js';
	import FormModal from '#lib/components/blocks/FormModal.svelte';
	import * as Alert from '#lib/components/ext/alert/index.js';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import { Switch } from '#lib/components/ui/switch/index.js';
	import { Textarea } from '#lib/components/ui/textarea/index.js';
	import type { GetBillingResponse } from '#lib/gen/nokku/v1/billing_pb.js';
	import type { Tone } from '#lib/tone.js';
	import { formatTs } from '#lib/utils.js';
	import { CalendarX, CreditCard, ExternalLink, ShieldAlert } from '@lucide/svelte';

	let { billing }: { billing: GetBillingResponse } = $props();

	const checkout = billingApi.checkout();
	const portal = billingApi.portal();
	const cancel = billingApi.cancelSubscription();

	const sub = $derived(billing.subscription);
	const isActive = $derived(sub?.status === 'active' || sub?.status === 'trialing');
	const isPastDue = $derived(sub?.status === 'past_due');
	const isCancelling = $derived(isActive && sub?.cancelAtPeriodEnd);

	// Community renders as Free.
	const planNames: Record<string, string> = {
		community: 'Free',
		pro: 'Pro',
		enterprise: 'Enterprise'
	};
	const planName = $derived(planNames[billing.plan || 'community'] ?? 'Free');

	const status = $derived.by((): { label: string; tone: Tone } => {
		if (isCancelling) return { label: 'Cancelling', tone: 'warning' };
		if (sub?.status === 'trialing') return { label: 'Trial', tone: 'info' };
		if (isPastDue) return { label: 'Past due', tone: 'destructive' };
		if (isActive) return { label: 'Active', tone: 'success' };
		return { label: 'Free tier', tone: 'muted' };
	});

	let cancelOpen = $state(false);
	let immediate = $state(false);
	let reason = $state('');

	async function submitCancel() {
		await cancel.mutateAsync({ immediate, reason });
		reason = '';
		immediate = false;
	}
</script>

<FormModal
	bind:open={cancelOpen}
	title="Cancel your subscription?"
	description={`It runs until ${formatTs(sub?.currentPeriodEnd)}, then the workspace drops to Free. Recordings and audit logs beyond the Free limits are kept for 30 more days.`}
	icon={CalendarX}
	onSubmit={submitCancel}
>
	<Field.Field>
		<Field.Label for="cancel-reason">What made you cancel? (optional)</Field.Label>
		<Textarea id="cancel-reason" bind:value={reason} placeholder="Help us get better" rows={3} />
	</Field.Field>
	<Field.Field orientation="horizontal">
		<Field.Content>
			<Field.Label for="cancel-immediately">End it now</Field.Label>
			<Field.Description>Instead of at the end of the billing period.</Field.Description>
		</Field.Content>
		<Switch id="cancel-immediately" bind:checked={immediate} />
	</Field.Field>
	{#snippet footer()}
		<Button type="button" variant="outline" onclick={() => (cancelOpen = false)}>Keep it</Button>
		<Button type="submit" variant="destructive" disabled={cancel.isPending}>
			{#if cancel.isPending}<Spinner data-icon="inline-start" />{/if}
			Cancel subscription
		</Button>
	{/snippet}
</FormModal>

{#if isCancelling}
	<Alert.Root variant="warning">
		<ShieldAlert />
		<Alert.Title>Cancellation pending</Alert.Title>
		<Alert.Description>
			Your plan ends on {formatTs(sub?.currentPeriodEnd)}, then the workspace drops to Free.
			Recordings and audit logs beyond the Free limits are kept for 30 more days.
		</Alert.Description>
	</Alert.Root>
{/if}

<Card.Root>
	<Card.Header>
		<span class="spec-label">Plan</span>
		<Card.Title class="text-3xl font-semibold tracking-tight">{planName}</Card.Title>
		<Card.Description>
			{#if isActive}
				{isCancelling ? 'Ends on' : 'Renews on'}
				<span class="font-medium text-foreground">{formatTs(sub?.currentPeriodEnd)}</span>
			{:else if isPastDue}
				Update your payment method to restore full access.
			{:else}
				The free tier, with limited capacity.
			{/if}
		</Card.Description>
		<Card.Action>
			<Badge variant={status.tone}>{status.label}</Badge>
		</Card.Action>
	</Card.Header>
	<Card.Footer class="flex flex-wrap gap-2 border-t">
		{#if isActive || isPastDue}
			<Button onclick={() => portal.mutate({})} disabled={portal.isPending}>
				{#if portal.isPending}<Spinner data-icon="inline-start" />{:else}<CreditCard
						data-icon="inline-start"
					/>{/if}
				Manage plan and payment
			</Button>
			{#if isActive && !isCancelling}
				<Button variant="ghost" onclick={() => (cancelOpen = true)}>Cancel subscription</Button>
			{/if}
		{:else}
			<Button onclick={() => checkout.mutate({})} disabled={checkout.isPending}>
				Upgrade workspace
				{#if checkout.isPending}<Spinner data-icon="inline-end" />{:else}<ExternalLink
						data-icon="inline-end"
					/>{/if}
			</Button>
		{/if}
	</Card.Footer>
</Card.Root>
