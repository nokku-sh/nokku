<script lang="ts">
	import { billing as billingApi } from '#lib/api/billing.svelte.js';
	import { HOLD_DAYS } from '#lib/api/license.svelte.js';
	import FormModal from '#lib/components/blocks/FormModal.svelte';
	import * as Alert from '#lib/components/ext/alert/index.js';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import { Switch } from '#lib/components/ui/switch/index.js';
	import { Textarea } from '#lib/components/ui/textarea/index.js';
	import * as ToggleGroup from '#lib/components/ui/toggle-group/index.js';
	import type { GetBillingResponse } from '#lib/gen/nokku/v1/billing_pb.js';
	import { planName } from '#lib/plans.js';
	import type { Tone } from '#lib/tone.js';
	import { formatTs } from '#lib/utils.js';
	import { CalendarX, CreditCard, ExternalLink, Info, ShieldAlert } from '@lucide/svelte';

	let { billing, isOwner }: { billing: GetBillingResponse; isOwner: boolean } = $props();

	const checkout = billingApi.checkout();
	const portal = billingApi.portal();
	const cancel = billingApi.cancelSubscription();

	const sub = $derived(billing.subscription);
	const isActive = $derived(sub?.status === 'active' || sub?.status === 'trialing');
	const isPastDue = $derived(sub?.status === 'past_due');
	const isCanceling = $derived(isActive && sub?.cancelAtPeriodEnd);
	const name = $derived(planName(billing.plan));
	const isCommunity = $derived((billing.plan || 'community') === 'community');

	const status = $derived.by((): { label: string; tone: Tone } | undefined => {
		if (isCanceling) return { label: 'Ending', tone: 'warning' };
		if (sub?.status === 'trialing') return { label: 'Trial', tone: 'info' };
		if (isPastDue) return { label: 'Payment failed', tone: 'warning' };
		if (isActive) return { label: 'Active', tone: 'success' };
		return undefined;
	});

	let cancelOpen = $state(false);
	let immediate = $state(false);
	let reason = $state('');
	let yearly = $state(false);

	const cancelDescription = $derived(
		(immediate
			? `It ends now and the workspace drops to Community.`
			: `It runs until ${formatTs(sub?.currentPeriodEnd)}, then the workspace drops to Community.`) +
			` Recordings and audit logs beyond the Community limits are kept for ${HOLD_DAYS} more days.`
	);

	async function submitCancel() {
		await cancel.mutateAsync({ immediate, reason });
		reason = '';
		immediate = false;
	}
</script>

<FormModal
	bind:open={cancelOpen}
	title="Cancel your subscription?"
	description={cancelDescription}
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
			{immediate ? 'End it now' : 'Cancel subscription'}
		</Button>
	{/snippet}
</FormModal>

<Card.Root>
	<Card.Header>
		<Card.Title class="text-xl font-semibold"><h2>{name} plan</h2></Card.Title>
		<Card.Description>
			{#if isActive}
				{isCanceling ? 'Ends on' : 'Renews on'}
				<span class="font-medium text-foreground">{formatTs(sub?.currentPeriodEnd)}</span>
			{:else if isPastDue}
				The last payment failed. Everything keeps working while Stripe retries.
			{:else if isCommunity}
				Free. Pro adds enforced SSO, audit log export, 90 days of history and as many members as you
				pay for.
			{/if}
		</Card.Description>
		{#if status}
			<Card.Action>
				<Badge variant={status.tone}>{status.label}</Badge>
			</Card.Action>
		{/if}
	</Card.Header>

	{#if isCanceling || isPastDue || sub?.keptUntil}
		<Card.Content>
			{#if isCanceling}
				<Alert.Root variant="warning">
					<ShieldAlert />
					<Alert.Title>Ends on {formatTs(sub?.currentPeriodEnd)}</Alert.Title>
					<Alert.Description>
						Then the workspace drops to Community. Recordings and audit logs beyond its limits are
						kept for {HOLD_DAYS} more days.
					</Alert.Description>
				</Alert.Root>
			{:else if isPastDue}
				<Alert.Root variant="warning">
					<ShieldAlert />
					<Alert.Title>Update the payment method</Alert.Title>
					<Alert.Description>
						If Stripe cannot charge it, the subscription ends and the workspace drops to Community.
					</Alert.Description>
				</Alert.Root>
			{:else if sub?.keptUntil}
				<Alert.Root variant="info">
					<Info />
					<Alert.Title>Your subscription ended</Alert.Title>
					<Alert.Description>
						Recordings and audit logs beyond the Community limits are kept until
						{formatTs(sub.keptUntil)}. Upgrade before then to keep them.
					</Alert.Description>
				</Alert.Root>
			{/if}
		</Card.Content>
	{/if}

	<Card.Footer class="flex flex-col items-stretch gap-3 border-t">
		{#if !isOwner}
			<p class="text-sm text-muted-foreground">The workspace owner manages the plan and payment.</p>
		{:else if isActive || isPastDue}
			<div class="flex flex-wrap gap-2">
				<Button
					variant={isPastDue ? 'default' : 'outline'}
					onclick={() => portal.mutate({})}
					disabled={portal.isPending}
				>
					{#if portal.isPending}<Spinner data-icon="inline-start" />{:else}<CreditCard
							data-icon="inline-start"
						/>{/if}
					{isPastDue ? 'Update payment method' : 'Manage plan and payment'}
				</Button>
				{#if isActive && !isCanceling}
					<Button variant="ghost" onclick={() => (cancelOpen = true)}>Cancel subscription</Button>
				{/if}
			</div>
		{:else if isCommunity}
			<div class="flex flex-wrap items-center gap-2">
				<ToggleGroup.Root
					type="single"
					variant="outline"
					value={yearly ? 'yearly' : 'monthly'}
					onValueChange={(v) => v && (yearly = v === 'yearly')}
					aria-label="Billing period"
				>
					<ToggleGroup.Item value="monthly">Monthly</ToggleGroup.Item>
					<ToggleGroup.Item value="yearly">Yearly</ToggleGroup.Item>
				</ToggleGroup.Root>
				<Button onclick={() => checkout.mutate({ yearly })} disabled={checkout.isPending}>
					Upgrade to Pro
					{#if checkout.isPending}<Spinner data-icon="inline-end" />{:else}<ExternalLink
							data-icon="inline-end"
						/>{/if}
				</Button>
			</div>
			<p class="text-xs text-muted-foreground">
				Billed per member, at least 5. Stripe shows the total before you pay.
			</p>
		{/if}
	</Card.Footer>
</Card.Root>
