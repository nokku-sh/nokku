<script lang="ts">
	import { billing } from '$lib/api/billing.svelte';
	import { workspace } from '$lib/api/workspaces.svelte';
	import * as Alert from '$lib/components/ui/alert';
	import { Badge } from '$lib/components/ui/badge';
	import Button from '$lib/components/ui/button/button.svelte';
	import * as Card from '$lib/components/ui/card';
	import * as Dialog from '$lib/components/ui/dialog';
	import Label from '$lib/components/ui/label/label.svelte';
	import { Switch } from '$lib/components/ui/switch';
	import { Textarea } from '$lib/components/ui/textarea';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import { formatTs } from '$lib/utils';
	import {
		CircleUserIcon,
		CreditCard,
		ExternalLink,
		IdCardIcon,
		ServerIcon,
		UsersIcon,
		WaypointsIcon,
		ShieldAlert,
		LoaderCircle,
		CreditCardIcon,
		ArrowLeftRightIcon
	} from '@lucide/svelte';

	let showCancelDialog = $state(false);
	let cancelImmediately = $state(false);
	let cancelReason = $state('');

	const customerData = $derived(billing.get());
	const subscription = $derived(customerData.data);
	const counts = $derived(customerData.data?.counts);

	function metaInt(key: string, fallback: number): number {
		const m = (customerData.data as any)?.metadata;
		if (m?.[key] !== undefined) {
			const n = parseInt(m[key], 10);
			if (!isNaN(n)) return n;
		}
		return fallback;
	}

	let ws = $derived(workspace.get());

	const isActive = $derived(
		subscription?.status === 'active' || subscription?.status === 'trialing'
	);
	const isCancelling = $derived(isActive && subscription?.cancelAtPeriodEnd);
	const cancel = billing.cancelSubscription();

	const planDisplayName = $derived(
		(subscription?.productName || 'Free').replace(/^Nokku\s*-\s*/i, '')
	);

	const checkout = billing.checkout();
	const portal = billing.portal();

	const overageAllowed = $derived(
		subscription?.status === 'active' || subscription?.status === 'trialing'
	);

	const resources = $derived([
		{
			key: 'members',
			label: 'Members',
			limit: metaInt('max_members', -1),
			credited: metaInt('credit_members', 0),
			used: Number(counts?.members ?? 0),
			icon: CircleUserIcon,
			overage: overageAllowed
		},
		{
			key: 'teams',
			label: 'Teams',
			limit: metaInt('max_teams', -1),
			credited: metaInt('credit_teams', 0),
			used: Number(counts?.teams ?? 0),
			icon: UsersIcon,
			overage: false
		},
		{
			key: 'service_accounts',
			label: 'Service Accounts',
			limit: metaInt('max_service_accounts', -1),
			credited: metaInt('credit_service_accounts', 0),
			used: Number(counts?.serviceAccounts ?? 0),
			icon: WaypointsIcon,
			overage: overageAllowed
		},
		{
			key: 'targets',
			label: 'Targets',
			limit: metaInt('max_targets', -1),
			credited: metaInt('credit_targets', 0),
			used: Number(counts?.targets ?? 0),
			icon: ServerIcon,
			overage: overageAllowed
		},
		{
			key: 'cas',
			label: 'Certificate Authorities',
			limit: metaInt('max_cas', -1),
			credited: metaInt('credit_cas', 0),
			used: Number(counts?.cas ?? 0),
			icon: IdCardIcon,
			overage: false
		}
	]);

	function handleCancel() {
		cancel.mutate({
			immediate: cancelImmediately,
			cancelAtPeriodEnd: !cancelImmediately,
			reason: cancelReason
		});
		showCancelDialog = false;
		cancelReason = '';
		cancelImmediately = false;
	}
</script>

<PageHeader
	title="Billing & Quotas"
	description="Manage your subscription, review inclusive quotas, and monitor resource consumption across your workspace environments."
	icon={CreditCardIcon}
/>

<Dialog.Root bind:open={showCancelDialog}>
	<Dialog.Content>
		<Dialog.Header>
			<Dialog.Title>Cancel Subscription</Dialog.Title>
			<Dialog.Description>
				We're sorry to see you go. Your subscription will continue until the end of the current
				billing period.
			</Dialog.Description>
		</Dialog.Header>

		<div class="space-y-4 py-4">
			<div class="space-y-2">
				<Label for="cancel-reason">Why are you cancelling? (optional)</Label>
				<Textarea
					id="cancel-reason"
					bind:value={cancelReason}
					placeholder="Help us improve..."
					rows={3}
				/>
			</div>

			<div class="flex items-center justify-between rounded-lg border p-4">
				<div class="space-y-0.5">
					<Label for="cancel-immediately" class="font-medium">Cancel immediately</Label>
					<p class="text-xs text-muted-foreground">
						End now instead of at period end ({formatTs(subscription?.currentPeriodEnd)})
					</p>
				</div>
				<Switch bind:checked={cancelImmediately} />
			</div>
		</div>

		<Dialog.Footer class="grid grid-cols-2">
			<Button variant="outline" onclick={() => (showCancelDialog = false)}>
				Keep Subscription
			</Button>
			<Button variant="destructive" onclick={handleCancel} disabled={cancel.isPending}>
				{cancel.isPending ? 'Cancelling...' : 'Confirm Cancellation'}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>

{#if isCancelling}
	<Alert.Root variant="destructive" class="border-destructive/40 bg-destructive/5">
		<ShieldAlert class="h-4 w-4 text-destructive" />
		<Alert.Title>Cancellation Pending</Alert.Title>
		<Alert.Description>
			Your subscription will end securely on <strong class="font-medium"
				>{formatTs(subscription?.currentPeriodEnd)}</strong
			>. You will be downgraded to the Free tier after this date.
		</Alert.Description>
	</Alert.Root>
{/if}

{#if !ws.data?.id}
	<Alert.Root variant="destructive" class="border-destructive/40 bg-destructive/5">
		<ShieldAlert class="h-4 w-4 text-destructive" />
		<Alert.Title>No Workspace Selected</Alert.Title>
		<Alert.Description>
			You must select a workspace to view actual billing details or upgrade. Any subscription
			purchased will be tied specifically to the currently active workspace.
		</Alert.Description>
	</Alert.Root>
{/if}

<div class="mx-auto max-w-xl">
	<!-- Active Plan Overview -->
	<Card.Root class="relative overflow-hidden rounded-xl border shadow-sm">
		<div
			class="pointer-events-none absolute -top-12 -right-12 h-32 w-32 rounded-full bg-primary/5 blur-3xl"
		></div>

		<Card.Header class="pb-4">
			<div class="flex items-center justify-between">
				<Card.Title class="relative z-10 text-3xl font-semibold tracking-tighter">
					{planDisplayName}
				</Card.Title>
				<Badge
					variant={isActive ? (isCancelling ? 'destructive' : 'secondary') : 'outline'}
					class="z-10 border-primary/20 bg-primary/10 font-medium text-primary hover:bg-primary/20"
				>
					{#if isCancelling}
						Cancelling
					{:else if subscription?.status === 'trialing'}
						Trial
					{:else if isActive}
						Active
					{:else}
						Free Tier
					{/if}
				</Badge>
			</div>

			<Card.Description class="relative z-10 mt-1">
				{#if !ws.data?.id}
					Select a workspace to upgrade.
				{:else if isActive}
					{isCancelling ? 'Ends on' : 'Next billing cycle'}
					<span class="font-medium text-foreground">{formatTs(subscription?.currentPeriodEnd)}</span
					>
				{:else}
					You are on our free, limited capacity tier.
				{/if}
			</Card.Description>
		</Card.Header>

		<Card.Content class="relative z-10 mb-4">
			<div class="space-y-3">
				{#each resources as r (r.key)}
					{@const effectiveMax = r.limit > 0 ? r.limit : r.credited > 0 ? r.credited * 3 : -1}
					{@const pct =
						effectiveMax > 0 ? Math.min(Math.round((r.used / effectiveMax) * 100), 100) : 0}
					{@const inOverage = r.credited > 0 && r.used >= r.credited}
					{@const nearLimit = effectiveMax > 0 && !inOverage && pct >= 90}
					<div class="flex items-center justify-between gap-4 text-sm">
						<div class="flex items-center gap-2">
							<r.icon size={14} class="text-muted-foreground" />
							<span class="text-muted-foreground">{r.label}</span>
						</div>
						<span class="font-medium tabular-nums">
							{r.used}
							{#if r.credited > 0}
								<span class="text-muted-foreground">/{r.credited}</span>
								<span class="text-xs text-muted-foreground/60"> ({effectiveMax})</span>
							{:else if r.limit !== -1}
								<span class="text-muted-foreground">/{r.limit}</span>
							{/if}
						</span>
					</div>
					{#if effectiveMax > 0}
						<div class="h-1 w-full overflow-hidden rounded-full bg-secondary">
							<div
								class="h-full rounded-full {inOverage
									? 'bg-amber-500'
									: nearLimit
										? 'bg-destructive'
										: 'bg-primary'}"
								style="width: {pct}%"
							></div>
						</div>
					{/if}
				{/each}
			</div>
		</Card.Content>

		<Card.Footer class="relative z-10 flex flex-col items-stretch gap-3 border-t sm:items-center">
			{#if isActive && !isCancelling}
				<Button
					variant="outline"
					class="w-full"
					onclick={checkout.mutate}
					target="_blank"
					disabled={!ws.data?.id || checkout.isPending}
				>
					{#if checkout.isPending}
						<LoaderCircle size={15} class="animate-spin" />
					{:else}
						<ArrowLeftRightIcon size={15} />
					{/if}
					Change Plan
				</Button>
				<Button
					variant="default"
					class="w-full shadow-md"
					onclick={portal.mutate}
					target="_blank"
					disabled={!ws.data?.id || portal.isPending}
				>
					{#if portal.isPending}
						<LoaderCircle size={15} class="animate-spin" />
					{:else}
						<CreditCard size={15} />
					{/if}
					Billing Portal
				</Button>
				<Button
					variant="ghost"
					class="w-full text-destructive hover:bg-destructive/10 hover:text-destructive"
					onclick={() => (showCancelDialog = true)}
				>
					Cancel Subscription
				</Button>
			{:else}
				<Button
					variant="default"
					class="w-full shadow-md"
					onclick={checkout.mutate}
					target="_blank"
					disabled={!ws.data?.id || checkout.isPending}
				>
					Upgrade Workspace
					{#if checkout.isPending}
						<LoaderCircle size={15} class="animate-spin" />
					{:else}
						<ExternalLink size={15} />
					{/if}
				</Button>
			{/if}
		</Card.Footer>
	</Card.Root>
</div>
