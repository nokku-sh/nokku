<script lang="ts">
	import { billing } from '$lib/api/billing.svelte';
	import { license } from '$lib/api/license.svelte';
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
	import { LicensePurchaseURL } from '$lib/config';
	import { formatBytes, formatTs } from '$lib/utils';
	import {
		CircleUserIcon,
		CreditCard,
		ExternalLink,
		KeyRound,
		ShieldAlert,
		LoaderCircle,
		CreditCardIcon,
		ArrowLeftRightIcon,
		BadgeCheck,
		Boxes,
		Check,
		Clock,
		Lock,
		Database
	} from '@lucide/svelte';

	let showCancelDialog = $state(false);
	let cancelImmediately = $state(false);
	let cancelReason = $state('');

	const customerData = $derived(billing.get());
	const data = $derived(customerData.data);
	const subscription = $derived(customerData.data?.subscription);
	const licenseData = $derived(license.get());
	const billingEnabled = $derived(customerData.data?.mode === 'saas');

	const licenseBenefits = [
		'Unlimited members and infrastructure',
		'SAML, enforced SSO & audit export',
		'365-day audit retention',
		'Offline, air-gapped activation'
	];

	let ws = $derived(workspace.get());

	const isActive = $derived(
		subscription?.status === 'active' || subscription?.status === 'trialing'
	);
	const isPastDue = $derived(subscription?.status === 'past_due');
	const isCancelling = $derived(isActive && subscription?.cancelAtPeriodEnd);
	const cancel = billing.cancelSubscription();

	// The API resolves the canonical plan name; community renders as Free.
	const planNames: Record<string, string> = {
		community: 'Free',
		pro: 'Pro',
		enterprise: 'Enterprise'
	};
	const planDisplayName = $derived(planNames[data?.plan ?? 'community'] ?? 'Free');

	const checkout = billing.checkout();
	const portal = billing.portal();

	// -1 = unlimited (per-seat billing on pro/enterprise).
	// int64 fields arrive as number | bigint; coerce for arithmetic.
	const seats = $derived({
		used: Number(data?.memberCount ?? 0),
		cap: Number(data?.quotas?.seats ?? -1)
	});
	const seatsUnlimited = $derived(seats.cap < 0);
	const retentionDays = $derived(Number(data?.quotas?.retentionDays ?? 7));
	const storageBytes = $derived(Number(data?.quotas?.recordingStorageBytes ?? -1));
	const resources = $derived({
		used: Number(data?.resourceCount ?? 0),
		cap: Number(data?.quotas?.resourceCap ?? -1)
	});
	const resourcesUnlimited = $derived(resources.cap < 0);

	// Full catalog from the API: true = enabled, false = locked upgrade bait.
	const featureCatalog = [
		{ key: 'oidc', label: 'OIDC SSO', unlocks: null },
		{ key: 'enforce_sso', label: 'Enforced SSO', unlocks: 'Pro' },
		{ key: 'saml', label: 'SAML SSO', unlocks: 'Pro' },
		{ key: 'audit_export', label: 'Audit log export', unlocks: 'Pro' },
		{ key: 'external_kms', label: 'External KMS', unlocks: 'Enterprise' }
	];

	function handleCancel() {
		cancel.mutate({
			immediate: cancelImmediately,
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

{#if billingEnabled && !ws.data?.id}
	<Alert.Root variant="destructive" class="border-destructive/40 bg-destructive/5">
		<ShieldAlert class="h-4 w-4 text-destructive" />
		<Alert.Title>No Workspace Selected</Alert.Title>
		<Alert.Description>
			You must select a workspace to view actual billing details or upgrade. Any subscription
			purchased will be tied specifically to the currently active workspace.
		</Alert.Description>
	</Alert.Root>
{/if}

<div class="mx-auto mt-8 max-w-xl space-y-6">
	{#if billingEnabled}
		<!-- Plan Overview -->
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
						variant={isPastDue ? 'destructive' : isActive ? 'secondary' : 'outline'}
						class="z-10 border-primary/20 bg-primary/10 font-medium text-primary hover:bg-primary/20"
					>
						{#if isCancelling}
							Cancelling
						{:else if subscription?.status === 'trialing'}
							Trial
						{:else if isPastDue}
							Past Due
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
						<span class="font-medium text-foreground"
							>{formatTs(subscription?.currentPeriodEnd)}</span
						>
					{:else if isPastDue}
						Update your payment method in the billing portal to restore full access.
					{:else}
						You are on our free, limited capacity tier.
					{/if}
				</Card.Description>
			</Card.Header>

			<Card.Footer class="relative z-10 flex flex-col items-stretch gap-3 border-t sm:items-center">
				{#if isActive && !isCancelling}
					<Button
						variant="outline"
						class="w-full"
						onclick={portal.mutate}
						target="_blank"
						disabled={!ws.data?.id || portal.isPending}
					>
						{#if portal.isPending}
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

		<!-- Usage & Quotas -->
		<Card.Root class="rounded-xl border shadow-sm">
			<Card.Header class="pb-3">
				<Card.Title class="text-lg font-semibold tracking-tight">Usage & Quotas</Card.Title>
				<Card.Description>What your current plan includes.</Card.Description>
			</Card.Header>
			<Card.Content class="space-y-3">
				<div class="flex items-center justify-between gap-4 text-sm">
					<div class="flex items-center gap-2">
						<CircleUserIcon size={14} class="text-muted-foreground" />
						<span class="text-muted-foreground">Members</span>
					</div>
					<span class="font-medium tabular-nums">
						{seats.used}
						{#if seatsUnlimited}
							<span class="text-muted-foreground">· per-seat billing</span>
						{:else}
							<span class="text-muted-foreground">/{seats.cap}</span>
						{/if}
					</span>
				</div>
				{#if !seatsUnlimited}
					{@const pct = Math.min(Math.round((seats.used / seats.cap) * 100), 100)}
					<div class="h-1 w-full overflow-hidden rounded-full bg-secondary">
						<div
							class="h-full rounded-full {pct >= 100
								? 'bg-destructive'
								: pct >= 90
									? 'bg-amber-500'
									: 'bg-primary'}"
							style="width: {pct}%"
						></div>
					</div>
				{/if}
				<div class="grid grid-cols-2 gap-3 pt-1 sm:grid-cols-3">
					<div class="flex flex-col gap-1 rounded-lg border p-3 text-sm">
						<div class="flex items-center gap-2">
							<Clock size={14} class="text-muted-foreground" />
							<span class="text-muted-foreground">Retention</span>
						</div>
						<span class="font-medium tabular-nums">{retentionDays} days</span>
					</div>
					<div class="flex flex-col gap-1 rounded-lg border p-3 text-sm">
						<div class="flex items-center gap-2">
							<Database size={14} class="text-muted-foreground" />
							<span class="text-muted-foreground">Recording storage</span>
						</div>
						<span class="font-medium tabular-nums">
							{storageBytes < 0 ? 'Unlimited' : formatBytes(storageBytes)}
						</span>
					</div>
					<div class="flex flex-col gap-1 rounded-lg border p-3 text-sm">
						<div class="flex items-center gap-2">
							<Boxes size={14} class="text-muted-foreground" />
							<span class="text-muted-foreground">Resources</span>
						</div>
						<span class="font-medium tabular-nums">
							{#if resourcesUnlimited}
								Unlimited
							{:else}
								{resources.used}<span class="text-muted-foreground">/{resources.cap}</span>
							{/if}
						</span>
					</div>
				</div>
			</Card.Content>
		</Card.Root>

		<!-- Features -->
		<Card.Root class="rounded-xl border shadow-sm">
			<Card.Header class="pb-3">
				<Card.Title class="text-lg font-semibold tracking-tight">Features</Card.Title>
				<Card.Description>Included in {planDisplayName}, and what's locked.</Card.Description>
			</Card.Header>
			<Card.Content>
				<ul class="space-y-3">
					{#each featureCatalog as f (f.key)}
						{@const enabled = data?.features?.[f.key] === true}
						<li class="flex items-center justify-between gap-4 text-sm">
							<div class="flex items-center gap-2.5">
								{#if enabled}
									<Check size={16} strokeWidth={2.5} class="shrink-0 text-primary" />
								{:else}
									<Lock size={14} class="shrink-0 text-muted-foreground/60" />
								{/if}
								<span class={enabled ? '' : 'text-muted-foreground/70'}>{f.label}</span>
							</div>
							{#if !enabled && f.unlocks}
								<Badge variant="outline" class="text-[11px] text-muted-foreground">
									{f.unlocks}
								</Badge>
							{/if}
						</li>
					{/each}
				</ul>
			</Card.Content>
		</Card.Root>
	{:else}
		<!-- On-Premise License (self-hosted deployments only) -->
		{#if licenseData.data?.active}
			<!-- Enterprise Card -->
			<Card.Root
				class="relative overflow-hidden rounded-xl border border-primary/20 bg-linear-to-b from-background to-muted/20 shadow-lg shadow-primary/5"
			>
				<div
					class="pointer-events-none absolute -top-24 -right-24 h-48 w-48 rounded-full bg-primary/10 blur-[3rem]"
				></div>
				<div
					class="pointer-events-none absolute -bottom-12 -left-12 h-32 w-32 rounded-full bg-primary/5 blur-[2rem]"
				></div>

				<Card.Header class="pb-5">
					<div class="flex items-center justify-between">
						<Card.Title
							class="relative z-10 flex items-center gap-2.5 text-2xl font-semibold tracking-tight"
						>
							<BadgeCheck size={24} class="fill-primary/10 text-primary" />
							<span
								class="bg-linear-to-br from-foreground to-foreground/70 bg-clip-text text-transparent"
							>
								Enterprise
							</span>
						</Card.Title>
						<Badge
							variant="secondary"
							class="z-10 border border-primary/20 bg-primary/10 px-2.5 py-0.5 text-xs font-semibold tracking-wide text-primary shadow-sm"
						>
							Active
						</Badge>
					</div>
					<Card.Description class="relative z-10 mt-2 text-sm">
						Your instance is fully licensed and running the Enterprise plan.
					</Card.Description>
				</Card.Header>

				<Card.Content>
					{#if licenseData.data?.expiresAt}
						<div
							class="flex items-center justify-between rounded-lg border border-primary/10 bg-primary/5 px-4 py-3 text-sm"
						>
							<span class="font-medium text-muted-foreground">Valid until</span>
							<span class="text-foreground tabular-nums">
								{formatTs(licenseData.data.expiresAt)}
							</span>
						</div>
					{/if}
				</Card.Content>
			</Card.Root>
		{:else}
			<!-- Community Card -->
			<Card.Root
				class="relative overflow-hidden rounded-xl border bg-background shadow-sm transition-all hover:shadow-md"
			>
				<div
					class="pointer-events-none absolute -top-12 -right-12 h-32 w-32 rounded-full bg-muted-foreground/5 blur-3xl"
				></div>

				<Card.Header class="pb-5">
					<div class="flex items-center justify-between">
						<Card.Title
							class="relative z-10 flex items-center gap-2.5 text-2xl font-semibold tracking-tight text-foreground/90"
						>
							<KeyRound size={22} class="text-muted-foreground" />
							Community
						</Card.Title>
						<Badge
							variant="outline"
							class="z-10 bg-muted/50 px-2.5 py-0.5 text-xs font-medium text-muted-foreground"
						>
							Free
						</Badge>
					</div>
					<Card.Description class="relative z-10 mt-2 text-sm">
						Unlock the full platform capabilities for on-premise deployments.
					</Card.Description>
				</Card.Header>

				<Card.Content class="relative z-10 mb-2">
					<ul class="space-y-3">
						{#each licenseBenefits as b (b)}
							<li class="flex items-start gap-2.5 text-sm text-muted-foreground">
								<Check size={16} strokeWidth={2.5} class="mt-0.5 shrink-0 text-primary/70" />
								<span class="leading-snug">{b}</span>
							</li>
						{/each}
					</ul>
				</Card.Content>

				<Card.Footer class="relative z-10 flex flex-col gap-4 border-t bg-muted/10 px-6 py-5">
					<Button
						variant="default"
						class="w-full bg-linear-to-b from-primary to-primary/90 shadow-md transition-all hover:shadow-lg"
						onclick={() => window.open(LicensePurchaseURL, '_blank', 'noopener')}
					>
						Buy an Enterprise License
						<ExternalLink size={14} class="ml-1 opacity-70" />
					</Button>
					<p class="text-center text-[11px] leading-relaxed text-muted-foreground">
						Set <code
							class="rounded border bg-muted px-1 py-0.5 font-mono text-[10px] text-foreground/80"
							>NOKKU_LICENSE_KEY</code
						> on your server and restart to activate.
					</p>
				</Card.Footer>
			</Card.Root>
		{/if}
	{/if}
</div>
