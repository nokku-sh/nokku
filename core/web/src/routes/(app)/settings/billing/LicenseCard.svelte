<script lang="ts">
	import { plural } from '#lib/api/bulk.js';
	import { daysUntil, HOLD_DAYS, license, licenseStatus } from '#lib/api/license.svelte.js';
	import FormModal from '#lib/components/blocks/FormModal.svelte';
	import * as Alert from '#lib/components/ext/alert/index.js';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Textarea } from '#lib/components/ui/textarea/index.js';
	import { LicensePortalURL, LicensePurchaseURL, LicenseTrialURL } from '#lib/config.js';
	import type { GetBillingResponse } from '#lib/gen/nokku/v1/billing_pb.js';
	import { usePlans } from '#lib/plans.js';
	import type { Tone } from '#lib/tone.js';
	import { formatTs } from '#lib/utils.js';
	import { CreditCard, ExternalLink, Info, KeyRound, ShieldAlert } from '@lucide/svelte';

	let { billing, isOwner }: { billing: GetBillingResponse; isOwner: boolean } = $props();

	// The trial note shows from this many days before the end.
	const TRIAL_WARN_DAYS = 7;

	const plans = usePlans();
	const activate = license.activate();

	const hosted = $derived(billing.mode === 'saas');
	const place = $derived(hosted ? 'workspace' : 'server');
	const status = $derived(licenseStatus(billing.license));
	const phase = $derived(status.state);
	// Hosted only: no plan, so Nokku signs no certificates.
	const inactive = $derived(billing.plan === 'inactive');
	const onTrial = $derived(!!billing.trialEndsAt && !inactive);
	const trialDaysLeft = $derived(
		onTrial && billing.trialEndsAt ? Math.max(daysUntil(billing.trialEndsAt), 0) : undefined
	);
	const trialEndingSoon = $derived(trialDaysLeft !== undefined && trialDaysLeft <= TRIAL_WARN_DAYS);

	const title = $derived(inactive ? 'No active plan' : `${plans.planName(billing.plan)} plan`);

	const badge = $derived.by((): { label: string; tone: Tone } | undefined => {
		if (inactive) return { label: 'Inactive', tone: 'destructive' };
		if (onTrial) return { label: 'Trial', tone: 'info' };
		if (phase === 'active') return { label: 'Active', tone: 'success' };
		if (phase === 'expiring') return { label: 'Expires soon', tone: 'warning' };
		if (phase === 'expired') return { label: 'Expired', tone: 'destructive' };
		return undefined;
	});
	const activateLabels: Record<typeof phase, string> = {
		none: 'Activate a key',
		active: 'Activate a newer key',
		expiring: 'Activate a renewed key',
		expired: 'Activate a renewed key'
	};
	const licensed = $derived(phase === 'active' || phase === 'expiring');
	// The one note the card shows, the most urgent first.
	const alert = $derived.by(() => {
		if (inactive) return 'inactive';
		if (trialEndingSoon) return 'trial';
		if (phase === 'expiring' || phase === 'expired') return phase;
		return undefined;
	});
	const validUntil = $derived(licensed ? status.expiresAt : undefined);

	let open = $state(false);
	let key = $state('');

	async function submit() {
		await activate.mutateAsync({ key });
		key = '';
	}
</script>

<FormModal
	bind:open
	title="Activate a license key"
	description="Paste the key from your license email. It applies at once, nothing restarts."
	icon={KeyRound}
	onSubmit={submit}
	submitLabel="Activate"
	submitDisabled={!key.trim()}
>
	<Field.Field>
		<Field.Label for="license-key">License key</Field.Label>
		<Textarea
			id="license-key"
			bind:value={key}
			placeholder="NOKKU-XXXXX-XXXXX-..."
			rows={5}
			class="font-mono text-xs break-all"
			autocomplete="off"
			spellcheck={false}
		/>
		{#if !hosted}
			<Field.Description>
				Setting <code class="font-mono text-foreground">NOKKU_LICENSE_KEY</code> on the server works too.
				The key that is valid longest wins.
			</Field.Description>
		{/if}
	</Field.Field>
</FormModal>

<Card.Root>
	<Card.Header>
		<Card.Title class="text-xl font-semibold"><h2>{title}</h2></Card.Title>
		<Card.Description>
			{#if onTrial}
				Free until
				<span class="font-medium text-foreground">{formatTs(billing.trialEndsAt)}</span>. Buy a
				license and activate its key here to keep going after the trial.
			{:else if inactive && phase === 'expired'}
				The license expired on {formatTs(status.expiresAt)}.
			{:else if inactive}
				The trial ended{billing.trialEndsAt ? ` on ${formatTs(billing.trialEndsAt)}` : ''}.
			{:else if phase === 'none'}
				Free on your own server for up to 5 members. Pro is billed per seat and adds enforced SSO,
				audit log export and 90 days of history. A free trial key unlocks every feature for 30 days.
				Keys activate offline, so air-gapped servers work.
			{:else if phase === 'expired'}
				The license expired, so this server runs on the Community limits.
			{:else if billing.license?.plan === 'pro'}
				This {place} is licensed for Pro.
			{:else}
				This {place} is licensed for every Enterprise feature.
			{/if}
		</Card.Description>
		{#if badge}
			<Card.Action>
				<Badge variant={badge.tone}>{badge.label}</Badge>
			</Card.Action>
		{/if}
	</Card.Header>

	{#if alert || validUntil}
		<Card.Content class="flex flex-col gap-4">
			{#if alert === 'inactive'}
				<Alert.Root variant="destructive">
					<ShieldAlert />
					<Alert.Title>Nokku signs no certificates for this workspace</Alert.Title>
					<Alert.Description>
						Servers keep their access rules, and certificates already signed work until they expire.
						Nobody can sign in with <code class="font-mono">nk</code> or open a terminal, and
						nothing new can be added.
						{#if billing.heldUntil}
							Recordings and older audit logs are kept until {formatTs(billing.heldUntil)}.
						{/if}
						{#if billing.deleteAt}
							On {formatTs(billing.deleteAt)} the workspace and everything in it is deleted, and its name
							becomes free.
						{/if}
						Activate a license key {billing.deleteAt ? 'before then ' : ''}to pick up where you left
						off.
					</Alert.Description>
				</Alert.Root>
			{:else if alert === 'trial'}
				<Alert.Root variant="info">
					<Info />
					<Alert.Title>
						{trialDaysLeft === 0
							? 'The trial ends today'
							: `The trial ends in ${plural(trialDaysLeft ?? 0, 'day')}`}
					</Alert.Title>
					<Alert.Description>
						Then Nokku stops signing certificates for this workspace until a license key is active.
						Servers and their access rules stay as they are. Without a key the workspace is deleted {HOLD_DAYS}
						days after the trial.
					</Alert.Description>
				</Alert.Root>
			{:else if alert === 'expiring'}
				<Alert.Root variant="warning">
					<ShieldAlert />
					<Alert.Title>Expires in {plural(status.daysLeft ?? 0, 'day')}</Alert.Title>
					<Alert.Description>
						A renewed key arrives by email when the license renews. A {place} that is online picks it
						up by itself, otherwise activate it here to keep the licensed features without a gap.
					</Alert.Description>
				</Alert.Root>
			{:else if alert === 'expired'}
				<Alert.Root variant="destructive">
					<ShieldAlert />
					<Alert.Title>Expired on {formatTs(status.expiresAt)}</Alert.Title>
					<Alert.Description>
						Servers and sign-ins keep working. Licensed features are off.
						{#if billing.heldUntil}
							Recordings and audit logs beyond the Community limits are kept until
							{formatTs(billing.heldUntil)}.
						{/if}
					</Alert.Description>
				</Alert.Root>
			{/if}

			{#if validUntil}
				<div class="flex items-center justify-between rounded-lg border bg-muted/40 px-4 py-3">
					<span class="spec-label">Valid until</span>
					<span class="font-mono text-sm tabular-nums">{formatTs(validUntil)}</span>
				</div>
			{/if}
		</Card.Content>
	{/if}

	<Card.Footer class="flex flex-col items-stretch gap-3 border-t">
		{#if isOwner}
			<div class="flex flex-wrap gap-2">
				<Button variant={licensed ? 'outline' : 'default'} onclick={() => (open = true)}>
					<KeyRound data-icon="inline-start" />
					{activateLabels[phase]}
				</Button>
				{#if licensed}
					<Button variant="outline" href={LicensePortalURL} target="_blank" rel="noopener">
						<CreditCard data-icon="inline-start" />
						Manage seats and payment
						<ExternalLink data-icon="inline-end" />
					</Button>
				{:else}
					<Button variant="outline" href={LicensePurchaseURL} target="_blank" rel="noopener">
						Buy a license
						<ExternalLink data-icon="inline-end" />
					</Button>
				{/if}
				<!-- One trial per server, a lapsed key is renewed by buying. Hosted signup starts its own. -->
				{#if phase === 'none' && !hosted}
					<Button variant="ghost" href={LicenseTrialURL} target="_blank" rel="noopener">
						Start a free trial
						<ExternalLink data-icon="inline-end" />
					</Button>
				{/if}
			</div>
			{#if licensed}
				<p class="text-xs text-muted-foreground">
					New seats show up here when you come back to this page.{hosted
						? ''
						: ' A server without internet needs the new key from the email.'}
				</p>
			{/if}
		{:else}
			<p class="text-sm text-muted-foreground">The workspace owner activates license keys.</p>
		{/if}
	</Card.Footer>
</Card.Root>
