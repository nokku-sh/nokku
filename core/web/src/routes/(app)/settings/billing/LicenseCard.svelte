<script lang="ts">
	import { license, licenseStatus } from '#lib/api/license.svelte.js';
	import FormModal from '#lib/components/blocks/FormModal.svelte';
	import * as Alert from '#lib/components/ext/alert/index.js';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { Textarea } from '#lib/components/ui/textarea/index.js';
	import { LicensePurchaseURL, LicenseTrialURL } from '#lib/config.js';
	import type { GetBillingResponse } from '#lib/gen/nokku/v1/billing_pb.js';
	import { usePlans } from '#lib/plans.js';
	import type { Tone } from '#lib/tone.js';
	import { formatTs } from '#lib/utils.js';
	import { ExternalLink, KeyRound, ShieldAlert } from '@lucide/svelte';

	let { billing, isOwner }: { billing: GetBillingResponse; isOwner: boolean } = $props();

	const data = license.get();
	const plans = usePlans();
	const activate = license.activate();

	const status = $derived(licenseStatus(data.data));
	const phase = $derived(status.state);

	const badges: Record<typeof phase, { label: string; tone: Tone } | undefined> = {
		none: undefined,
		active: { label: 'Active', tone: 'success' },
		expiring: { label: 'Expires soon', tone: 'warning' },
		expired: { label: 'Expired', tone: 'destructive' }
	};
	const activateLabels: Record<typeof phase, string> = {
		none: 'Activate a key',
		active: 'Activate a newer key',
		expiring: 'Activate a renewed key',
		expired: 'Activate a renewed key'
	};

	const badge = $derived(badges[phase]);
	// Community unless the key is active.
	const plan = $derived(data.data?.plan);

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
		<Field.Description>
			Setting <code class="font-mono text-foreground">NOKKU_LICENSE_KEY</code> on the server works too.
			The key that is valid longest wins.
		</Field.Description>
	</Field.Field>
</FormModal>

{#if data.isLoading}
	<Skeleton class="h-56 w-full rounded-xl" />
{:else}
	<Card.Root>
		<Card.Header>
			<Card.Title class="text-xl font-semibold">
				<h2>{plans.planName(plan)} plan</h2>
			</Card.Title>
			<Card.Description>
				{#if phase === 'none'}
					Free on your own server for up to 5 members. Pro is billed per seat and adds enforced SSO,
					audit log export and 90 days of history. A free trial key unlocks every feature for 30
					days. Keys activate offline, so air-gapped servers work.
				{:else if phase === 'expired'}
					The license expired, so this server runs on the Community limits.
				{:else if plan === 'pro'}
					This server is licensed for Pro.
				{:else}
					This server is licensed for every Enterprise feature.
				{/if}
			</Card.Description>
			{#if badge}
				<Card.Action>
					<Badge variant={badge.tone}>{badge.label}</Badge>
				</Card.Action>
			{/if}
		</Card.Header>

		{#if phase !== 'none'}
			<Card.Content class="flex flex-col gap-4">
				{#if phase === 'expiring'}
					<Alert.Root variant="warning">
						<ShieldAlert />
						<Alert.Title>
							Expires in {status.daysLeft}
							{status.daysLeft === 1 ? 'day' : 'days'}
						</Alert.Title>
						<Alert.Description>
							A renewed key arrives by email when the license renews. Activate it here to keep the
							licensed features without a gap.
						</Alert.Description>
					</Alert.Root>
				{:else if phase === 'expired'}
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

				{#if status.expiresAt && phase !== 'expired'}
					<div class="flex items-center justify-between rounded-lg border bg-muted/40 px-4 py-3">
						<span class="spec-label">Valid until</span>
						<span class="font-mono text-sm tabular-nums">{formatTs(status.expiresAt)}</span>
					</div>
				{/if}
			</Card.Content>
		{/if}

		<Card.Footer class="flex flex-col items-stretch gap-3 border-t">
			{#if isOwner}
				<div class="flex flex-wrap gap-2">
					<Button
						variant={phase === 'active' ? 'outline' : 'default'}
						onclick={() => (open = true)}
					>
						<KeyRound data-icon="inline-start" />
						{activateLabels[phase]}
					</Button>
					{#if phase === 'none' || phase === 'expired'}
						<Button variant="outline" href={LicensePurchaseURL} target="_blank" rel="noopener">
							Buy a license
							<ExternalLink data-icon="inline-end" />
						</Button>
					{/if}
					<!-- One trial per server, a lapsed key is renewed by buying. -->
					{#if phase === 'none'}
						<Button variant="ghost" href={LicenseTrialURL} target="_blank" rel="noopener">
							Start a free trial
							<ExternalLink data-icon="inline-end" />
						</Button>
					{/if}
				</div>
			{:else}
				<p class="text-sm text-muted-foreground">The workspace owner activates license keys.</p>
			{/if}
		</Card.Footer>
	</Card.Root>
{/if}
