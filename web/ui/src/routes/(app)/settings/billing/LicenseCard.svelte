<script lang="ts">
	import { WorkspaceRole } from '#lib/gen/nokku/v1/access_pb.js';
	import { license, licenseStatus } from '#lib/api/license.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import FormModal from '#lib/components/blocks/FormModal.svelte';
	import * as Alert from '#lib/components/ext/alert/index.js';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { Textarea } from '#lib/components/ui/textarea/index.js';
	import { LicensePurchaseURL } from '#lib/config.js';
	import { atLeast } from '#lib/roles.js';
	import type { Tone } from '#lib/tone.js';
	import { formatTs } from '#lib/utils.js';
	import { Check, ExternalLink, KeyRound, ShieldAlert } from '@lucide/svelte';

	const data = license.get();
	const activate = license.activate();
	const me = user.self();

	const status = $derived(licenseStatus(data.data));
	const phase = $derived(status.state);
	const canActivate = $derived(atLeast(me.data?.role, WorkspaceRole.OWNER));

	const badges: Record<typeof phase, { label: string; tone: Tone }> = {
		none: { label: 'Free', tone: 'muted' },
		active: { label: 'Active', tone: 'success' },
		expiring: { label: 'Expires soon', tone: 'warning' },
		expired: { label: 'Expired', tone: 'destructive' }
	};

	const benefits = [
		'Unlimited users and infrastructure',
		'SCIM, enforced SSO and audit export',
		'365-day audit retention',
		'Offline, air-gapped activation'
	];

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
			<span class="spec-label">Self-hosted license</span>
			<Card.Title class="text-3xl font-semibold tracking-tight">
				{phase === 'none' ? 'Community' : 'Enterprise'}
			</Card.Title>
			<Card.Description>
				{#if phase === 'none'}
					Everything you need to start. Enterprise unlocks the rest.
				{:else if phase === 'expired'}
					This instance runs on Community limits until a new key is activated.
				{:else}
					This instance is licensed for every Enterprise feature.
				{/if}
			</Card.Description>
			<Card.Action>
				<Badge variant={badges[phase].tone}>{badges[phase].label}</Badge>
			</Card.Action>
		</Card.Header>
		<Card.Content class="flex flex-col gap-4">
			{#if phase === 'expiring'}
				<Alert.Root variant="warning">
					<ShieldAlert />
					<Alert.Title>
						Expires in {status.daysLeft}
						{status.daysLeft === 1 ? 'day' : 'days'}
					</Alert.Title>
					<Alert.Description>
						A renewed key arrives by email when the license renews. Activate it here to keep
						Enterprise features without a gap.
					</Alert.Description>
				</Alert.Root>
			{:else if phase === 'expired'}
				<Alert.Root variant="destructive">
					<ShieldAlert />
					<Alert.Title>Expired on {formatTs(status.expiresAt)}</Alert.Title>
					<Alert.Description>
						Licensed features are off. Nothing is deleted yet, recordings and audit logs beyond the
						Community limits are kept until {formatTs(status.keptUntil)}.
					</Alert.Description>
				</Alert.Root>
			{/if}

			{#if phase === 'none'}
				<ul class="flex flex-col gap-2.5">
					{#each benefits as b (b)}
						<li class="flex items-start gap-2.5 text-sm text-muted-foreground">
							<Check class="mt-0.5 size-4 shrink-0 text-primary" />
							{b}
						</li>
					{/each}
				</ul>
			{:else if status.expiresAt && phase !== 'expired'}
				<div class="flex items-center justify-between rounded-lg border bg-muted/40 px-4 py-3">
					<span class="spec-label">Valid until</span>
					<span class="font-mono text-sm tabular-nums">{formatTs(status.expiresAt)}</span>
				</div>
			{/if}
		</Card.Content>
		<Card.Footer class="flex flex-col items-stretch gap-3 border-t">
			<div class="flex flex-wrap gap-2">
				{#if canActivate}
					<Button
						variant={phase === 'active' ? 'outline' : 'default'}
						onclick={() => (open = true)}
					>
						<KeyRound data-icon="inline-start" />
						{phase === 'none' ? 'Activate a key' : 'Activate a renewed key'}
					</Button>
				{/if}
				{#if phase === 'none' || phase === 'expired'}
					<Button variant="outline" href={LicensePurchaseURL} target="_blank" rel="noopener">
						Buy an Enterprise license
						<ExternalLink data-icon="inline-end" />
					</Button>
				{/if}
			</div>
			{#if !canActivate}
				<p class="text-xs text-muted-foreground">A workspace owner can activate a license key.</p>
			{/if}
		</Card.Footer>
	</Card.Root>
{/if}
