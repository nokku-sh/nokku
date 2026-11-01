<script lang="ts">
	import { whenFresh } from '#lib/api/auth.svelte.js';
	import { ca, manualKeyState } from '#lib/api/certificates.svelte.js';
	import { target } from '#lib/api/targets.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import CodeSnippet from '#lib/components/blocks/CodeSnippet.svelte';
	import DurationInput from '#lib/components/blocks/DurationInput.svelte';
	import LoadError from '#lib/components/blocks/LoadError.svelte';
	import SaveStatus from '#lib/components/blocks/SaveStatus.svelte';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import DangerZone from '#lib/components/sheets/DangerZone.svelte';
	import DetailList from '#lib/components/sheets/DetailList.svelte';
	import Section from '#lib/components/sheets/Section.svelte';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { CertificateAuthoritySchema } from '#lib/gen/nokku/v1/certificates_pb.js';
	import { confirm, useAutoSave, useDraft } from '#lib/hooks/index.js';
	import { formatTs, toDate } from '#lib/utils.js';
	import type { Duration } from '@bufbuild/protobuf/wkt';
	import { Clock, Fingerprint, History, KeyRound, RefreshCw, Server } from '@lucide/svelte';

	const can = user.can();
	const query = ca.get();
	const entity = $derived(query.data);
	const draft = useDraft(CertificateAuthoritySchema, () => query.data);
	const model = $derived(draft.current);

	const update = ca.update();
	const rollover = ca.rollover();

	const autoSave = useAutoSave(() => draft.save((changes) => update.mutateAsync({ ...changes })));
	const save = () => autoSave.save();
	// A change here takes a recent sign-in, so that comes before anything is typed.
	const askFresh = () => void whenFresh(() => {});

	const lifetimes: {
		key: 'userDefaultTtl' | 'userMaxTtl' | 'hostTtl';
		label: string;
		hint: string;
	}[] = [
		{
			key: 'userDefaultTtl',
			label: 'Login certificates',
			hint: 'What a login gets unless nk asks for less or more.'
		},
		{ key: 'userMaxTtl', label: 'Longest login', hint: 'The most nk --ttl can ask for.' },
		{
			key: 'hostTtl',
			label: 'Host certificates',
			hint: 'A daemon renews its own before this runs out.'
		}
	];

	function setLifetime(key: (typeof lifetimes)[number]['key'], value: Duration) {
		if (!model) return;
		model[key] = value;
		save();
	}

	const targets = target.list();
	const manual = $derived((targets.data?.targets ?? []).filter((t) => !t.daemonId));
	const missingKey = $derived(
		manual.filter((t) => manualKeyState(entity, t.lastSyncAt).rotated).map((t) => t.name)
	);
	const keepsOldKey = $derived(
		manual.filter((t) => manualKeyState(entity, t.lastSyncAt).oldKeyUntil).map((t) => t.name)
	);
	const syncCommands = (names: string[]) => names.map((name) => `nk sync ${name}`).join('\n');
	const unchecked = $derived((targets.data?.total ?? 0) - (targets.data?.targets.length ?? 0));

	const previousTrusted = $derived(
		!!entity?.previousPublicKey &&
			!!entity.previousTrustedUntil &&
			toDate(entity.previousTrustedUntil).getTime() > Date.now()
	);

	// Both run the same call, marked fresh. Only daemons learn the new keys on their own.
	function askRotate() {
		void whenFresh(() =>
			confirm({
				title: 'Rotate the keys?',
				description:
					'New keys replace both, for every server in this workspace. Servers with the daemon take them at their next sync, and certificates already signed keep working until they run out. A server set up with nk sync still trusts only the old key, so run nk sync on it right away. Until you do, people there keep the certificate they hold, an hour at most, and then get refused.',
				confirmText: 'Rotate',
				onConfirm: () => rollover.mutateAsync({ revokePrevious: false })
			})
		);
	}

	function askRollover() {
		void whenFresh(() =>
			confirm({
				title: 'Emergency rollover?',
				description:
					'New keys replace both, for every server in this workspace, and the old ones stop being trusted at once. Servers with the daemon drop them at their next sync, and people get a new certificate at their next connection. A server set up with nk sync goes on trusting the old key and refuses every new certificate until someone reaches it another way and runs nk sync.',
				confirmText: 'Roll over',
				typeToConfirm: 'emergency rollover',
				onConfirm: () => rollover.mutateAsync({ revokePrevious: true })
			})
		);
	}
</script>

<PageHeader
	title="Certificate authority"
	description="One CA signs every login and every host certificate in this workspace"
>
	{#if model && entity}
		<SaveStatus
			state={autoSave.saveState}
			onRetry={autoSave.retry}
			idleText={can.edit ? 'Changes save automatically' : 'View only, your role cannot change this'}
		/>
	{/if}
</PageHeader>

{#if query.isError}
	<LoadError
		title="The certificate authority did not load"
		description="Nothing changed, servers keep working as before."
		onRetry={() => query.refetch()}
		class="h-[25vh] rounded-xl border-solid bg-card text-card-foreground"
	/>
{:else if !model || !entity}
	<Skeleton class="h-56 w-full rounded-xl" />
	<Skeleton class="h-36 w-full rounded-xl" />
{:else}
	{#if missingKey.length || keepsOldKey.length}
		<Card.Root>
			<Card.Header>
				<Card.Title><h2>Servers to sync</h2></Card.Title>
				<Card.Description>
					These servers were set up with nk sync, so they only learn a key when you run it.
					{#if unchecked > 0}
						{unchecked} more servers were not checked, open them under Infrastructure.
					{/if}
				</Card.Description>
			</Card.Header>
			<Card.Content class="flex flex-col divide-y">
				{#if missingKey.length}
					<Section
						title="Missing the new key"
						icon={RefreshCw}
						description="They refuse new certificates until you run this on your own machine."
					>
						<CodeSnippet code={syncCommands(missingKey)} language="bash" wrap />
					</Section>
				{/if}
				{#if keepsOldKey.length}
					<Section
						title="Still trusting the old key"
						icon={Clock}
						description="They can't drop it on their own. Run this after {formatTs(
							entity.previousTrustedUntil
						)}."
					>
						<CodeSnippet code={syncCommands(keepsOldKey)} language="bash" wrap />
					</Section>
				{/if}
			</Card.Content>
		</Card.Root>
	{/if}

	<Card.Root>
		<Card.Header>
			<Card.Title><h2>Certificate lifetime</h2></Card.Title>
			<Card.Description>One setting for every server in this workspace</Card.Description>
		</Card.Header>
		<Card.Content class="flex flex-col gap-4" onfocusin={askFresh}>
			<div class="grid grid-cols-1 gap-4 lg:grid-cols-3">
				{#each lifetimes as l (l.key)}
					<Field.Field>
						<Field.Label for="ca-{l.key}">{l.label}</Field.Label>
						<DurationInput
							id="ca-{l.key}"
							value={model[l.key]}
							disabled={!can.edit}
							onchange={(v) => setLifetime(l.key, v)}
						/>
						<Field.Description>{l.hint}</Field.Description>
					</Field.Field>
				{/each}
			</div>
			<p class="text-sm text-muted-foreground">
				Short login certificates are the safest, a server without the daemon only drops access when
				they expire. There, and for service accounts, a certificate lasts an hour at most whatever
				you set here. nk renews them on its own.
			</p>
		</Card.Content>
	</Card.Root>

	<Card.Root>
		<Card.Header>
			<Card.Title><h2>Where people log in from</h2></Card.Title>
			<Card.Description>
				It goes on every person's certificate and on browser terminals. A service account has limits
				of its own, set on the account, so this list never blocks a CI runner.
			</Card.Description>
		</Card.Header>
		<Card.Content onfocusin={askFresh}>
			<Field.Field>
				<Field.Label for="ca-source-address">Allowed source IPs</Field.Label>
				<Input
					id="ca-source-address"
					class="font-mono"
					bind:value={model.sourceAddress}
					disabled={!can.edit}
					oninput={save}
					placeholder="10.0.0.0/8, 192.168.1.10"
				/>
				<Field.Description>
					Addresses and CIDRs, separated by commas. Leave empty to allow any.
				</Field.Description>
			</Field.Field>
		</Card.Content>
	</Card.Root>

	<Card.Root>
		<Card.Header>
			<Card.Title><h2>Public keys</h2></Card.Title>
			<Card.Description>The private halves never leave the core</Card.Description>
		</Card.Header>
		<Card.Content class="flex flex-col divide-y">
			<Section
				title="User key"
				icon={KeyRound}
				description="Servers let in logins whose certificate this key signed. It is what sshd's TrustedUserCAKeys holds."
			>
				<CodeSnippet code={entity.publicKey} language="openssh" wrap />
			</Section>

			<Section
				title="Host key"
				icon={Server}
				description="People trust a daemon whose host certificate this key signed. It never signs a login."
			>
				<CodeSnippet code={entity.hostPublicKey} language="openssh" wrap />
			</Section>

			{#if previousTrusted}
				<Section
					title="Previous keys"
					icon={History}
					description="Replaced by a rotation. Still trusted until {formatTs(
						entity.previousTrustedUntil
					)}."
				>
					<CodeSnippet code={entity.previousPublicKey ?? ''} language="openssh" wrap />
					{#if entity.previousHostPublicKey}
						<CodeSnippet code={entity.previousHostPublicKey} language="openssh" wrap />
					{/if}
				</Section>
			{/if}

			<Section title="Identity" icon={Fingerprint}>
				<DetailList
					items={[
						{ label: 'Algorithm', value: 'Ed25519' },
						{ label: 'Keys made', value: formatTs(entity.rotatedAt) }
					]}
				/>
			</Section>
		</Card.Content>
	</Card.Root>

	<DangerZone
		actions={can.edit
			? [
					{
						title: 'Rotate keys',
						description:
							'Replace both keys. Daemons take the new ones on their own, run nk sync on every other server.',
						label: 'Rotate',
						onClick: askRotate
					},
					{
						title: 'Emergency rollover',
						description:
							'Distrust the keys now and replace them, for keys that may have leaked. Servers set up with nk sync lock out until you reach them another way.',
						label: 'Roll over',
						onClick: askRollover
					}
				]
			: []}
	/>
{/if}
