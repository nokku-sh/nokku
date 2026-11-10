<script lang="ts">
	import { whenFresh } from '#lib/api/auth.svelte.js';
	import { plural } from '#lib/api/bulk.js';
	import { ca, missedRollover } from '#lib/api/certificates.svelte.js';
	import { target } from '#lib/api/targets.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import { util, workspace } from '#lib/api/workspaces.svelte.js';
	import Chip from '#lib/components/blocks/Chip.svelte';
	import CodeSnippet from '#lib/components/blocks/CodeSnippet.svelte';
	import LoadError from '#lib/components/blocks/LoadError.svelte';
	import SaveStatus from '#lib/components/blocks/SaveStatus.svelte';
	import StatusDot from '#lib/components/blocks/StatusDot.svelte';
	import * as Alert from '#lib/components/ext/alert/index.js';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import * as InputGroup from '#lib/components/ui/input-group/index.js';
	import * as Item from '#lib/components/ui/item/index.js';
	import * as Select from '#lib/components/ui/select/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { CertificateAuthoritySchema } from '#lib/gen/nokku/v1/certificates_pb.js';
	import { TargetStatus } from '#lib/gen/nokku/v1/target_pb.js';
	import { AuditOutcome } from '#lib/gen/nokku/v1/util_pb.js';
	import { confirm, useAutoSave, useDraft } from '#lib/hooks/index.js';
	import { UseClipboard } from '#lib/hooks/use-clipboard.svelte.js';
	import type { Tone } from '#lib/tone.js';
	import { cn, formatHours, formatTs, listNames, toDate } from '#lib/utils.js';
	import { durationFromMs, durationMs, timestampFromMs } from '@bufbuild/protobuf/wkt';
	import { Check, Copy, Plus, ShieldAlert, TriangleAlert } from '@lucide/svelte';

	// Ansible fills in the braces, so they stay out of the markup.
	const PLAYBOOK = `- name: Trust the Nokku CA, run it again after a rollover
  ansible.builtin.command: nk sync {{ inventory_hostname }}
  delegate_to: localhost`;
	const MAX_ADDRESSES = 1024;
	const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

	const can = user.can();
	const ws = workspace.get();
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

	// The core takes 15 minutes to 7 days. These cover what people pick.
	const LIFETIME_HOURS = [1, 4, 8, 16, 24, 72, 168];
	const lifetimeHours = $derived(model?.userTtl ? durationMs(model.userTtl) / 3_600_000 : 0);
	// One set over the API stays on offer.
	const lifetimes = $derived(
		[...new Set([...LIFETIME_HOURS, lifetimeHours])].filter(Boolean).toSorted((a, b) => a - b)
	);

	function setLifetime(hours: string) {
		if (!model) return;
		model.userTtl = durationFromMs(Number(hours) * 3_600_000);
		save();
	}

	const manualList = target.list(() => ({ status: TargetStatus.MANUAL }));
	const manual = $derived(manualList.data?.targets ?? []);
	const manualCount = $derived(manualList.data?.total ?? 0);
	const manualNames = $derived(manual.map((t) => t.name));
	const missingKey = $derived(
		manual.filter((t) => missedRollover(entity?.rotatedAt, t.lastSyncAt)).map((t) => t.name)
	);
	const missingText = $derived(
		`${plural(missingKey.length, 'server')} ${missingKey.length === 1 ? 'misses' : 'miss'} the new key`
	);
	const unchecked = $derived(manualCount - manual.length);
	const syncCommands = (names: string[]) => names.map((name) => `nk sync ${name}`).join('\n');

	const midnight = timestampFromMs(new Date().setHours(0, 0, 0, 0));
	const signedToday = util.getLogs(() => ({
		filter: {
			actions: ['SignSSHCertificate'],
			outcome: AuditOutcome.SUCCEEDED,
			startDate: midnight
		},
		limit: 1
	}));
	// The rollover's own audit row, looked up by its time, not by scanning back.
	const rotatedMs = $derived(entity?.rotatedAt ? toDate(entity.rotatedAt).getTime() : 0);
	const rollovers = util.getLogs(
		() => ({
			filter: {
				actions: ['RolloverCertificateAuthority'],
				outcome: AuditOutcome.SUCCEEDED,
				startDate: timestampFromMs(rotatedMs - 60_000),
				endDate: timestampFromMs(rotatedMs + 60_000)
			},
			limit: 1
		}),
		() => rotatedMs > 0
	);

	// Only what we can tell. A daemon that is offline may still miss a new key.
	const status = $derived.by((): { tone: Tone; text: string } => {
		if (missingKey.length) return { tone: 'destructive', text: missingText };
		if (unchecked > 0) return { tone: 'muted', text: `${plural(unchecked, 'server')} not checked` };
		return {
			tone: 'success',
			text: `In use since ${formatTs(entity?.rotatedAt ?? entity?.createdAt, 'short')}`
		};
	});

	const facts = $derived([
		{ label: 'Algorithm', value: 'Ed25519' },
		{ label: 'Made', value: formatTs(entity?.createdAt, 'short') },
		...(signedToday.data
			? [{ label: 'Certificates today', value: String(signedToday.data.total) }]
			: [])
	]);

	const keys = $derived(
		entity
			? [
					{ name: 'User key', key: entity.userPublicKey, print: entity.userPublicKeyFingerprint },
					{ name: 'Host key', key: entity.hostPublicKey, print: entity.hostPublicKeyFingerprint }
				]
			: []
	);
	const clipboard = new UseClipboard({ delay: 1500 });
	let copiedKey = $state('');
	// Plain http has no clipboard, so the whole key shows up to select instead.
	let shownKey = $state('');
	async function copyKey(key: string) {
		copiedKey = key;
		if ((await clipboard.copy(key)) === 'failure') shownKey = key;
	}

	const history = $derived.by(() => {
		if (!entity) return [];
		if (!entity.rotatedAt) {
			return [
				{
					title: 'Current keys',
					detail: `Made with the workspace, ${formatTs(entity.createdAt, 'short')}`
				}
			];
		}
		const actor = rollovers.data?.logs[0]?.actorName;
		const by = actor ? `, by ${actor}` : '';
		return [
			{ title: 'Current keys', detail: `Since ${formatTs(entity.rotatedAt, 'short')}${by}` },
			{ title: 'Previous keys', detail: 'Not trusted any more' }
		];
	});

	const callout = $derived.by(() => {
		if (missingKey.length) {
			return {
				tone: 'destructive' as const,
				title: missingText,
				text: 'They refuse new certificates until you run this on your own machine. A certificate from before the rollover still gets you in, for an hour at most.',
				names: missingKey
			};
		}
		if (manual.length) {
			return {
				tone: 'warning' as const,
				title: 'Before you roll over',
				text: `${plural(manualCount, 'server')} ${manualCount === 1 ? 'was' : 'were'} set up with nk sync and ${manualCount === 1 ? 'has' : 'have'} no daemon. Run this right after a rollover, new logins there fail until you do.`,
				names: manualNames
			};
		}
		return undefined;
	});

	function askRollover() {
		void whenFresh(() =>
			confirm({
				title: 'Roll over the keys?',
				description:
					'New keys replace both, for every server in this workspace, and nothing trusts the old ones any more. Servers with the daemon take the new keys at their next sync, within a minute, and close sessions that started on the old ones. People get a new certificate when they next connect. A server set up with nk sync trusts only the old key until you run nk sync on it, so do that right away. Until then, people there keep the certificate they hold, an hour at most.' +
					(manualCount
						? ` That is ${plural(manualCount, 'server')} here: ${listNames(manualNames, 5, manualCount)}.`
						: ''),
				confirmText: 'Roll over',
				typeToConfirm: 'roll over',
				onConfirm: () => rollover.mutateAsync({})
			})
		);
	}

	// The server takes addresses and CIDRs split by commas, the same check runs here first.
	const addresses = $derived([
		...new Set(
			(model?.sourceAddress ?? '')
				.split(',')
				.map((a) => a.trim())
				.filter(Boolean)
		)
	]);
	let typedAddress = $state('');
	let addressError = $state('');

	// A pasted list goes in at once, what does not parse stays in the box.
	function addAddress() {
		const typed = typedAddress.split(/[\s,]+/).filter(Boolean);
		if (!typed.length || !model) return;
		const bad = typed.filter((a) => !validAddress(a));
		const next = [...new Set([...addresses, ...typed.filter(validAddress)])].join(',');
		if (next.length > MAX_ADDRESSES) {
			addressError = `The list holds up to ${MAX_ADDRESSES} characters.`;
			return;
		}
		typedAddress = bad.join(' ');
		addressError = bad.length
			? `${listNames(bad)} ${bad.length === 1 ? 'is' : 'are'} neither an address nor a CIDR.`
			: '';
		if (next === addresses.join(',')) return;
		model.sourceAddress = next;
		save();
	}

	function removeAddress(value: string) {
		if (!model) return;
		model.sourceAddress = addresses.filter((a) => a !== value).join(',');
		save();
	}

	// Follows Go's net.ParseIP, the URL parser has the same IPv6 rules.
	function validAddress(value: string): boolean {
		const [ip, prefix, ...rest] = value.split('/');
		if (rest.length) return false;
		const v4 = IPV4.test(ip);
		const v6 = !v4 && ip.includes(':') && URL.canParse(`http://[${ip}]`);
		if (!v4 && !v6) return false;
		if (prefix === undefined) return true;
		return /^\d{1,3}$/.test(prefix) && Number(prefix) <= (v4 ? 32 : 128);
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
			idleText={can.admin
				? 'Changes save automatically'
				: 'View only, your role cannot change this'}
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
	<Skeleton class="h-80 w-full rounded-xl" />
	<div class="grid gap-6 lg:grid-cols-2">
		<Skeleton class="h-64 w-full rounded-xl" />
		<Skeleton class="h-40 w-full rounded-xl" />
	</div>
{:else}
	<Card.Root class="gap-0 overflow-hidden py-0">
		<div class="grid lg:grid-cols-2">
			<section aria-labelledby="ca-keys" class="flex min-w-0 flex-col gap-5 p-6 lg:border-r">
				<div class="flex flex-wrap items-start justify-between gap-3">
					<div class="flex min-w-0 flex-col">
						<h2 id="ca-keys" class="truncate font-semibold">
							{ws.data?.name ? `${ws.data.name} CA` : 'Workspace CA'}
						</h2>
						<p class="text-sm text-muted-foreground">The private halves never leave the core.</p>
					</div>
					<Badge variant={status.tone} class="gap-1.5">
						<StatusDot tone={status.tone} />
						{status.text}
					</Badge>
				</div>

				<dl class="grid grid-cols-3 gap-4">
					{#each facts as f (f.label)}
						<div class="flex min-w-0 flex-col gap-1">
							<dt class="spec-label">{f.label}</dt>
							<dd class="truncate font-medium">{f.value}</dd>
						</div>
					{/each}
				</dl>

				<ul class="flex flex-col gap-2" aria-label="Public keys">
					{#each keys as k (k.name)}
						{@const copied = clipboard.copied && copiedKey === k.key}
						<li
							class="grid grid-cols-[1fr_auto] items-center gap-x-3 gap-y-1 rounded-lg border px-3 py-2"
						>
							<span class="text-sm font-medium">{k.name}</span>
							<Button
								variant="outline"
								size="xs"
								aria-label={`Copy the ${k.name.toLowerCase()}`}
								onclick={() => copyKey(k.key)}
							>
								{#if copied}
									<Check data-icon="inline-start" />
									Copied
								{:else}
									<Copy data-icon="inline-start" />
									Copy key
								{/if}
							</Button>
							<code
								class="col-span-2 font-mono text-xs break-all text-muted-foreground select-all"
								title={k.key}
							>
								{shownKey === k.key ? k.key : k.print}
							</code>
						</li>
					{/each}
				</ul>
				<p class="text-xs text-muted-foreground">
					The user key is what sshd's TrustedUserCAKeys holds. People trust a daemon whose host
					certificate the host key signed.
				</p>
			</section>

			<section
				aria-labelledby="ca-rollover"
				class="flex min-w-0 flex-col gap-4 border-t bg-muted/40 p-6 lg:border-t-0"
			>
				<div class="flex flex-col gap-1">
					<h2 id="ca-rollover" class="font-semibold">Rollover</h2>
					<p class="text-sm text-muted-foreground">
						For keys that may have leaked. If the core's secret or KMS key leaked, rotate that
						first, then roll over here. Nothing trusts the old keys after a rollover.
					</p>
				</div>

				<ol aria-label="Key history" class="flex flex-col">
					{#each history as h, i (h.title)}
						<li class="flex gap-3">
							<span aria-hidden="true" class="flex w-3 shrink-0 flex-col items-center">
								<span
									class={cn(
										'mt-1 size-3 rounded-full border-2',
										i === 0 ? 'border-primary bg-primary' : 'border-muted-foreground/50 bg-card'
									)}
								></span>
								{#if i < history.length - 1}
									<span class="w-0.5 flex-1 bg-border"></span>
								{/if}
							</span>
							<span class="flex min-w-0 flex-col pb-4">
								<span class="text-sm font-medium">{h.title}</span>
								<span class="text-xs text-muted-foreground">{h.detail}</span>
							</span>
						</li>
					{/each}
				</ol>

				{#if callout}
					<Alert.Root variant={callout.tone}>
						<TriangleAlert />
						<Alert.Title>{callout.title}</Alert.Title>
						<Alert.Description class="flex flex-col gap-2">
							<p>{callout.text}</p>
							<CodeSnippet code={syncCommands(callout.names)} language="bash" wrap class="w-full" />
							{#if unchecked > 0}
								<p>
									{plural(unchecked, 'more server')}
									{unchecked === 1 ? 'was' : 'were'} not checked,
									<a href="/servers?status=manual" class="underline">find them under Servers</a>.
								</p>
							{/if}
						</Alert.Description>
					</Alert.Root>
				{/if}

				{#if can.admin}
					<div>
						<Button variant="destructive" onclick={askRollover}>
							<ShieldAlert data-icon="inline-start" />
							Roll over keys
						</Button>
					</div>
				{/if}
			</section>
		</div>
	</Card.Root>

	<div class="grid gap-6 lg:grid-cols-2 lg:items-start">
		<Card.Root>
			<Card.Header>
				<Card.Title><h2>How long certificates last</h2></Card.Title>
				<Card.Description>
					Shorter is safer. nk renews them in the background, so people don't notice.
				</Card.Description>
			</Card.Header>
			<Card.Content class="flex flex-col gap-3" onfocusin={askFresh}>
				<Item.Root variant="outline">
					<Item.Content>
						<Item.Title><label for="ca-user-ttl">Login certificates</label></Item.Title>
						<Item.Description>What a person's login gets, a week at most.</Item.Description>
					</Item.Content>
					<Item.Actions class="w-full sm:w-auto">
						<Select.Root
							type="single"
							value={String(lifetimeHours)}
							disabled={!can.admin}
							onValueChange={setLifetime}
						>
							<Select.Trigger id="ca-user-ttl" class="w-full sm:w-44">
								{formatHours(lifetimeHours)}
							</Select.Trigger>
							<Select.Content>
								{#each lifetimes as h (h)}
									<Select.Item value={String(h)}>{formatHours(h)}</Select.Item>
								{/each}
							</Select.Content>
						</Select.Root>
					</Item.Actions>
				</Item.Root>
				<p class="text-xs text-muted-foreground">
					A server without the daemon only drops access when a certificate runs out. There, and for
					service accounts, a certificate lasts an hour at most whatever is set here. A daemon's
					host certificate lasts 90 days and renews by itself.
				</p>
			</Card.Content>
		</Card.Root>

		<div class="flex min-w-0 flex-col gap-6">
			<Card.Root>
				<Card.Header>
					<Card.Title><h2>Where people log in from</h2></Card.Title>
					<Card.Description>
						Goes on every person's certificate and on browser terminals. Service accounts have
						limits of their own, so this never blocks a CI runner.
					</Card.Description>
				</Card.Header>
				<Card.Content onfocusin={askFresh}>
					<Field.Field data-invalid={addressError ? true : undefined}>
						<Field.Label for="ca-source-address">Allowed addresses</Field.Label>
						{#if addresses.length}
							<div class="flex flex-wrap gap-1.5">
								{#each addresses as a (a)}
									<Chip label={a} mono onRemove={can.admin ? () => removeAddress(a) : undefined} />
								{/each}
							</div>
						{/if}
						{#if can.admin}
							<InputGroup.Root>
								<InputGroup.Input
									id="ca-source-address"
									class="font-mono"
									bind:value={typedAddress}
									aria-invalid={addressError ? true : undefined}
									placeholder="10.0.0.0/8"
									oninput={() => (addressError = '')}
									onkeydown={(e) => {
										if (e.key !== 'Enter' && e.key !== ',') return;
										e.preventDefault();
										addAddress();
									}}
									onblur={addAddress}
								/>
								<InputGroup.Addon align="inline-end">
									<InputGroup.Button
										type="button"
										variant="secondary"
										size="xs"
										onclick={addAddress}
									>
										<Plus data-icon="inline-start" />
										Add
									</InputGroup.Button>
								</InputGroup.Addon>
							</InputGroup.Root>
						{/if}
						<Field.Description>
							{#if addressError}
								{addressError}
							{:else if addresses.length}
								Logins from anywhere else are refused.
							{:else}
								Empty, so any address can log in.
							{/if}
						</Field.Description>
					</Field.Field>
				</Card.Content>
			</Card.Root>

			<Card.Root>
				<Card.Header>
					<Card.Title><h2>For Ansible</h2></Card.Title>
					<Card.Description>
						nk sync runs on your machine with your nk login, reaches the server as root with your
						own ssh, and is safe to run again.
					</Card.Description>
				</Card.Header>
				<Card.Content>
					<CodeSnippet code={PLAYBOOK} language="yaml" />
				</Card.Content>
			</Card.Root>
		</div>
	</div>
{/if}
