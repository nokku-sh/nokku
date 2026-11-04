<script lang="ts">
	import SecretReveal from '#lib/components/blocks/SecretReveal.svelte';
	import { target as targetApi } from '#lib/api/targets.svelte.js';
	import { token as tokenApi } from '#lib/api/tokens.svelte.js';
	import SubjectChip from '#lib/components/access/SubjectChip.svelte';
	import SubjectPicker from '#lib/components/access/SubjectPicker.svelte';
	import type { Subject } from '#lib/components/access/subjects.svelte.js';
	import * as Alert from '#lib/components/ext/alert/index.js';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import * as InputGroup from '#lib/components/ui/input-group/index.js';
	import { Progress } from '#lib/components/ui/progress/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import { Switch } from '#lib/components/ui/switch/index.js';
	import * as Tabs from '#lib/components/ui/tabs/index.js';
	import { TagsInput } from '#lib/components/ui/tags-input/index.js';
	import * as ToggleGroup from '#lib/components/ui/toggle-group/index.js';
	import CodeSnippet from '#lib/components/blocks/CodeSnippet.svelte';
	import CopyText from '#lib/components/blocks/CopyText.svelte';
	import type { JoinToken } from '#lib/gen/nokku/v1/join_token_pb.js';
	import { SubjectKind } from '#lib/gen/nokku/v1/target_account_pb.js';
	import { confirm } from '#lib/hooks/index.js';
	import { formatTs, toDate } from '#lib/utils.js';
	import {
		CircleCheck,
		Info,
		KeyRound,
		List,
		Plus,
		Rocket,
		ShieldCheck,
		Timer,
		Trash2,
		X
	} from '@lucide/svelte';
	import EntitySheet from './EntitySheet.svelte';
	import Section from './Section.svelte';

	let { open = $bindable(false) }: { open?: boolean } = $props();

	const expiries = [
		{ value: '3600', label: '1 hour' },
		{ value: '86400', label: '1 day' },
		{ value: '604800', label: '7 days' },
		{ value: '2592000', label: '30 days' },
		{ value: 'never', label: 'Never' }
	];
	const usePresets = [
		{ value: '1', label: '1 host' },
		{ value: '25', label: '25' },
		{ value: 'unlimited', label: 'Unlimited' },
		{ value: 'custom', label: 'Custom' }
	];

	const retirePresets = [
		{ value: '300', label: '5 minutes' },
		{ value: '900', label: '15 minutes' },
		{ value: '3600', label: '1 hour' },
		{ value: '86400', label: '24 hours' }
	];
	// Same rule as the API, so a bad name fails here instead of on submit.
	const usernameRE = /^[A-Za-z_][A-Za-z0-9._-]*\$?$/;

	const tokens = tokenApi.list();
	const tagFilters = targetApi.filters();
	const createToken = tokenApi.create();
	const removeToken = tokenApi.remove();

	let tab = $state('new');
	let label = $state('');
	// Hosts enroll within minutes.
	let expiry = $state('86400');
	let uses = $state('unlimited');
	let customUses = $state('');
	let autoApprove = $state(true);
	let tags = $state<string[]>([]);
	let grants = $state<{ username: string; subjects: Subject[] }[]>([]);
	let newAccount = $state('');
	let ephemeral = $state(false);
	let retireAfter = $state('900');

	const canAddAccount = $derived.by(() => {
		const name = newAccount.trim();
		return (
			name.length > 0 &&
			name.length <= 32 &&
			usernameRE.test(name) &&
			!grants.some((g) => g.username === name)
		);
	});

	function addAccount() {
		if (!canAddAccount) return;
		grants.push({ username: newAccount.trim(), subjects: [] });
		newAccount = '';
	}

	function toggleGrant(username: string, subject: Subject, grant: boolean) {
		const g = grants.find((x) => x.username === username);
		if (!g) return;
		g.subjects = grant
			? [...g.subjects.filter((s) => s.id !== subject.id), subject]
			: g.subjects.filter((s) => s.id !== subject.id);
	}

	const ids = (subjects: Subject[], kind: SubjectKind) =>
		subjects.filter((s) => s.kind === kind).map((s) => s.id);

	const maxUses = $derived(
		uses === 'unlimited'
			? undefined
			: uses === 'custom'
				? Number(customUses) || undefined
				: Number(uses)
	);

	async function submit() {
		await createToken.mutateAsync({
			label: label.trim(),
			ttl: expiry === 'never' ? undefined : { seconds: BigInt(expiry) },
			maxUses,
			autoApprove: autoApprove || ephemeral,
			tags,
			grants: grants.map((g) => ({
				username: g.username,
				userIds: ids(g.subjects, SubjectKind.USER),
				teamIds: ids(g.subjects, SubjectKind.TEAM),
				serviceAccountIds: ids(g.subjects, SubjectKind.SERVICE_ACCOUNT)
			})),
			ephemeral,
			retireAfter: ephemeral ? { seconds: BigInt(retireAfter) } : undefined
		});
	}

	function another() {
		createToken.reset();
		label = '';
		tags = [];
		grants = [];
		ephemeral = false;
	}

	function askRevoke(t: JoinToken) {
		void confirm({
			title: `Revoke ${t.label || 'this token'}?`,
			description:
				'New hosts can no longer enroll with it. Daemons that already joined keep working.',
			confirmText: 'Revoke',
			onConfirm: () => removeToken.mutateAsync({ id: t.id })
		});
	}

	function expiresSoon(t: JoinToken) {
		return !!t.expiresAt && toDate(t.expiresAt).getTime() - Date.now() < 24 * 3600 * 1000;
	}

	const active = $derived(tokens.data?.tokens ?? []);

	// The installer needs root. Ansible and cloud-init already run as root.
	const installer = 'curl -fsSL https://get.nokku.sh/nokkud';
	// nokkud talks to app.nokku.sh unless told otherwise, self-hosted needs the URL.
	const selfHosted = location.origin !== 'https://app.nokku.sh';
	const apiEnv = selfHosted ? `NOKKUD_API_URL=${location.origin} ` : '';

	function envFlags(token: string) {
		return [
			`NOKKUD_ENROLL_TOKEN='${token}'`,
			...(selfHosted ? [`NOKKUD_API_URL=${location.origin}`] : [])
		];
	}

	function snippets(token: string) {
		return [
			{
				value: 'host',
				label: 'One host',
				language: 'bash',
				hint: 'Paste the token when nokkud asks for it. It never ends up in your shell history.',
				code: [
					`${installer} | sudo sh`,
					`sudo ${apiEnv}nokkud enroll`,
					'sudo systemctl restart nokkud'
				].join('\n')
			},
			{
				value: 'script',
				label: 'Script',
				language: 'bash',
				hint: 'Unattended. The token goes in through the environment, never as an argument.',
				code: [
					`${installer} | sudo sh`,
					`sudo NOKKUD_ENROLL_TOKEN='${token}' ${apiEnv}nokkud enroll`,
					'sudo systemctl restart nokkud'
				].join('\n')
			},
			{
				value: 'ansible',
				label: 'Ansible',
				language: 'yaml',
				hint: 'Idempotent, reruns skip enrolled hosts. Keep the token in ansible-vault for real playbooks.',
				code: `- name: Enroll hosts with Nokku
  hosts: all
  become: true
  vars:
    nokkud_enroll_token: "${token}"
  tasks:
    - name: Install nokkud
      ansible.builtin.shell: ${installer} | sh
      args:
        creates: /usr/bin/nokkud

    - name: Enroll
      ansible.builtin.command: nokkud enroll
      args:
        creates: /var/lib/nokkud/ssh_host_ecdsa_key
      environment:
        NOKKUD_ENROLL_TOKEN: "{{ nokkud_enroll_token }}"${selfHosted ? `\n        NOKKUD_API_URL: "${location.origin}"` : ''}
      no_log: true
      notify: Restart nokkud

    - name: Keep nokkud running
      ansible.builtin.systemd_service:
        name: nokkud
        state: started
        enabled: true

  handlers:
    - name: Restart nokkud
      ansible.builtin.systemd_service:
        name: nokkud
        state: restarted`
			},
			{
				value: 'cloud-init',
				label: 'cloud-init',
				language: 'yaml',
				hint: 'User data is readable from the instance metadata, so use a short expiry and a use limit.',
				code: `#cloud-config
runcmd:
  - ${installer} | sh
  - NOKKUD_ENROLL_TOKEN='${token}' ${apiEnv}nokkud enroll
  - systemctl restart nokkud`
			},
			{
				value: 'container',
				label: 'Container',
				language: 'bash',
				hint: 'The container enrolls itself on start and is reached through the relay, no port to open. An ephemeral token removes it again when it stops.',
				code: [
					'docker run -d --hostname alice \\',
					...envFlags(token).map((e) => `  -e ${e} \\`),
					'  ghcr.io/nokku-sh/nokkud',
					'ssh dev@alice'
				].join('\n')
			}
		];
	}
</script>

<EntitySheet
	{open}
	onClose={() => {
		open = false;
		another();
	}}
	title="Enroll daemons"
	tabs={[
		{ value: 'new', label: 'New token', icon: Plus },
		{ value: 'active', label: 'Active', icon: List, count: active.length }
	]}
	{tab}
	onTabChange={(t) => (tab = t)}
>
	{#snippet media()}
		<div class="flex size-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
			<Rocket class="size-5" />
		</div>
	{/snippet}
	{#snippet subtitle()}
		Tokens let new nokkud installs join this workspace. One token can enroll a whole fleet.
	{/snippet}

	<Tabs.Content value="new" class="flex flex-col divide-y">
		{#if createToken.isSuccess}
			<Section title="Token created" icon={CircleCheck}>
				<SecretReveal
					note="Copy it now, it is only shown once. Revoke it under Active if it leaks."
				>
					{@const secret = createToken.data.secret}
					<div class="flex items-center gap-2 rounded-lg border bg-muted/40 px-3 py-2">
						<span class="shrink-0 text-xs text-muted-foreground">Token</span>
						<CopyText value={secret} mono class="text-sm" />
					</div>

					<Tabs.Root value="host" class="gap-2">
						<Tabs.List variant="line" class="w-full justify-start">
							{#each snippets(secret) as s (s.value)}
								<Tabs.Trigger value={s.value} class="flex-none">{s.label}</Tabs.Trigger>
							{/each}
						</Tabs.List>
						{#each snippets(secret) as s (s.value)}
							<Tabs.Content value={s.value} class="flex flex-col gap-2">
								<CodeSnippet code={s.code} language={s.language} />
								<p class="text-xs text-muted-foreground">{s.hint}</p>
							</Tabs.Content>
						{/each}
					</Tabs.Root>

					{#if selfHosted}
						<Alert.Root variant="info">
							<Info />
							<Alert.Description>
								Self-hosted: the commands point nokkud at {location.origin} through NOKKUD_API_URL.
							</Alert.Description>
						</Alert.Root>
					{/if}
				</SecretReveal>
				<Button variant="outline" size="sm" class="self-start" onclick={another}>
					<Plus data-icon="inline-start" />
					Create another
				</Button>
			</Section>
		{:else}
			<form
				class="flex flex-col divide-y"
				onsubmit={(e) => {
					e.preventDefault();
					void submit();
				}}
			>
				<Section title="Settings" icon={KeyRound}>
					<Field.Group class="gap-4">
						<Field.Field>
							<Field.Label for="token-label">Name</Field.Label>
							<Input
								id="token-label"
								bind:value={label}
								placeholder="ansible prod-eu"
								maxlength={100}
							/>
							<Field.Description>Helps you find it later in the Active list.</Field.Description>
						</Field.Field>
						<Field.Field>
							<Field.Label>Expires after</Field.Label>
							<ToggleGroup.Root
								type="single"
								variant="outline"
								size="sm"
								value={expiry}
								onValueChange={(v) => v && (expiry = v)}
								class="w-full flex-wrap"
							>
								{#each expiries as e (e.value)}
									<ToggleGroup.Item value={e.value} class="flex-1">{e.label}</ToggleGroup.Item>
								{/each}
							</ToggleGroup.Root>
						</Field.Field>
						<Field.Field>
							<Field.Label>Hosts it can enroll</Field.Label>
							<ToggleGroup.Root
								type="single"
								variant="outline"
								size="sm"
								value={uses}
								onValueChange={(v) => v && (uses = v)}
								class="w-full"
							>
								{#each usePresets as u (u.value)}
									<ToggleGroup.Item value={u.value} class="flex-1">{u.label}</ToggleGroup.Item>
								{/each}
							</ToggleGroup.Root>
							{#if uses === 'custom'}
								<Input
									type="number"
									min="1"
									bind:value={customUses}
									placeholder="How many"
									aria-label="Maximum uses"
								/>
							{/if}
						</Field.Field>
					</Field.Group>
				</Section>

				<Section title="Enrolled hosts" icon={ShieldCheck}>
					<Field.Field orientation="horizontal">
						<Field.Content>
							<Field.Label for="token-auto-approve">Approve automatically</Field.Label>
							<Field.Description>
								Daemons join right away instead of waiting for your approval in the servers list.
								Handy for fleets, keep it off for one-off hosts.
							</Field.Description>
						</Field.Content>
						<Switch
							id="token-auto-approve"
							checked={autoApprove || ephemeral}
							onCheckedChange={(v) => (autoApprove = v)}
							disabled={ephemeral}
						/>
					</Field.Field>
					<Field.Field>
						<Field.Label for="token-tags">Tags</Field.Label>
						<TagsInput
							id="token-tags"
							value={tags}
							suggestions={tagFilters.data?.tags}
							onValueChange={(v) => (tags = v)}
						/>
						<Field.Description>Every server the token adds gets these tags.</Field.Description>
					</Field.Field>
					<Field.Field>
						<Field.Label for="token-account">Login accounts</Field.Label>
						{#each grants as g (g.username)}
							<div class="flex flex-col gap-1.5 rounded-lg border bg-card p-2">
								<div class="flex items-center gap-2">
									<span class="min-w-0 flex-1 truncate font-mono text-sm">{g.username}</span>
									<SubjectPicker
										selected={g.subjects.map((s) => s.id)}
										onToggle={(s, grant) => toggleGrant(g.username, s, grant)}
										label="Grant"
										variant="ghost"
										size="xs"
									/>
									<Button
										variant="ghost"
										size="icon-xs"
										aria-label={`Remove ${g.username}`}
										onclick={() => (grants = grants.filter((x) => x.username !== g.username))}
									>
										<X />
									</Button>
								</div>
								{#if g.subjects.length}
									<div class="flex flex-wrap gap-1.5">
										{#each g.subjects as s (s.id)}
											<SubjectChip
												grant={{ id: s.id, kind: s.kind, subject: s }}
												onRemove={() => toggleGrant(g.username, s, false)}
											/>
										{/each}
									</div>
								{/if}
							</div>
						{/each}
						<InputGroup.Root>
							<InputGroup.Addon><KeyRound /></InputGroup.Addon>
							<InputGroup.Input
								id="token-account"
								bind:value={newAccount}
								placeholder="Add a login account, e.g. dev"
								onkeydown={(e) => {
									if (e.key !== 'Enter') return;
									e.preventDefault();
									addAccount();
								}}
							/>
							<InputGroup.Addon align="inline-end">
								<InputGroup.Button type="button" variant="secondary" size="xs" onclick={addAccount}>
									<Plus data-icon="inline-start" />
									Add
								</InputGroup.Button>
							</InputGroup.Addon>
						</InputGroup.Root>
						<Field.Description>
							Every host enrolled with this token starts with these grants. The account has to exist
							on the host. Change grants per host later, under its target.
						</Field.Description>
					</Field.Field>
				</Section>

				<Section title="Lifetime" icon={Timer}>
					<Field.Field orientation="horizontal">
						<Field.Content>
							<Field.Label for="token-ephemeral">Ephemeral hosts</Field.Label>
							<Field.Description>
								For containers, devboxes and sandboxes. A host is approved on enroll, removes itself
								when it stops, and is removed after it has been offline for a while.
							</Field.Description>
						</Field.Content>
						<Switch id="token-ephemeral" bind:checked={ephemeral} />
					</Field.Field>
					{#if ephemeral}
						<Field.Field>
							<Field.Label>Remove after offline for</Field.Label>
							<ToggleGroup.Root
								type="single"
								variant="outline"
								size="sm"
								value={retireAfter}
								onValueChange={(v) => v && (retireAfter = v)}
								class="w-full flex-wrap"
							>
								{#each retirePresets as r (r.value)}
									<ToggleGroup.Item value={r.value} class="flex-1">{r.label}</ToggleGroup.Item>
								{/each}
							</ToggleGroup.Root>
							<Field.Description>
								A host that comes back under the same name takes over from the one that went away.
							</Field.Description>
						</Field.Field>
					{/if}
				</Section>

				<div class="pt-5">
					<Button type="submit" disabled={createToken.isPending} class="w-full sm:w-auto">
						{#if createToken.isPending}
							<Spinner data-icon="inline-start" />
						{:else}
							<Plus data-icon="inline-start" />
						{/if}
						Create token
					</Button>
				</div>
			</form>
		{/if}
	</Tabs.Content>

	<Tabs.Content value="active" class="flex flex-col gap-2">
		{#if tokens.isLoading}
			<Skeleton class="h-20 w-full rounded-xl" />
			<Skeleton class="h-20 w-full rounded-xl" />
		{:else if !active.length}
			<Empty.Root class="border border-dashed">
				<Empty.Header>
					<Empty.Media variant="icon"><KeyRound /></Empty.Media>
					<Empty.Title>Nothing active</Empty.Title>
					<Empty.Description>Tokens show up here until they expire or run out.</Empty.Description>
				</Empty.Header>
				<Empty.Content>
					<Button size="sm" variant="outline" onclick={() => (tab = 'new')}>
						<Plus data-icon="inline-start" />
						Create token
					</Button>
				</Empty.Content>
			</Empty.Root>
		{:else}
			{#each active as t (t.id)}
				<div class="flex flex-col gap-2.5 rounded-xl border bg-card p-3">
					<div class="flex items-start gap-3">
						<div class="min-w-0 flex-1">
							<p class="flex flex-wrap items-center gap-1.5 text-sm font-medium">
								<span class="truncate">{t.label || 'Untitled'}</span>
								{#if t.ephemeral}<Badge variant="info">Ephemeral</Badge>{/if}
								{#if t.autoApprove && !t.ephemeral}<Badge variant="info">Auto-approve</Badge>{/if}
								{#if t.grants.length}
									<Badge variant="outline">
										{t.grants.length}
										{t.grants.length === 1 ? 'account' : 'accounts'}
									</Badge>
								{/if}
								{#each t.tags as tag (tag)}<Badge variant="muted">{tag}</Badge>{/each}
							</p>
							<p class="text-xs text-muted-foreground">
								Created {formatTs(t.createdAt, 'relative')}
								{#if t.lastUsedAt}· last used {formatTs(t.lastUsedAt, 'relative')}{/if}
							</p>
						</div>
						<Button
							variant="ghost"
							size="icon-sm"
							aria-label={`Revoke ${t.label || 'token'}`}
							onclick={() => askRevoke(t)}
						>
							<Trash2 />
						</Button>
					</div>
					<div class="flex items-center gap-3 text-xs">
						{#if t.maxUses}
							<Progress value={(t.uses / t.maxUses) * 100} class="h-1.5 flex-1" />
							<span class="shrink-0 text-muted-foreground tabular-nums">
								{t.uses} / {t.maxUses} used
							</span>
						{:else}
							<span class="flex-1 text-muted-foreground tabular-nums">
								{t.uses} used · no limit
							</span>
						{/if}
						<Badge variant={expiresSoon(t) ? 'warning' : 'outline'} class="shrink-0">
							{t.expiresAt ? `Expires ${formatTs(t.expiresAt, 'relative')}` : 'Never expires'}
						</Badge>
					</div>
					<div class="text-xs text-muted-foreground">
						ID <CopyText value={t.id} mono />
					</div>
				</div>
			{/each}
		{/if}
	</Tabs.Content>
</EntitySheet>
