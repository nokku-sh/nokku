<script lang="ts">
	import { WorkspaceRole } from '#lib/gen/nokku/v1/access_pb.js';
	import SecretReveal from '#lib/components/blocks/SecretReveal.svelte';
	import { untrack, type Snippet } from 'svelte';
	import { ca } from '#lib/api/certificates.svelte.js';
	import { target as targetApi } from '#lib/api/targets.svelte.js';
	import { token as tokenApi } from '#lib/api/tokens.svelte.js';
	import RolePicker from '#lib/components/access/RolePicker.svelte';
	import SubjectChip from '#lib/components/access/SubjectChip.svelte';
	import SubjectPicker from '#lib/components/access/SubjectPicker.svelte';
	import type { Subject } from '#lib/components/access/subjects.svelte.js';
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
	import * as Select from '#lib/components/ui/select/index.js';
	import * as Tabs from '#lib/components/ui/tabs/index.js';
	import { TagsInput } from '#lib/components/ui/tags-input/index.js';
	import * as ToggleGroup from '#lib/components/ui/toggle-group/index.js';
	import CopyText from '#lib/components/blocks/CopyText.svelte';
	import { JoinTokenKind, type JoinToken } from '#lib/gen/nokku/v1/join_token_pb.js';
	import { SubjectKind } from '#lib/gen/nokku/v1/target_account_pb.js';
	import { confirm } from '#lib/hooks/index.js';
	import { roleLabel } from '#lib/roles.js';
	import { formatTs, toDate } from '#lib/utils.js';
	import type { LucideIcon } from '@lucide/svelte';
	import { CircleCheck, KeyRound, List, Plus, ShieldCheck, Timer, Trash2, X } from '@lucide/svelte';
	import EntitySheet from './EntitySheet.svelte';
	import Section from './Section.svelte';

	interface Props {
		open: boolean;
		kind: JoinTokenKind;
		title: string;
		description: string;
		icon: LucideIcon;
		labelPlaceholder: string;
		/** What to do with a fresh secret: commands, a link, etc. */
		reveal: Snippet<[string, JoinToken | undefined]>;
	}

	let {
		open = $bindable(),
		kind,
		title,
		description,
		icon: Icon,
		labelPlaceholder,
		reveal
	}: Props = $props();

	const isEnroll = $derived(kind === JoinTokenKind.ENROLL);
	const noun = $derived(isEnroll ? 'token' : 'invite link');

	const expiries = [
		{ value: '3600', label: '1 hour' },
		{ value: '86400', label: '1 day' },
		{ value: '604800', label: '7 days' },
		{ value: '2592000', label: '30 days' },
		{ value: 'never', label: 'Never' }
	];
	const usePresets = $derived(
		isEnroll
			? [
					{ value: '1', label: '1 host' },
					{ value: '25', label: '25' },
					{ value: 'unlimited', label: 'Unlimited' },
					{ value: 'custom', label: 'Custom' }
				]
			: [
					{ value: '1', label: '1 person' },
					{ value: 'unlimited', label: 'Unlimited' },
					{ value: 'custom', label: 'Custom' }
				]
	);

	const retirePresets = [
		{ value: '300', label: '5 minutes' },
		{ value: '900', label: '15 minutes' },
		{ value: '3600', label: '1 hour' },
		{ value: '86400', label: '24 hours' }
	];
	// Same rule as the API, so a bad name fails here instead of on submit.
	const usernameRE = /^[A-Za-z_][A-Za-z0-9._-]*\$?$/;

	const tokens = tokenApi.list(() => kind);
	// Enrolled daemons create a target, which only an SSH CA can sign for.
	const cas = ca.list();
	const tagFilters = targetApi.filters();
	const caList = $derived(cas.data ?? []);
	const caName = (id: string) => caList.find((c) => c.id === id)?.name;
	const createToken = tokenApi.create();
	const removeToken = tokenApi.remove();

	let tab = $state('new');
	let label = $state('');
	// Hosts enroll within minutes, people take a few days to accept.
	let expiry = $state(untrack(() => (kind === JoinTokenKind.INVITE ? '604800' : '86400')));
	let uses = $state('unlimited');
	let customUses = $state('');
	let autoApprove = $state(true);
	let caId = $state('');
	let role = $state(WorkspaceRole.MEMBER);
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
			kind,
			label: label.trim(),
			ttl: expiry === 'never' ? undefined : { seconds: BigInt(expiry) },
			maxUses,
			autoApprove: isEnroll ? autoApprove || ephemeral : undefined,
			caId: isEnroll && caId ? caId : undefined,
			role: isEnroll ? undefined : role,
			tags: isEnroll ? tags : undefined,
			grants: isEnroll
				? grants.map((g) => ({
						username: g.username,
						userIds: ids(g.subjects, SubjectKind.USER),
						teamIds: ids(g.subjects, SubjectKind.TEAM),
						serviceAccountIds: ids(g.subjects, SubjectKind.SERVICE_ACCOUNT)
					}))
				: undefined,
			ephemeral: isEnroll ? ephemeral : undefined,
			retireAfter: isEnroll && ephemeral ? { seconds: BigInt(retireAfter) } : undefined
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
			title: `Revoke ${t.label || `this ${noun}`}?`,
			description: isEnroll
				? 'New hosts can no longer enroll with it. Daemons that already joined keep working.'
				: 'Nobody else can join with it. People who already joined stay.',
			confirmText: 'Revoke',
			onConfirm: () => removeToken.mutateAsync({ id: t.id })
		});
	}

	function expiresSoon(t: JoinToken) {
		return !!t.expiresAt && toDate(t.expiresAt).getTime() - Date.now() < 24 * 3600 * 1000;
	}

	const active = $derived(tokens.data?.tokens ?? []);
</script>

<EntitySheet
	{open}
	onClose={() => {
		open = false;
		another();
	}}
	{title}
	tabs={[
		{ value: 'new', label: `New ${noun}`, icon: Plus },
		{ value: 'active', label: 'Active', icon: List, count: active.length }
	]}
	{tab}
	onTabChange={(t) => (tab = t)}
>
	{#snippet media()}
		<div class="flex size-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
			<Icon class="size-5" />
		</div>
	{/snippet}
	{#snippet subtitle()}
		{description}
	{/snippet}

	<Tabs.Content value="new" class="flex flex-col divide-y">
		{#if createToken.isSuccess}
			<Section title={`${isEnroll ? 'Token' : 'Invite link'} created`} icon={CircleCheck}>
				<SecretReveal
					note="Copy it now, it is only shown once. Revoke it under Active if it leaks."
				>
					{@render reveal(createToken.data.secret, createToken.data.token)}
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
								placeholder={labelPlaceholder}
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
							<Field.Label>{isEnroll ? 'Hosts it can enroll' : 'People who can join'}</Field.Label>
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

				<Section title={isEnroll ? 'Enrolled hosts' : 'Role'} icon={ShieldCheck}>
					{#if isEnroll}
						<Field.Field orientation="horizontal">
							<Field.Content>
								<Field.Label for="token-auto-approve">Approve automatically</Field.Label>
								<Field.Description>
									Daemons join right away instead of waiting for you in the daemons list. Handy for
									fleets, keep it off for one-off hosts.
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
							<Field.Label for="token-ca">Certificate authority</Field.Label>
							<Select.Root type="single" bind:value={caId}>
								<Select.Trigger id="token-ca" class="w-full">
									{caName(caId) ?? 'Workspace default'}
								</Select.Trigger>
								<Select.Content>
									<Select.Group>
										<Select.Item value="">Workspace default</Select.Item>
										{#each caList as c (c.id)}
											<Select.Item value={c.id}>{c.name}</Select.Item>
										{/each}
									</Select.Group>
								</Select.Content>
							</Select.Root>
							<Field.Description>
								The target each host creates on enroll is pinned to this CA.
							</Field.Description>
						</Field.Field>
						<Field.Field>
							<Field.Label for="token-tags">Tags</Field.Label>
							<TagsInput
								id="token-tags"
								value={tags}
								suggestions={tagFilters.data?.tags}
								onValueChange={(v) => (tags = v)}
							/>
							<Field.Description>Every target the token creates gets these tags.</Field.Description>
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
									<InputGroup.Button
										type="button"
										variant="secondary"
										size="xs"
										onclick={addAccount}
									>
										<Plus data-icon="inline-start" />
										Add
									</InputGroup.Button>
								</InputGroup.Addon>
							</InputGroup.Root>
							<Field.Description>
								Every host enrolled with this token starts with these grants. The account has to
								exist on the host. Change grants per host later, under its target.
							</Field.Description>
						</Field.Field>
					{:else}
						<RolePicker value={role} onChange={(r) => (role = r)} />
					{/if}
				</Section>

				{#if isEnroll}
					<Section title="Lifetime" icon={Timer}>
						<Field.Field orientation="horizontal">
							<Field.Content>
								<Field.Label for="token-ephemeral">Ephemeral hosts</Field.Label>
								<Field.Description>
									For containers, devboxes and sandboxes. A host is approved on enroll, removes
									itself when it stops, and is removed after it has been offline for a while.
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
				{/if}

				<div class="pt-5">
					<Button type="submit" disabled={createToken.isPending} class="w-full sm:w-auto">
						{#if createToken.isPending}
							<Spinner data-icon="inline-start" />
						{:else}
							<Plus data-icon="inline-start" />
						{/if}
						Create {noun}
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
						Create {noun}
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
								{#if t.caId}<Badge variant="outline">CA {caName(t.caId) ?? 'unknown'}</Badge>{/if}
								{#if t.role}<Badge variant="secondary">{roleLabel(t.role)}</Badge>{/if}
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
							aria-label={`Revoke ${t.label || noun}`}
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
