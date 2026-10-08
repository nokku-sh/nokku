<script lang="ts">
	import { WorkspaceRole } from '#lib/gen/nokku/v1/access_pb.js';
	import SecretReveal from '#lib/components/blocks/SecretReveal.svelte';
	import { untrack, type Snippet } from 'svelte';
	import { ca } from '#lib/api/certificates.svelte.js';
	import { token as tokenApi } from '#lib/api/tokens.svelte.js';
	import RolePicker from '#lib/components/access/RolePicker.svelte';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Progress } from '#lib/components/ui/progress/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import { Switch } from '#lib/components/ui/switch/index.js';
	import * as Select from '#lib/components/ui/select/index.js';
	import * as Tabs from '#lib/components/ui/tabs/index.js';
	import * as ToggleGroup from '#lib/components/ui/toggle-group/index.js';
	import CopyText from '#lib/components/blocks/CopyText.svelte';
	import { AuthorityType } from '#lib/gen/nokku/v1/certificates_pb.js';
	import { TokenKind, type Token } from '#lib/gen/nokku/v1/token_pb.js';
	import { confirm } from '#lib/hooks/index.js';
	import { roleLabel } from '#lib/roles.js';
	import { formatTs, toDate } from '#lib/utils.js';
	import type { LucideIcon } from '@lucide/svelte';
	import { CircleCheck, KeyRound, List, Plus, ShieldCheck, Trash2 } from '@lucide/svelte';
	import EntitySheet from './EntitySheet.svelte';
	import Section from './Section.svelte';

	interface Props {
		open: boolean;
		kind: TokenKind;
		title: string;
		description: string;
		icon: LucideIcon;
		labelPlaceholder: string;
		/** What to do with a fresh secret: commands, a link, etc. */
		reveal: Snippet<[string, Token | undefined]>;
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

	const isEnroll = $derived(kind === TokenKind.ENROLL);
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

	const tokens = tokenApi.list(() => kind);
	// Enrolled daemons create a target, which only an SSH CA can sign for.
	const cas = ca.list();
	const sshCAs = $derived((cas.data ?? []).filter((c) => c.authorityType === AuthorityType.SSH));
	const caName = (id: string) => sshCAs.find((c) => c.id === id)?.name;
	const createToken = tokenApi.create();
	const removeToken = tokenApi.remove();

	let tab = $state('new');
	let label = $state('');
	// Hosts enroll within minutes, people take a few days to accept.
	let expiry = $state(untrack(() => (kind === TokenKind.INVITE ? '604800' : '86400')));
	let uses = $state('unlimited');
	let customUses = $state('');
	let autoApprove = $state(true);
	let caId = $state('');
	let role = $state(WorkspaceRole.MEMBER);

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
			autoApprove: isEnroll ? autoApprove : undefined,
			caId: isEnroll && caId ? caId : undefined,
			role: isEnroll ? undefined : role
		});
	}

	function another() {
		createToken.reset();
		label = '';
	}

	function askRevoke(t: Token) {
		void confirm({
			title: `Revoke ${t.label || `this ${noun}`}?`,
			description: isEnroll
				? 'New hosts can no longer enroll with it. Daemons that already joined keep working.'
				: 'Nobody else can join with it. People who already joined stay.',
			confirmText: 'Revoke',
			onConfirm: () => removeToken.mutateAsync({ id: t.id })
		});
	}

	function expiresSoon(t: Token) {
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
							<Switch id="token-auto-approve" bind:checked={autoApprove} />
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
										{#each sshCAs as c (c.id)}
											<Select.Item value={c.id}>{c.name}</Select.Item>
										{/each}
									</Select.Group>
								</Select.Content>
							</Select.Root>
							<Field.Description>
								The target each host creates on enroll is pinned to this CA.
							</Field.Description>
						</Field.Field>
					{:else}
						<RolePicker value={role} onChange={(r) => (role = r)} />
					{/if}
				</Section>

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
								{#if t.autoApprove}<Badge variant="info">Auto-approve</Badge>{/if}
								{#if t.caId}<Badge variant="outline">CA {caName(t.caId) ?? 'unknown'}</Badge>{/if}
								{#if t.role}<Badge variant="secondary">{roleLabel(t.role)}</Badge>{/if}
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
