<script lang="ts">
	import { targetAccount as accountApi } from '#lib/api/target-accounts.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import { MAX_PAGE_SIZE } from '#lib/config.js';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as DropdownMenu from '#lib/components/ui/dropdown-menu/index.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import * as InputGroup from '#lib/components/ui/input-group/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import * as Tooltip from '#lib/components/ui/tooltip/index.js';
	import { SubjectKind, type TargetAccount } from '#lib/gen/nokku/v1/target_account_pb.js';
	import { confirm } from '#lib/hooks/index.js';
	import { Ellipsis, KeyRound, Plus, Search, SquareTerminal, Trash2 } from '@lucide/svelte';
	import { SvelteMap } from 'svelte/reactivity';
	import GrantLength from './GrantLength.svelte';
	import SubjectChip from './SubjectChip.svelte';
	import SubjectPicker from './SubjectPicker.svelte';
	import { grantEnd, grantsOf, kindLabels, type Subject, type SubjectRef } from './subjects.svelte';

	interface Props {
		targetId: string;
		/** Accounts come from `nk sync` instead of a daemon. */
		manual?: boolean;
	}

	let { targetId, manual = false }: Props = $props();

	const can = user.can();
	const accounts = accountApi.list(() => ({ targetId, limit: MAX_PAGE_SIZE }));
	const addSubjects = accountApi.addSubjects();
	const removeSubjects = accountApi.removeSubjects();
	const addAccount = accountApi.addAccount();
	const removeAccount = accountApi.removeAccount();

	// Pending grants and revokes, shown right away until the refetch lands.
	const pending = new SvelteMap<string, SubjectRef | null>();
	const key = (p: TargetAccount, id: string) => `${p.id}:${id}`;

	function granted(p: TargetAccount): SubjectRef[] {
		const server = grantsOf(p).filter((g) => pending.get(key(p, g.id)) !== null);
		const added = [...pending]
			.filter(([k, g]) => g && k.startsWith(`${p.id}:`) && !server.some((s) => s.id === g.id))
			.map(([, g]) => g as SubjectRef);
		return [...server, ...added];
	}

	// Hours a grant made here lasts, 0 is for good.
	let hours = $state(0);

	async function toggle(p: TargetAccount, subject: Pick<Subject, 'id' | 'kind'>, grant: boolean) {
		const k = key(p, subject.id);
		const expiresAt = grant ? grantEnd(hours) : undefined;
		pending.set(
			k,
			grant ? { id: subject.id, kind: subject.kind, subject: subject as Subject, expiresAt } : null
		);
		const change = { id: p.id, subjectIds: [subject.id], kind: subject.kind };
		try {
			await (grant
				? addSubjects.mutateAsync({ ...change, expiresAt })
				: removeSubjects.mutateAsync(change));
		} finally {
			pending.delete(k);
		}
	}

	function summary(grants: SubjectRef[]) {
		if (!grants.length) return 'Nobody can use it yet';
		const kinds = [SubjectKind.USER, SubjectKind.TEAM, SubjectKind.SERVICE_ACCOUNT];
		return kinds
			.map((kind) => {
				const n = grants.filter((g) => g.kind === kind).length;
				return n ? `${n} ${n === 1 ? kindLabels[kind].one : kindLabels[kind].many}` : '';
			})
			.filter(Boolean)
			.join(' · ');
	}

	let filter = $state('');
	let newAccount = $state('');
	const list = $derived(accounts.data?.accounts ?? []);
	const shown = $derived(
		filter ? list.filter((a) => a.username.includes(filter.trim().toLowerCase())) : list
	);
	const canAdd = $derived(
		!!newAccount.trim() && !list.some((a) => a.username === newAccount.trim())
	);

	async function submitAccount() {
		if (!canAdd) return;
		const username = newAccount.trim();
		newAccount = '';
		await addAccount.mutateAsync({ targetId, username });
	}

	function askRemoveAccount(p: TargetAccount) {
		void confirm({
			title: `Remove ${p.username}?`,
			description:
				'Everyone granted on this login account loses it. The account on the host stays untouched.',
			confirmText: 'Remove',
			onConfirm: () => removeAccount.mutateAsync({ id: p.id })
		});
	}
</script>

<div class="flex flex-col gap-3">
	<p class="text-sm text-muted-foreground">
		People log in as one of these accounts. Grant a team and every member gets it.
	</p>
	{#if can.edit && list.length}
		<GrantLength bind:hours />
	{/if}

	{#if list.length > 6}
		<InputGroup.Root>
			<InputGroup.Addon><Search /></InputGroup.Addon>
			<InputGroup.Input
				bind:value={filter}
				placeholder="Filter accounts"
				aria-label="Filter accounts"
			/>
		</InputGroup.Root>
	{/if}

	{#if accounts.isLoading}
		<Skeleton class="h-24 w-full rounded-xl" />
		<Skeleton class="h-24 w-full rounded-xl" />
	{:else if list.length === 0}
		<Empty.Root class="border border-dashed">
			<Empty.Header>
				<Empty.Media variant="icon"><KeyRound /></Empty.Media>
				<Empty.Title>No login accounts yet</Empty.Title>
				<Empty.Description>
					{manual
						? 'Run nk sync on the host to report its accounts'
						: 'The daemon reports the host accounts when it connects'}{can.edit
						? ', or add one below.'
						: '.'}
				</Empty.Description>
			</Empty.Header>
		</Empty.Root>
	{:else}
		{#each shown as account (account.id)}
			{@const grants = granted(account)}
			<div class="overflow-hidden rounded-xl border bg-card">
				<div class="flex items-center gap-3 py-2.5 pr-2 pl-3">
					<div
						class={[
							'flex size-8 shrink-0 items-center justify-center rounded-lg',
							grants.length ? 'bg-primary/10 text-primary' : 'bg-muted text-muted-foreground'
						]}
					>
						<SquareTerminal class="size-4" />
					</div>
					<div class="min-w-0 flex-1">
						<p class="flex items-center gap-1.5">
							<span class="truncate font-mono text-sm font-medium">{account.username}</span>
							{#if account.username === 'root'}
								<Badge variant="warning">Superuser</Badge>
							{/if}
							{#if !account.seenAt}
								<Tooltip.Root>
									<Tooltip.Trigger>
										{#snippet child({ props })}
											<span {...props}><Badge variant="muted">Not on the host</Badge></span>
										{/snippet}
									</Tooltip.Trigger>
									<Tooltip.Content>
										The host has not reported this account. Grants on it open nothing until it
										exists there.
									</Tooltip.Content>
								</Tooltip.Root>
							{/if}
						</p>
						<p class="truncate text-xs text-muted-foreground">{summary(grants)}</p>
					</div>
					{#if can.edit}
						<SubjectPicker
							selected={grants.map((g) => g.id)}
							onToggle={(s, grant) => toggle(account, s, grant)}
							label="Grant"
							variant="ghost"
						/>
						<DropdownMenu.Root>
							<DropdownMenu.Trigger>
								{#snippet child({ props })}
									<Button {...props} variant="ghost" size="icon-sm" aria-label="More">
										<Ellipsis />
									</Button>
								{/snippet}
							</DropdownMenu.Trigger>
							<DropdownMenu.Content align="end">
								<DropdownMenu.Group>
									<DropdownMenu.Item
										variant="destructive"
										onclick={() => askRemoveAccount(account)}
									>
										<Trash2 />
										Remove login account
									</DropdownMenu.Item>
								</DropdownMenu.Group>
							</DropdownMenu.Content>
						</DropdownMenu.Root>
					{/if}
				</div>
				{#if grants.length}
					<div class="flex flex-wrap gap-1.5 border-t bg-muted/40 px-3 py-2.5">
						{#each grants as grant (grant.id)}
							<SubjectChip
								{grant}
								onRemove={can.edit ? () => toggle(account, grant, false) : undefined}
							/>
						{/each}
					</div>
				{/if}
			</div>
		{:else}
			<p class="py-4 text-center text-sm text-muted-foreground">No account matches.</p>
		{/each}
	{/if}

	{#if can.edit}
		<form
			onsubmit={(e) => {
				e.preventDefault();
				void submitAccount();
			}}
		>
			<InputGroup.Root>
				<InputGroup.Addon><KeyRound /></InputGroup.Addon>
				<InputGroup.Input
					bind:value={newAccount}
					placeholder="Add a login account, e.g. deploy"
					aria-label="New login account"
				/>
				<InputGroup.Addon align="inline-end">
					<!-- Never disabled, InputGroup greys out the whole field for a disabled child. -->
					<InputGroup.Button type="submit" variant="secondary" size="xs">
						<Plus data-icon="inline-start" />
						Add
					</InputGroup.Button>
				</InputGroup.Addon>
			</InputGroup.Root>
		</form>
	{/if}
</div>
