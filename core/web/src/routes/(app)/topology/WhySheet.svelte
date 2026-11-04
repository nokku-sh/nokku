<script lang="ts">
	import { plural } from '#lib/api/bulk.js';
	import { targetAccount } from '#lib/api/target-accounts.svelte.js';
	import { target } from '#lib/api/targets.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import {
		MAX_SERVERS,
		openGrant,
		planRevoke,
		subjectLabel,
		useGrantWhere
	} from '#lib/components/access/grant.svelte.js';
	import SubjectAvatar from '#lib/components/access/SubjectAvatar.svelte';
	import { kindLabels, subjectHref, type Subject } from '#lib/components/access/subjects.svelte.js';
	import Chip from '#lib/components/blocks/Chip.svelte';
	import * as Alert from '#lib/components/ext/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Sheet from '#lib/components/ui/sheet/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import type { AccessMatrixCell, AccessMatrixRow } from '#lib/gen/nokku/v1/target_pb.js';
	import { SubjectKind } from '#lib/gen/nokku/v1/target_account_pb.js';
	import { IsMobile } from '#lib/hooks/index.js';
	import { cn, formatTs, listNames } from '#lib/utils.js';
	import { Clock, Server, UserMinus, UserPlus } from '@lucide/svelte';
	import { tagLabel } from './graph.js';

	interface Props {
		row: AccessMatrixRow;
		cell: AccessMatrixCell;
		subject: Subject;
		/** Every server with the tag. */
		total: number;
		/** Not used in 30 days. */
		stale: boolean;
		onClose: () => void;
	}

	let { row, cell, subject, total, stale, onClose }: Props = $props();

	const SERVERS = 50;
	const MISSING = 5;

	const can = user.can();
	const mobile = new IsMobile();

	const team = $derived(row.kind === SubjectKind.TEAM);
	const person = $derived(row.kind === SubjectKind.USER);
	const servers = target.accessGraphTargets(() => ({
		tag: cell.tag,
		filter: { subjectId: row.subjectId },
		limit: SERVERS
	}));
	const reached = $derived((servers.data?.targets ?? []).filter((t) => t.matched));
	const missing = $derived((servers.data?.targets ?? []).filter((t) => !t.matched));
	// Untagged servers go by name, which only works when all of them loaded.
	const complete = $derived(!!cell.tag || (!!servers.data && servers.data.total <= SERVERS));

	function change() {
		openGrant({
			subjects: [subject],
			// The untagged servers have no tag to grant on, they go by name.
			...(cell.tag ? { tags: [cell.tag] } : { servers: reached }),
			account: cell.usernames[0]
		});
	}

	let revoking = $state(false);
	const where = useGrantWhere(
		() => (cell.tag ? { ids: [], tags: [cell.tag] } : { ids: reached.map((t) => t.id), tags: [] }),
		() => revoking
	);
	const tooMany = $derived(!!where.data?.tooMany);
	const plan = $derived(
		where.data && !tooMany ? planRevoke(subject, where.data.servers) : undefined
	);
	const notes = $derived.by(() => {
		const otherTags = plan?.servers.filter((t) => t.tags.length > 1) ?? [];
		return [
			team &&
				'Every member loses it too, unless a grant of their own or another team gives it to them.',
			person && 'What their teams give them stays.',
			otherTags.length > 0 &&
				`${listNames(
					otherTags.map((t) => t.name),
					MISSING
				)} ${otherTags.length === 1 ? 'has' : 'have'} other tags too, so the access goes there as well.`
		].filter((n) => typeof n === 'string');
	});
	const revokeTitle = $derived.by(() => {
		if (tooMany) return `More than ${MAX_SERVERS} servers`;
		if (!plan) return 'Finding the grants...';
		if (!plan.calls.length) return 'Nothing left to revoke here.';
		return `Removes ${plural(plan.calls.length, 'grant')} on ${plural(plan.servers.length, 'server')}`;
	});

	let done = '';
	let calls = 0;
	const revoke = targetAccount.revoke((ok) =>
		ok === calls ? done : 'Part of the revoke went through, what is left stays in the sheet'
	);

	async function submit() {
		if (!plan?.calls.length) return;
		done = `Revoked ${subjectLabel(subject)} on ${plural(plan.servers.length, 'server')}`;
		calls = plan.calls.length;
		try {
			const { failures } = await revoke.mutateAsync(plan.calls);
			if (!failures.length) onClose();
		} catch {
			// The mutation already toasted it.
		}
	}
</script>

<!-- Mounted on open, so it lands on top. -->
<Sheet.Root open onOpenChange={(o) => !o && onClose()}>
	<Sheet.Content
		side={mobile.current ? 'bottom' : 'right'}
		class="w-full gap-0 p-0 data-[side=bottom]:max-h-[92dvh] data-[side=bottom]:rounded-t-2xl data-[side=right]:sm:max-w-md"
	>
		<Sheet.Header class="border-b px-5 pt-5 pb-4">
			<span class="spec-label">Why</span>
			<Sheet.Title class="flex items-center gap-2 text-lg">
				<SubjectAvatar {subject} class="size-6" />
				<a
					href={`${subjectHref(row.kind, row.subjectId)}&tab=access`}
					class="truncate rounded-sm hover:underline"
				>
					{subjectLabel(subject)}
				</a>
				<span class="text-muted-foreground">on</span>
				<span class={cell.tag ? 'font-mono' : 'italic'}>{tagLabel(cell.tag)}</span>
			</Sheet.Title>
			<Sheet.Description>
				{team
					? `Every member of the team gets this, ${plural(row.memberCount, 'person', 'people')} today.`
					: person
						? 'A grant of their own. Teams they are in can give them more.'
						: 'A grant of its own.'}
			</Sheet.Description>
		</Sheet.Header>

		<div class="flex min-h-0 flex-1 flex-col gap-5 overflow-y-auto px-5 py-5">
			<dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
				<dt class="text-muted-foreground">As</dt>
				<dd class="font-mono">{cell.usernames.join(', ')}</dd>
				<dt class="text-muted-foreground">Servers</dt>
				<dd>
					{#if cell.tag}
						{cell.targets} of the {total} tagged <span class="font-mono">{cell.tag}</span>
					{:else}
						{cell.targets} of the {total} without a tag
					{/if}
				</dd>
				<dt class="text-muted-foreground">Ends</dt>
				<dd>
					{cell.expiresAt
						? `${formatTs(cell.expiresAt, 'withTime')}, ${formatTs(cell.expiresAt, 'relative')}`
						: 'Never, it is for good'}
				</dd>
				<dt class="text-muted-foreground">Last used</dt>
				<dd>
					{cell.lastUsedAt
						? `${formatTs(cell.lastUsedAt, 'relative')}${team ? ', by a member' : ''}`
						: 'Never'}
				</dd>
			</dl>

			{#if stale}
				<Alert.Root variant="warning">
					<Clock />
					<Alert.Title>{cell.lastUsedAt ? 'Not used in 30 days' : 'Never used'}</Alert.Title>
					<Alert.Description>
						{cell.lastUsedAt
							? 'Nobody logged in here with it for a month.'
							: 'Nobody logged in here with it yet.'} In an access review, this is one to ask about.
					</Alert.Description>
				</Alert.Root>
			{/if}

			{#if revoking}
				<section
					aria-labelledby="why-revoke"
					class="flex flex-col gap-3 rounded-lg border border-destructive/30 bg-destructive/5 p-4"
				>
					<h3
						id="why-revoke"
						tabindex="-1"
						class="text-sm font-medium outline-none"
						{@attach (el) => el.focus()}
					>
						{revokeTitle}
					</h3>
					{#if tooMany}
						<p class="text-xs text-muted-foreground">
							The sheet revokes on up to {MAX_SERVERS} servers at a time for now. Open the {kindLabels[
								row.kind
							].one} and remove it per server.
						</p>
					{:else if !plan}
						<Skeleton class="h-12 w-full" />
					{:else if plan.calls.length}
						<ul class="flex flex-col gap-1.5 text-sm">
							{#each plan.accounts as a (a.username)}
								<li>
									<span class="font-mono">{a.username}</span>
									<span class="text-muted-foreground">
										on {listNames(
											a.servers.map((t) => t.name),
											MISSING
										)}
									</span>
								</li>
							{/each}
						</ul>
						{#if notes.length}
							<div class="flex flex-col gap-1 text-xs text-muted-foreground">
								{#each notes as note (note)}
									<p>{note}</p>
								{/each}
							</div>
						{/if}
					{/if}
				</section>
			{:else}
				<section aria-labelledby="why-servers" class="flex flex-col gap-2">
					<h3 id="why-servers" class="text-sm font-medium">
						Servers {team ? 'the team reaches' : 'they reach'}
					</h3>
					{#if person}
						<p class="text-xs text-muted-foreground">With what their teams give them too.</p>
					{/if}
					{#if servers.isLoading}
						<Skeleton class="h-16 w-full" />
					{:else}
						<div class="flex flex-wrap gap-1.5">
							{#each reached as t (t.id)}
								<Chip label={t.name} mono href={`/servers?id=${t.id}`}>
									{#snippet leading()}
										<Server class="ml-2 size-3 text-muted-foreground" />
									{/snippet}
								</Chip>
							{/each}
						</div>
						{#if missing.length}
							<p class="text-xs text-muted-foreground">
								Not on {listNames(
									missing.map((t) => t.name),
									MISSING
								)}.
							</p>
						{/if}
						{#if (servers.data?.total ?? 0) > SERVERS}
							<p class="text-xs text-muted-foreground">
								The first {SERVERS} of {servers.data?.total} servers with the tag.
							</p>
						{/if}
					{/if}
				</section>
			{/if}
		</div>

		{#if can.edit && complete}
			<Sheet.Footer
				class={cn(
					'flex-row gap-2 border-t px-5 py-3',
					revoking ? 'justify-end' : 'justify-between'
				)}
			>
				{#if revoking}
					<Button variant="outline" onclick={() => (revoking = false)}>Cancel</Button>
					<Button
						variant="destructive"
						onclick={submit}
						disabled={!plan?.calls.length || where.isFetching || revoke.isPending}
					>
						{#if revoke.isPending}<Spinner data-icon="inline-start" />{/if}
						Revoke
					</Button>
				{:else}
					<Button variant="destructive" onclick={() => (revoking = true)}>
						<UserMinus data-icon="inline-start" />
						Revoke
					</Button>
					<Button onclick={change}>
						<UserPlus data-icon="inline-start" />
						Change in the grant sheet
					</Button>
				{/if}
			</Sheet.Footer>
		{/if}
	</Sheet.Content>
</Sheet.Root>
