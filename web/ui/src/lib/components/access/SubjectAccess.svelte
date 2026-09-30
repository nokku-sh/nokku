<script lang="ts">
	import { principal as principalApi } from '$lib/api/principals.svelte';
	import { target as targetApi } from '$lib/api/targets.svelte';
	import { team as teamApi } from '$lib/api/team.svelte';
	import { Button } from '$lib/components/ui/button';
	import * as Empty from '$lib/components/ui/empty';
	import * as InputGroup from '$lib/components/ui/input-group';
	import { Skeleton } from '$lib/components/ui/skeleton';
	import Chip from '$lib/components/blocks/Chip.svelte';
	import { SubjectKind, type Principal } from '$lib/gen/nokku/v1/principal_pb';
	import type { Target } from '$lib/gen/nokku/v1/target_pb';
	import { Search, Server, ShieldOff, SquareTerminal, Users } from '@lucide/svelte';
	import { SvelteSet } from 'svelte/reactivity';
	import GrantPopover from './GrantPopover.svelte';
	import { kindLabels, subjectIds } from './subjects.svelte';

	interface Props {
		subjectId: string;
		kind: SubjectKind;
		name: string;
	}

	let { subjectId, kind, name }: Props = $props();

	const PAGE = 30;

	const access = targetApi.access(() => subjectId);
	const userTeams = teamApi.listForUser(() => (kind === SubjectKind.USER ? subjectId : undefined));
	const teamNames = $derived(new Map((userTeams.data ?? []).map((t) => [t.id, t.name])));
	const removeSubjects = principalApi.removeSubjects();
	const revoking = new SvelteSet<string>();

	type Grant = { principal: Principal; direct: boolean; via: string[] };

	function grants(t: Target): Grant[] {
		return t.principals
			.map((p) => ({
				principal: p,
				direct: subjectIds(p, kind).includes(subjectId),
				via: p.teamIds.filter((id) => teamNames.has(id)).map((id) => teamNames.get(id)!)
			}))
			.filter((g) => (g.direct || g.via.length) && !revoking.has(g.principal.id));
	}

	async function revoke(p: Principal) {
		revoking.add(p.id);
		try {
			await removeSubjects.mutateAsync({ id: p.id, subjectIds: [subjectId], kind });
		} finally {
			revoking.delete(p.id);
		}
	}

	let filter = $state('');
	let showAll = $state(false);
	const targets = $derived(access.data?.targets ?? []);
	const filtered = $derived(
		filter
			? targets.filter((t) => t.name.toLowerCase().includes(filter.trim().toLowerCase()))
			: targets
	);
	const shown = $derived(showAll ? filtered : filtered.slice(0, PAGE));
	const accountCount = $derived(targets.reduce((n, t) => n + grants(t).length, 0));

	function summary(list: Grant[]) {
		const direct = list.filter((g) => g.direct).length;
		const inherited = list.length - direct;
		return [direct && `${direct} direct`, inherited && `${inherited} through a team`]
			.filter(Boolean)
			.join(' · ');
	}
</script>

<div class="flex flex-col gap-3">
	<div class="flex items-start justify-between gap-3">
		<p class="text-sm text-muted-foreground">
			{#if targets.length}
				{name} can log in to <span class="font-medium text-foreground">{targets.length}</span>
				{targets.length === 1 ? 'target' : 'targets'} with
				<span class="font-medium text-foreground">{accountCount}</span>
				{accountCount === 1 ? 'login account' : 'login accounts'}.
			{:else if !access.isLoading}
				{name} can't log in anywhere yet.
			{/if}
			{#if kind === SubjectKind.TEAM}
				Every member gets this access.
			{/if}
		</p>
		<GrantPopover {subjectId} {kind} />
	</div>

	{#if targets.length > 6}
		<InputGroup.Root>
			<InputGroup.Addon><Search /></InputGroup.Addon>
			<InputGroup.Input
				bind:value={filter}
				placeholder="Filter targets"
				aria-label="Filter targets"
			/>
		</InputGroup.Root>
	{/if}

	{#if access.isLoading}
		<Skeleton class="h-20 w-full rounded-xl" />
		<Skeleton class="h-20 w-full rounded-xl" />
	{:else if targets.length === 0}
		<Empty.Root class="border border-dashed">
			<Empty.Header>
				<Empty.Media variant="icon"><ShieldOff /></Empty.Media>
				<Empty.Title>No access yet</Empty.Title>
				<Empty.Description>
					Grant this {kindLabels[kind].one} a login account on a target to let them in.
				</Empty.Description>
			</Empty.Header>
		</Empty.Root>
	{:else}
		{#each shown as t (t.id)}
			{@const list = grants(t)}
			<div class="overflow-hidden rounded-xl border bg-card">
				<div class="flex items-center gap-3 py-2.5 pr-2 pl-3">
					<div
						class="flex size-8 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground"
					>
						<Server class="size-4" />
					</div>
					<div class="min-w-0 flex-1">
						<a
							href={`/infrastructure/targets?id=${t.id}&tab=access`}
							class="block truncate text-sm font-medium hover:underline"
						>
							{t.name}
						</a>
						<p class="truncate text-xs text-muted-foreground">
							{summary(list) || t.description}
						</p>
					</div>
					<GrantPopover {subjectId} {kind} targetId={t.id} label="Edit" variant="ghost" />
				</div>
				<div class="flex flex-wrap gap-1.5 border-t bg-muted/40 px-3 py-2.5">
					{#each list as g (g.principal.id)}
						<Chip
							label={g.principal.username}
							mono
							muted={!g.direct}
							title={g.direct ? undefined : `Through ${g.via.join(', ')}`}
							onRemove={g.direct ? () => revoke(g.principal) : undefined}
							removeLabel={`Revoke ${g.principal.username}`}
						>
							{#snippet leading()}
								<SquareTerminal class="ml-2 size-3 text-muted-foreground" />
							{/snippet}
							{#snippet trailing()}
								{#if !g.direct}<Users class="size-3" />{/if}
							{/snippet}
						</Chip>
					{/each}
				</div>
			</div>
		{:else}
			<p class="py-4 text-center text-sm text-muted-foreground">No target matches.</p>
		{/each}
		{#if filtered.length > shown.length}
			<Button variant="ghost" size="sm" onclick={() => (showAll = true)}>
				Show all {filtered.length} targets
			</Button>
		{/if}
		{#if kind === SubjectKind.USER && targets.some((t) => grants(t).some((g) => !g.direct))}
			<p class="flex items-center gap-1.5 text-xs text-muted-foreground">
				<Users class="size-3" /> Dashed accounts come from a team. Change them on the team.
			</p>
		{/if}
	{/if}
</div>
