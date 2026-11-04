<script lang="ts">
	import { page } from '$app/state';
	import { plural } from '#lib/api/bulk.js';
	import { target } from '#lib/api/targets.svelte.js';
	import SubjectAvatar from '#lib/components/access/SubjectAvatar.svelte';
	import { subjectLabel } from '#lib/components/access/grant.svelte.js';
	import { subjectHref, type Subject } from '#lib/components/access/subjects.svelte.js';
	import * as Empty from '#lib/components/ext/empty/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Command from '#lib/components/ui/command/index.js';
	import * as InputGroup from '#lib/components/ui/input-group/index.js';
	import * as Popover from '#lib/components/ui/popover/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import * as Table from '#lib/components/ui/table/index.js';
	import * as ToggleGroup from '#lib/components/ui/toggle-group/index.js';
	import type { AccessMatrixCell, AccessMatrixRow } from '#lib/gen/nokku/v1/target_pb.js';
	import { SubjectKind } from '#lib/gen/nokku/v1/target_account_pb.js';
	import { setFilters, usePagination } from '#lib/hooks/index.js';
	import { cn, formatTs, toDate } from '#lib/utils.js';
	import {
		Check,
		ChevronDown,
		ChevronLeft,
		ChevronRight,
		Columns3,
		Grid3x3,
		Search
	} from '@lucide/svelte';
	import { Debounced, useDebounce } from 'runed';
	import { SvelteSet } from 'svelte/reactivity';
	import { tagLabel } from './graph.js';
	import TeamMemberRows from './TeamMemberRows.svelte';
	import WhySheet from './WhySheet.svelte';

	const STALE_MS = 30 * 86_400_000;
	const MAX_COLUMNS = 20;
	// A tag can't hold a comma, and this stands for the servers without one.
	const UNTAGGED = '(untagged)';

	const kinds = [
		{ value: 'all', label: 'Everyone' },
		{ value: 'team', label: 'Teams', kind: SubjectKind.TEAM },
		{ value: 'user', label: 'People', kind: SubjectKind.USER },
		{ value: 'service-account', label: 'Service accounts', kind: SubjectKind.SERVICE_ACCOUNT }
	];

	const pager = usePagination();
	const params = $derived(page.url.searchParams);
	const kindParam = $derived(params.get('kind') ?? 'all');
	const picked = $derived(
		params
			.get('tags')
			?.split(',')
			.filter(Boolean)
			.map((t) => (t === UNTAGGED ? '' : t)) ?? []
	);
	// What is typed stays local, the URL follows a beat later. A late navigation then can't eat a letter.
	let typed = $state(page.url.searchParams.get('q') ?? '');
	const search = new Debounced(() => typed.trim(), 300);
	const writeQuery = useDebounce((q: string) => setFilters({ q: q || undefined }), 300);

	const matrix = target.accessMatrix(() => ({
		query: search.current || undefined,
		kind: kinds.find((k) => k.value === kindParam)?.kind,
		tags: picked,
		...pager.args
	}));
	const columns = $derived(matrix.data?.columns ?? []);
	const rows = $derived(matrix.data?.rows ?? []);
	const total = $derived(matrix.data?.total ?? 0);
	const pageCount = $derived(Math.max(1, Math.ceil(total / pager.pageSize)));
	const now = Date.now();

	let pickerOpen = $state(false);
	// The URL is ahead of the columns while the next page loads.
	const shown = $derived(picked.length ? picked : columns.map((c) => c.tag));
	function toggleTag(tag: string) {
		const next = shown.includes(tag) ? shown.filter((t) => t !== tag) : [...shown, tag];
		if (!next.length || next.length > MAX_COLUMNS) return;
		setFilters({ tags: next.map((t) => t || UNTAGGED).join(',') || undefined });
	}

	const subjectOf = (r: AccessMatrixRow): Subject => ({
		id: r.subjectId,
		kind: r.kind,
		name: r.name,
		detail: r.email
	});
	const rowDetail = (r: AccessMatrixRow) =>
		r.kind === SubjectKind.TEAM
			? plural(r.memberCount, 'member')
			: r.kind === SubjectKind.USER
				? r.email
				: 'service account';
	const cellOf = (r: AccessMatrixRow, tag: string) => r.cells.find((c) => c.tag === tag);
	const stale = (c: AccessMatrixCell) =>
		!c.lastUsedAt || now - toDate(c.lastUsedAt).getTime() > STALE_MS;
	let why = $state<{ row: AccessMatrixRow; cell: AccessMatrixCell; total: number }>();

	const expanded = new SvelteSet<string>();
	function toggleTeam(id: string) {
		if (!expanded.delete(id)) expanded.add(id);
	}
</script>

<div class="flex flex-col gap-3">
	<div class="flex flex-wrap items-center gap-2">
		<InputGroup.Root class="w-full sm:w-72">
			<InputGroup.Addon><Search /></InputGroup.Addon>
			<InputGroup.Input
				bind:value={typed}
				oninput={() => writeQuery(typed.trim())}
				placeholder="Find a person, team or service account"
				aria-label="Find a row"
			/>
		</InputGroup.Root>
		<ToggleGroup.Root
			type="single"
			variant="outline"
			size="sm"
			class="flex-wrap"
			aria-label="Show"
			value={kindParam}
			onValueChange={(v) => v && setFilters({ kind: v === 'all' ? undefined : v })}
		>
			{#each kinds as k (k.value)}
				<ToggleGroup.Item value={k.value}>{k.label}</ToggleGroup.Item>
			{/each}
		</ToggleGroup.Root>
		<Popover.Root bind:open={pickerOpen}>
			<Popover.Trigger>
				{#snippet child({ props })}
					<Button {...props} variant="outline" size="sm" class="sm:ml-auto">
						<Columns3 data-icon="inline-start" />
						Tags {shown.length}/{matrix.data?.tags.length ?? 0}
					</Button>
				{/snippet}
			</Popover.Trigger>
			<Popover.Content align="end" class="w-72 p-0">
				<Command.Root>
					<Command.Input placeholder="Find a tag..." />
					<Command.List>
						<Command.Empty>No tag matches.</Command.Empty>
						<Command.Group heading={`Columns, up to ${MAX_COLUMNS}`}>
							{#each matrix.data?.tags ?? [] as t (t.tag)}
								{@const on = shown.includes(t.tag)}
								<Command.Item
									value={tagLabel(t.tag)}
									disabled={on ? shown.length === 1 : shown.length >= MAX_COLUMNS}
									onSelect={() => toggleTag(t.tag)}
								>
									<Check class={on ? 'text-primary' : 'invisible'} />
									<span class={cn('flex-1 truncate', t.tag ? 'font-mono' : 'italic')}>
										{tagLabel(t.tag)}
									</span>
									<span class="text-xs text-muted-foreground tabular-nums">{t.total}</span>
								</Command.Item>
							{/each}
						</Command.Group>
					</Command.List>
				</Command.Root>
				{#if picked.length}
					<div class="border-t p-1">
						<Button
							variant="ghost"
							size="sm"
							class="w-full"
							onclick={() => {
								setFilters({ tags: undefined });
								pickerOpen = false;
							}}
						>
							Back to the biggest tags
						</Button>
					</div>
				{/if}
			</Popover.Content>
		</Popover.Root>
	</div>

	{#if matrix.isLoading}
		<Skeleton class="h-96 w-full rounded-xl" />
	{:else if !rows.length && pager.pageIndex > 0}
		<Empty.Root class="rounded-xl border border-dashed">
			<Empty.Header>
				<Empty.Media variant="icon"><Grid3x3 /></Empty.Media>
				<Empty.Title>Nothing on this page</Empty.Title>
				<Empty.Description>The list got shorter than this page.</Empty.Description>
			</Empty.Header>
			<Empty.Content>
				<Button variant="outline" onclick={() => pager.set(0)}>Back to the first page</Button>
			</Empty.Content>
		</Empty.Root>
	{:else if !rows.length}
		<Empty.Root class="rounded-xl border border-dashed">
			<Empty.Header>
				<Empty.Media variant="icon"><Grid3x3 /></Empty.Media>
				<Empty.Title
					>{search.current || kindParam !== 'all' ? 'Nobody matches' : 'No access yet'}</Empty.Title
				>
				<Empty.Description>
					{search.current || kindParam !== 'all'
						? 'Try another name or show everyone.'
						: 'Grant a person, team or service account a login account and a row shows up here.'}
				</Empty.Description>
			</Empty.Header>
		</Empty.Root>
	{:else}
		<!-- One scroll box for both axes, so the header and the first column stay put. The table's own wrapper would
		     scroll sideways on its own and take the sticky header with it. -->
		<div
			class="max-h-[70vh] overflow-auto rounded-xl border bg-card [&_[data-slot=table-container]]:overflow-visible"
		>
			<Table.Root class="border-separate border-spacing-0">
				<Table.Header>
					<Table.Row class="hover:bg-transparent">
						<Table.Head class="sticky top-0 left-0 z-20 w-40 border-b bg-card sm:w-64">
							Who, by tag
						</Table.Head>
						{#each columns as c (c.tag)}
							<Table.Head class="sticky top-0 z-10 border-b bg-card text-center">
								<span class="flex flex-col items-center leading-tight">
									<span class={c.tag ? 'font-mono' : 'italic'}>{tagLabel(c.tag)}</span>
									<span class="text-2xs font-normal text-muted-foreground">
										{plural(c.total, 'server')}
									</span>
								</span>
							</Table.Head>
						{/each}
					</Table.Row>
				</Table.Header>
				<Table.Body>
					{#each rows as r (r.subjectId)}
						{@const subject = subjectOf(r)}
						<Table.Row class="hover:bg-transparent has-aria-expanded:bg-transparent">
							<Table.Head
								scope="row"
								class="sticky left-0 z-10 max-w-40 border-b bg-card py-2 font-normal sm:max-w-64"
							>
								<div class="flex min-w-0 items-center gap-1">
									<a
										href={`${subjectHref(r.kind, r.subjectId)}&tab=access`}
										class="flex min-w-0 flex-1 items-center gap-2 rounded-sm hover:underline"
									>
										<SubjectAvatar {subject} class="size-6" />
										<span class="flex min-w-0 flex-col">
											<span class="truncate text-sm font-medium">{subjectLabel(subject)}</span>
											<span class="truncate text-xs text-muted-foreground">
												{rowDetail(r)} · {plural(r.targets, 'server')}
											</span>
										</span>
									</a>
									{#if r.kind === SubjectKind.TEAM && r.memberCount > 0}
										<Button
											variant="ghost"
											size="icon-xs"
											aria-label={`Members of ${subjectLabel(subject)}`}
											aria-expanded={expanded.has(r.subjectId)}
											onclick={() => toggleTeam(r.subjectId)}
										>
											<ChevronDown
												class={cn(
													'transition-transform',
													expanded.has(r.subjectId) && 'rotate-180'
												)}
											/>
										</Button>
									{/if}
								</div>
							</Table.Head>
							{#each columns as col (col.tag)}
								{@const cell = cellOf(r, col.tag)}
								<Table.Cell class="border-b p-1 text-center">
									{#if cell}
										<button
											type="button"
											class="flex w-full min-w-24 flex-col items-center rounded-md border border-transparent bg-primary/10 px-2 py-1 text-xs hover:border-primary focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
											aria-label={`Why ${subjectLabel(subject)} reaches ${tagLabel(col.tag)}${stale(cell) ? ', unused for 30 days' : ''}`}
											onclick={() => (why = { row: r, cell, total: col.total })}
										>
											<span class="max-w-32 truncate font-mono">{cell.usernames.join(', ')}</span>
											<span class="text-2xs text-muted-foreground tabular-nums">
												{cell.targets}/{col.total}
												{#if cell.expiresAt}
													· <span class="text-warning"
														>ends {formatTs(cell.expiresAt, 'relative-short')}</span
													>
												{/if}
												{#if stale(cell)}
													· unused
												{/if}
											</span>
										</button>
									{:else}
										<span class="text-muted-foreground/50" aria-label="No access">·</span>
									{/if}
								</Table.Cell>
							{/each}
						</Table.Row>
						{#if expanded.has(r.subjectId)}
							<TeamMemberRows row={r} tags={columns.map((c) => c.tag)} />
						{/if}
					{/each}
				</Table.Body>
			</Table.Root>
		</div>

		<div class="flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground">
			<p>
				Someone in a team shows under the team, open it to see who. A server with two tags shows in
				both.
			</p>
			<div class="flex items-center gap-2">
				<span class="tabular-nums">
					{pager.pageIndex * pager.pageSize + 1}-{Math.min(
						total,
						(pager.pageIndex + 1) * pager.pageSize
					)}
					of {total}
				</span>
				<Button
					variant="outline"
					size="icon-sm"
					aria-label="Previous page"
					disabled={pager.pageIndex === 0}
					onclick={() => pager.set(pager.pageIndex - 1)}
				>
					<ChevronLeft />
				</Button>
				<Button
					variant="outline"
					size="icon-sm"
					aria-label="Next page"
					disabled={pager.pageIndex + 1 >= pageCount}
					onclick={() => pager.set(pager.pageIndex + 1)}
				>
					<ChevronRight />
				</Button>
			</div>
		</div>
	{/if}
</div>

{#if why}
	<WhySheet
		{...why}
		subject={subjectOf(why.row)}
		stale={stale(why.cell)}
		onClose={() => (why = undefined)}
	/>
{/if}
