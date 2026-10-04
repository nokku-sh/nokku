<script lang="ts">
	import { plural } from '#lib/api/bulk.js';
	import { target as targetApi } from '#lib/api/targets.svelte.js';
	import { kindLabels } from '#lib/components/access/subjects.svelte.js';
	import Chip from '#lib/components/blocks/Chip.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import { SubjectKind } from '#lib/gen/nokku/v1/principal_pb.js';
	import type { GetAccessGraphResponse } from '#lib/gen/nokku/v1/target_pb.js';
	import { useSheet } from '#lib/hooks/index.js';
	import { tagLabel, type Focus } from './graph.js';

	interface Props {
		focus: Focus;
		overview: GetAccessGraphResponse;
		/** The graph narrowed to the focus, unset while it loads. */
		graph?: GetAccessGraphResponse;
		onclear: () => void;
	}

	let { focus, overview, graph, onclear }: Props = $props();

	const MAX_NAMES = 4;

	const sheet = useSheet();
	const targetQuery = targetApi.get(() => (focus.kind === 'target' ? focus.id : undefined));
	const hasSheet = $derived(focus.kind !== 'account' && focus.kind !== 'tag');
	const subject = $derived(
		(graph?.subjects ?? overview.subjects).find((s) => s.id === focus.id) ??
			overview.subjects.find((s) => s.id === focus.id)
	);

	const name = $derived.by(() => {
		switch (focus.kind) {
			case 'account':
				return focus.id;
			case 'tag':
				return tagLabel(focus.id);
			case 'target':
				return targetQuery.data?.name ?? (targetQuery.isError ? 'Not found' : '');
			default:
				return subject?.name || subject?.email || (graph ? 'Not found' : '');
		}
	});

	const names = (all: string[]) =>
		all.length > MAX_NAMES
			? `${all.slice(0, MAX_NAMES).join(', ')} and ${all.length - MAX_NAMES} more`
			: all.join(', ');

	const summary = $derived.by(() => {
		if (!graph) return '';
		const accounts = names(graph.accounts.map((a) => a.username).sort());
		// The subjects holding a grant, as "2 teams, 3 members".
		const holders = [SubjectKind.TEAM, SubjectKind.USER, SubjectKind.SERVICE_ACCOUNT]
			.map((kind) => {
				const n = graph.subjects.filter((s) => s.kind === kind && s.targets > 0).length;
				return n ? plural(n, kindLabels[kind].one, kindLabels[kind].many) : '';
			})
			.filter(Boolean)
			.join(', ');

		switch (focus.kind) {
			case 'account':
				return holders
					? `Granted on ${plural(graph.targets, 'target')} to ${holders}`
					: 'Granted to nobody';
			case 'tag': {
				const total = overview.tags.find((t) => t.tag === focus.id)?.total ?? 0;
				return `${graph.targets} of ${plural(total, 'target')} have grants`;
			}
			case 'target':
				return holders ? `${holders} can log in as ${accounts}` : 'Nobody can log in yet';
			default: {
				if (graph.targets === 0) return "Can't log in anywhere yet";
				const teams =
					focus.kind === 'user'
						? graph.subjects.filter((s) => s.kind === SubjectKind.TEAM).map((s) => s.name)
						: [];
				const through = teams.length ? `, through ${names(teams)}` : '';
				return `Can log in to ${plural(graph.targets, 'target')} as ${accounts}${through}`;
			}
		}
	});

	const listHref = $derived(
		focus.kind === 'account'
			? `/infrastructure/targets?principals=${encodeURIComponent(focus.id)}`
			: focus.kind === 'tag' && focus.id
				? `/infrastructure/targets?tags=${encodeURIComponent(focus.id)}`
				: undefined
	);
</script>

<div class="flex min-w-0 flex-1 flex-wrap items-center gap-x-3 gap-y-1.5 sm:flex-nowrap">
	<Chip
		label={name || 'Loading'}
		mono={focus.kind === 'account'}
		onRemove={onclear}
		removeLabel="Clear focus"
		class="shrink-0"
	/>
	{#if graph}
		<p
			class="order-last min-w-0 basis-full text-sm text-muted-foreground sm:order-0 sm:flex-1 sm:basis-0 sm:truncate"
			title={summary}
		>
			{summary}
		</p>
	{:else}
		<div class="flex-1"><Spinner /></div>
	{/if}
	{#if hasSheet && name !== 'Not found'}
		<Button
			variant="outline"
			size="sm"
			class="ml-auto shrink-0"
			onclick={() => sheet.show(focus.id, 'access')}
		>
			Manage access
		</Button>
	{:else if listHref}
		<Button variant="outline" size="sm" class="ml-auto shrink-0" href={listHref}
			>View targets</Button
		>
	{/if}
</div>
