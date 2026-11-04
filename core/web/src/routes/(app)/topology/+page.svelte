<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { target } from '#lib/api/targets.svelte.js';
	import { team } from '#lib/api/team.svelte.js';
	import AccessReportMenu from '#lib/components/access/AccessReportMenu.svelte';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import UserSheet from '#lib/components/sheets/UserSheet.svelte';
	import ServiceAccountSheet from '#lib/components/sheets/ServiceAccountSheet.svelte';
	import TargetSheet from '#lib/components/sheets/TargetSheet.svelte';
	import TeamSheet from '#lib/components/sheets/TeamSheet.svelte';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import * as Tabs from '#lib/components/ui/tabs/index.js';
	import { Grid3x3, VectorSquare, Waypoints } from '@lucide/svelte';
	import {
		Background,
		BackgroundVariant,
		Controls,
		SvelteFlow,
		type ColorMode
	} from '@xyflow/svelte';
	import '@xyflow/svelte/dist/style.css';
	import { mode } from 'mode-watcher';
	import FocusSummary from './FocusSummary.svelte';
	import {
		buildGraph,
		drawEdges,
		filterOf,
		GRAPH_WIDTH,
		MAX_TARGETS,
		PAGE,
		parseFocus,
		type Actions,
		type Focus
	} from './graph.js';
	import LabelNode from './LabelNode.svelte';
	import Matrix from './Matrix.svelte';
	import RowNode from './RowNode.svelte';
	import Search from './Search.svelte';

	const nodeTypes = { row: RowNode, label: LabelNode };
	const MORE = 20;
	const PADDING = 24;

	// The matrix holds any number of people and tags, the graph reads best for one focus at a time.
	const view = $derived(page.url.searchParams.get('view') === 'matrix' ? 'matrix' : 'graph');
	function setView(next: string) {
		// Each view keeps its own filters, a switch starts clean.
		const url = new URL(page.url.pathname, page.url.origin);
		if (next === 'matrix') url.searchParams.set('view', 'matrix');
		void goto(url, { reset: false });
	}

	// The focus lives in the URL, so a view is shareable and Back steps through what was looked at.
	const focus = $derived(parseFocus(page.url.searchParams.get('focus')));
	function setFocus(next?: Focus) {
		const url = new URL(page.url.href);
		if (next) url.searchParams.set('focus', `${next.kind}:${next.id}`);
		else url.searchParams.delete('focus');
		void goto(url, { reset: false });
	}

	let hovered = $state<string>();
	let openTeam = $state<string>();
	let openTag = $state<string>();
	let shown = $state({ ...PAGE });
	let width = $state(0);

	const filter = $derived(focus && filterOf(focus));
	const overview = target.accessGraph(undefined, () => view === 'graph');
	const focusedQuery = target.accessGraph(
		() => filter,
		() => view === 'graph' && !!focus
	);
	// Without a focus the query shares the overview's cache entry.
	const focused = $derived(focus ? focusedQuery.data : undefined);
	const members = team.members(() => openTeam);
	const targets = target.accessGraphTargets(() => ({
		tag: openTag,
		filter,
		limit: shown.targets
	}));

	const actions: Actions = {
		focus: (next) => setFocus(focus?.kind === next.kind && focus.id === next.id ? undefined : next),
		toggleTeam: (id) => {
			openTeam = openTeam === id ? undefined : id;
			shown.members = PAGE.members;
		},
		toggleTag: (tag) => {
			openTag = openTag === tag ? undefined : tag;
			shown.targets = PAGE.targets;
		},
		more: (section) => {
			const next = shown[section] + MORE;
			shown[section] = section === 'targets' ? Math.min(next, MAX_TARGETS) : next;
		}
	};

	const layout = $derived(
		overview.data &&
			buildGraph(
				{
					overview: overview.data,
					focused,
					focus,
					shown,
					openTeam,
					members: members.data,
					openTag,
					targets: targets.data?.targets,
					targetTotal: targets.data?.total
				},
				actions
			)
	);
	const edges = $derived(layout ? drawEdges(layout.links, !!focused, hovered) : []);

	const colorMode: ColorMode = $derived(mode.current === 'dark' ? 'dark' : 'light');
	const zoom = $derived(Math.min(1, Math.max(0.5, (width - PADDING * 2) / GRAPH_WIDTH)));
</script>

<PageHeader title="Topology" description="Who can log in where, across the whole workspace">
	<AccessReportMenu />
</PageHeader>

<Tabs.Root value={view} onValueChange={setView}>
	<Tabs.List aria-label="View">
		<Tabs.Trigger value="graph"><Waypoints />Graph</Tabs.Trigger>
		<Tabs.Trigger value="matrix"><Grid3x3 />Matrix</Tabs.Trigger>
	</Tabs.List>
</Tabs.Root>

{#if view === 'matrix'}
	<Matrix />
{:else}
	<div class="flex flex-col gap-3 sm:flex-row sm:items-center">
		<Search
			accounts={overview.data?.accounts.map((a) => a.username) ?? []}
			tags={overview.data?.tags.map((t) => t.tag) ?? []}
			onpick={(next, tag) => {
				setFocus(next);
				if (tag !== undefined && tag !== openTag) actions.toggleTag(tag);
			}}
		/>
		{#if focus && overview.data}
			<FocusSummary {focus} overview={overview.data} graph={focused} onclear={() => setFocus()} />
		{:else}
			<p class="text-sm text-muted-foreground">
				Pick a row to trace its access. A line is as thick as the servers it covers.
			</p>
		{/if}
	</div>

	<div
		bind:clientWidth={width}
		class="canvas relative min-h-112 flex-1 overflow-hidden rounded-xl border bg-card"
	>
		{#if overview.isLoading}
			<div class="absolute inset-0 flex items-center justify-center">
				<Spinner class="size-6 text-primary" />
			</div>
		{:else if !layout || overview.data?.grants.length === 0}
			<Empty.Root class="absolute inset-0">
				<Empty.Header>
					<Empty.Media variant="icon"><VectorSquare /></Empty.Media>
					<Empty.Title>No access yet</Empty.Title>
					<Empty.Description>
						Grant a person, team or service account a login account on a server and it shows up
						here.
					</Empty.Description>
				</Empty.Header>
			</Empty.Root>
		{:else if width}
			<SvelteFlow
				nodes={layout.nodes}
				{edges}
				{nodeTypes}
				{colorMode}
				initialViewport={{
					x: Math.max(PADDING, (width - GRAPH_WIDTH * zoom) / 2),
					y: PADDING,
					zoom
				}}
				minZoom={0.3}
				maxZoom={1.5}
				panOnScroll
				zoomOnDoubleClick={false}
				nodesDraggable={false}
				nodesConnectable={false}
				nodesFocusable={false}
				edgesFocusable={false}
				elementsSelectable={false}
				onnodepointerenter={({ node }) => (hovered = node.id)}
				onnodepointerleave={() => (hovered = undefined)}
				onpaneclick={() => setFocus()}
			>
				<Background variant={BackgroundVariant.Dots} class="bg-background" />
				<Controls showLock={false} />
			</SvelteFlow>
		{/if}
	</div>
{/if}

{#if focus?.kind === 'team'}
	<TeamSheet />
{:else if focus?.kind === 'user'}
	<UserSheet />
{:else if focus?.kind === 'service-account'}
	<ServiceAccountSheet />
{:else if focus?.kind === 'target'}
	<TargetSheet />
{/if}

<style>
	.canvas :global(.svelte-flow__edge-path) {
		transition:
			opacity 150ms,
			stroke 150ms;
	}
</style>
