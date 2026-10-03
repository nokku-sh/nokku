<script lang="ts">
	import * as Empty from '#lib/components/ui/empty/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import { VectorSquare } from '@lucide/svelte';
	import { target } from '#lib/api/targets.svelte.js';
	import { team } from '#lib/api/team.svelte.js';
	import { workspace } from '#lib/api/workspaces.svelte.js';
	import {
		Background,
		BackgroundVariant,
		Controls,
		MiniMap,
		Position,
		SvelteFlow,
		type ColorMode,
		type Edge,
		type Node
	} from '@xyflow/svelte';
	import '@xyflow/svelte/dist/style.css';
	import dagre from 'dagre';
	import { mode } from 'mode-watcher';
	import TargetNode from './TargetNode.svelte';
	import PrincipalNode from './PrincipalNode.svelte';
	import SubjectNode from './SubjectNode.svelte';
	import type { Target } from '#lib/gen/nokku/v1/target_pb.js';
	import { principal } from '#lib/api/principals.svelte.js';
	import { serviceAccount } from '#lib/api/service_account.svelte.js';
	import Toolbar from './Toolbar.svelte';
	import { SubjectKind } from '#lib/gen/nokku/v1/principal_pb.js';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';

	const nodeTypes = {
		target: TargetNode,
		principal: PrincipalNode,
		subject: SubjectNode
	};

	let nodes = $state<Node[]>([]);
	let edges = $state<Edge[]>([]);
	let colorMode: ColorMode = $derived(mode.current === 'dark' ? 'dark' : 'light');
	let selectedTarget = $state<Target | undefined>(undefined);
	let selectedPrincipals = $state<string[]>([]);
	let selectedSubjectTypes = $state<string[]>([]);

	const targetData = target.list();
	const teamData = team.list();
	const serviceAccountData = serviceAccount.list();
	const members = workspace.listMembers();

	const principalData = principal.list(() => ({ targetId: selectedTarget?.id }));
	const targetPrincipals = $derived(principalData.data?.principals || []);
	const teams = $derived(teamData.data?.teams || []);
	const users = $derived(members.data?.members || []);
	const serviceAccounts = $derived(serviceAccountData.data?.serviceAccounts || []);

	function generateTreeForTarget(target: Target) {
		const nodes: Node[] = [];
		const edges: Edge[] = [];

		if (!selectedTarget) return { nodes, edges };
		nodes.push({
			id: target.id,
			type: 'target',
			data: { ...selectedTarget },
			position: { x: 0, y: 0 }
		});
		const activePrincipals = targetPrincipals.filter((p) => {
			if (selectedPrincipals.length === 0) return true;
			return selectedPrincipals.includes(p.username);
		});

		activePrincipals.forEach((p) => {
			const principalId = `principal-${p.id}`;
			nodes.push({
				id: principalId,
				type: 'principal',
				data: { ...p },
				position: { x: 0, y: 0 }
			});
			edges.push({
				id: `edge-${target.id}-${principalId}`,
				source: target.id,
				target: principalId,
				type: 'smoothstep',
				animated: true,
				style: 'stroke: var(--muted-foreground); stroke-width: 2px;'
			});
			if (selectedSubjectTypes.length === 0 || selectedSubjectTypes.includes('user')) {
				p.userIds?.forEach((userId: string) => {
					const user = users.find((u) => u.id === userId);
					if (!user) return;

					const subjectId = `subject-user-${userId}-${p.id}`;
					nodes.push({
						id: subjectId,
						type: 'subject',
						data: {
							...user,
							subjectType: SubjectKind.USER,
							principalId: p.id,
							principalUsername: p.username
						},
						position: { x: 0, y: 0 }
					});

					edges.push({
						id: `edge-${principalId}-${subjectId}`,
						source: principalId,
						target: subjectId,
						type: 'smoothstep',
						animated: true,
						style: 'stroke: var(--chart-1); stroke-width: 2px;'
					});
				});
			}
			if (selectedSubjectTypes.length === 0 || selectedSubjectTypes.includes('team')) {
				p.teamIds?.forEach((teamId: string) => {
					const t = teams.find((t) => t.id === teamId);
					if (!t) return;

					const subjectId = `subject-team-${teamId}-${p.id}`;
					nodes.push({
						id: subjectId,
						type: 'subject',
						data: {
							...t,
							subjectType: SubjectKind.TEAM,
							principalId: p.id,
							principalUsername: p.username
						},
						position: { x: 0, y: 0 }
					});

					edges.push({
						id: `edge-${principalId}-${subjectId}`,
						source: principalId,
						target: subjectId,
						type: 'smoothstep',
						animated: true,
						style: 'stroke: var(--chart-2); stroke-width: 2px;'
					});
				});
			}
			if (selectedSubjectTypes.length === 0 || selectedSubjectTypes.includes('service-account')) {
				p.serviceAccountIds?.forEach((serviceAccountId: string) => {
					const serviceAccount = serviceAccounts.find((sa) => sa.id === serviceAccountId);
					if (!serviceAccount) return;

					const subjectId = `subject-service-account-${serviceAccountId}-${p.id}`;
					nodes.push({
						id: subjectId,
						type: 'subject',
						data: {
							...serviceAccount,
							subjectType: SubjectKind.SERVICE_ACCOUNT,
							principalId: p.id,
							principalUsername: p.username
						},
						position: { x: 0, y: 0 }
					});

					edges.push({
						id: `edge-${principalId}-${subjectId}`,
						source: principalId,
						target: subjectId,
						type: 'smoothstep',
						animated: true,
						style: 'stroke: var(--chart-5); stroke-width: 2px;'
					});
				});
			}
		});

		return { nodes, edges };
	}

	function layoutTree(nodes: Node[], edges: Edge[]) {
		const dagreGraph = new dagre.graphlib.Graph();
		dagreGraph.setDefaultEdgeLabel(() => ({}));
		dagreGraph.setGraph({
			rankdir: 'TB',
			nodesep: 20,
			ranksep: 200
		});
		const getNodeDimensions = (type?: string) => {
			switch (type) {
				case 'target':
					return { width: 360, height: 220 }; // Matches w-[360px]
				case 'principal':
					return { width: 280, height: 180 }; // Matches w-[280px]
				case 'subject':
					return { width: 250, height: 100 }; // Matches w-[250px]
				default:
					return { width: 200, height: 150 };
			}
		};

		nodes.forEach((node) => {
			const { width, height } = getNodeDimensions(node.type);
			dagreGraph.setNode(node.id, { width, height });
		});

		edges.forEach((edge) => {
			dagreGraph.setEdge(edge.source, edge.target);
		});

		dagre.layout(dagreGraph);

		const layoutedNodes = nodes.map((node) => {
			const nodeWithPosition = dagreGraph.node(node.id);
			const { width, height } = getNodeDimensions(node.type);

			return {
				...node,
				targetPosition: Position.Top,
				sourcePosition: Position.Bottom,
				position: {
					x: nodeWithPosition.x - width / 2,
					y: nodeWithPosition.y - height / 2
				}
			};
		});

		return { nodes: layoutedNodes, edges };
	}

	$effect(() => {
		if (!selectedTarget || principalData.isLoading) {
			nodes = [];
			edges = [];
			return;
		}

		const { nodes: treeNodes, edges: treeEdges } = generateTreeForTarget(selectedTarget);
		const { nodes: layoutedNodes, edges: layoutedEdges } = layoutTree(treeNodes, treeEdges);

		nodes = layoutedNodes;
		edges = layoutedEdges;
	});
</script>

<PageHeader title="Topology" description="Who can reach which account on a target, as a graph" />

<Toolbar
	bind:selectedTarget
	bind:selectedPrincipals
	bind:selectedSubjectTypes
	{targetPrincipals}
	data={targetData.data?.targets}
/>

<div class="relative h-[70dvh] min-h-96 overflow-hidden rounded-xl border bg-card">
	{#if !selectedTarget}
		<Empty.Root class="absolute inset-0 z-10">
			<Empty.Header>
				<Empty.Media variant="icon"><VectorSquare /></Empty.Media>
				<Empty.Title>Pick a target</Empty.Title>
				<Empty.Description>
					See its login accounts and every person, team and service account that can use them.
				</Empty.Description>
			</Empty.Header>
		</Empty.Root>
	{:else if principalData.isLoading}
		<div class="absolute inset-0 z-10 flex items-center justify-center bg-card/80">
			<Spinner class="size-6 text-primary" />
		</div>
	{/if}
	{#key selectedTarget?.id}
		<SvelteFlow
			{nodeTypes}
			bind:nodes
			bind:edges
			{colorMode}
			nodesConnectable={false}
			nodesDraggable={true}
			fitView
		>
			<Background variant={BackgroundVariant.Dots} class="bg-background" />
			<MiniMap
				maskColor="color-mix(in oklch, var(--background) 85%, transparent)"
				nodeStrokeWidth={3}
			/>
			<Controls />
		</SvelteFlow>
	{/key}
</div>
