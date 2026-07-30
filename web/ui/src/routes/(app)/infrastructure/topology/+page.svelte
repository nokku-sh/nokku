<script lang="ts">
	import { target } from '$lib/api/targets.svelte';
	import { team } from '$lib/api/team.svelte';
	import { workspace } from '$lib/api/workspaces.svelte';
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
	import type { Target } from '$lib/gen/nokku/v1/target_pb';
	import { principal } from '$lib/api/principals.svelte';
	import { serviceAccount } from '$lib/api/service_account.svelte';
	import Toolbar from './Toolbar.svelte';
	import { PrincipalType } from '$lib/gen/nokku/v1/principal_pb';
	import { VectorSquare } from '@lucide/svelte';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import { SvelteSet } from 'svelte/reactivity';

	const nodeTypes = {
		target: TargetNode,
		principal: PrincipalNode,
		subject: SubjectNode
	};

	let nodes = $state<Node[]>([]);
	let edges = $state<Edge[]>([]);
	let colorMode: ColorMode = $derived(mode.current === 'dark' ? 'dark' : 'light');
	let selectedTarget = $state<Target | undefined>(undefined);
	let selectedPrincipals = $state(new SvelteSet<string>());
	let selectedSubjectTypes = $state(new SvelteSet<string>());

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

		// Add target node (root)
		nodes.push({
			id: target.id,
			type: 'target',
			data: { ...selectedTarget },
			position: { x: 0, y: 0 }
		});

		// Find all principals for this target
		const activePrincipals = targetPrincipals.filter((p) => {
			if (selectedPrincipals.size === 0) return true;
			return selectedPrincipals.has(p.username);
		});

		activePrincipals.forEach((p) => {
			// Add principal node
			const principalId = `principal-${p.id}`;
			nodes.push({
				id: principalId,
				type: 'principal',
				data: { ...p },
				position: { x: 0, y: 0 }
			});

			// Add edge from target to principal
			edges.push({
				id: `edge-${target.id}-${principalId}`,
				source: target.id,
				target: principalId,
				type: 'smoothstep',
				animated: true,
				style: 'stroke: rgb(168 85 247); stroke-width: 2px;'
			});

			// Add user nodes
			if (selectedSubjectTypes.size === 0 || selectedSubjectTypes.has('user')) {
				p.userIds?.forEach((userId: string) => {
					const user = users.find((u) => u.id === userId);
					if (!user) return;

					const subjectId = `subject-user-${userId}-${p.id}`;
					nodes.push({
						id: subjectId,
						type: 'subject',
						data: {
							...user,
							subjectType: PrincipalType.USER,
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
						style: 'stroke: rgb(59 130 246); stroke-width: 2px;'
					});
				});
			}

			// Add team nodes
			if (selectedSubjectTypes.size === 0 || selectedSubjectTypes.has('team')) {
				p.teamIds?.forEach((teamId: string) => {
					const t = teams.find((t) => t.id === teamId);
					if (!t) return;

					const subjectId = `subject-team-${teamId}-${p.id}`;
					nodes.push({
						id: subjectId,
						type: 'subject',
						data: {
							...t,
							subjectType: PrincipalType.TEAM,
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
						style: 'stroke: rgb(34 197 94); stroke-width: 2px;'
					});
				});
			}

			// Add service account nodes
			if (selectedSubjectTypes.size === 0 || selectedSubjectTypes.has('service-account')) {
				p.serviceAccountIds?.forEach((serviceAccountId: string) => {
					const serviceAccount = serviceAccounts.find((sa) => sa.id === serviceAccountId);
					if (!serviceAccount) return;

					const subjectId = `subject-service-account-${serviceAccountId}-${p.id}`;
					nodes.push({
						id: subjectId,
						type: 'subject',
						data: {
							...serviceAccount,
							subjectType: PrincipalType.SERVICE_ACCOUNT,
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
						style: 'stroke: rgb(168 85 247); stroke-width: 2px;'
					});
				});
			}
		});

		console.log('Topology target:', target.id, 'principals:', targetPrincipals);
		console.log(
			'Available subjects - users:',
			users.length,
			'teams:',
			teams.length,
			'SAs:',
			serviceAccounts.length
		);
		console.log('Generated nodes:', nodes);
		console.log('Generated edges:', edges);
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

		// Define node dimensions to match the actual component styling
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

<PageHeader
	icon={VectorSquare}
	title="Topology"
	description="View the infrastructure topology for your workspace"
/>

<div class="space-y-4">
	<Toolbar
		bind:selectedTarget
		bind:selectedPrincipals
		bind:selectedSubjectTypes
		{targetPrincipals}
		data={targetData.data?.targets}
	/>

	<div style:height="calc(90vh - 200px)" class="rounded-lg border border-border bg-muted/20">
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
					maskColor={colorMode === 'dark' ? 'rgb(15, 23, 42, 0.85)' : 'rgb(241, 245, 249, 0.85)'}
					nodeStrokeWidth={3}
				/>
				<Controls />
			</SvelteFlow>
		{/key}
	</div>
</div>
