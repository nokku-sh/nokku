<script lang="ts">
	import {
		Bot,
		IdCard,
		Key,
		Layers2,
		Server,
		Terminal,
		TriangleAlert,
		Users
	} from '@lucide/svelte';
	import { ca } from '$lib/api/certificates.svelte';
	import { daemon } from '$lib/api/daemons.svelte';
	import { recordings } from '$lib/api/recordings.svelte';
	import { target } from '$lib/api/targets.svelte';
	import { user } from '$lib/api/user.svelte';
	import { workspace } from '$lib/api/workspaces.svelte';
	import JoinModal from '$lib/components/modals/JoinModal.svelte';
	import WorkspaceModal from '$lib/components/modals/WorkspaceModal.svelte';
	import { Button } from '$lib/components/ui/button';
	import * as Empty from '$lib/components/ui/empty';
	import {
		ActivityFeed,
		HealthAlerts,
		OnboardingChecklist,
		type HealthIssue,
		ServersTable,
		SessionFeed,
		type SetupStep,
		SectionHeading,
		StatCard
	} from '$lib/components/dashboard';
	import { DaemonStatus } from '$lib/gen/nokku/v1/daemon_pb';
	import { WorkspaceSchema } from '$lib/gen/nokku/v1/workspace_pb';
	import { createEntityModalState } from '$lib/hooks';
	import { toDate } from '$lib/utils';
	import { workspaceID } from '$lib/store.svelte';
	import { atLeast } from '$lib/roles';

	const workspaceModal = createEntityModalState(WorkspaceSchema);

	const currentUser = user.self();
	const currentWorkspace = workspace.get();
	const isAdmin = $derived(atLeast(currentWorkspace.data?.role, 'editor'));

	const access = target.access(() => currentUser.data?.id);
	const accessTargets = $derived(access.data?.targets ?? []);
	const accessAgents = $derived(access.data?.daemons ?? []);

	const daemons = daemon.list(() => ({ limit: 100 }));
	const cas = ca.list();
	const members = workspace.listMembers(() => ({ limit: 1 }));
	const recs = recordings.list();

	const onlineAgents = $derived(accessAgents.filter((a) => a.online));
	const reachableTargets = $derived(
		accessTargets.filter((t) => accessAgents.some((a) => a.id === t.daemonId && a.online))
	);
	const pendingDaemons = $derived(
		daemons.data?.daemons.filter((d) => d.status === DaemonStatus.PENDING).length ?? 0
	);
	const offlineDaemons = $derived(daemons.data?.daemons.filter((d) => !d.online).length ?? 0);
	const totalDaemons = $derived(daemons.data?.total ?? accessAgents.length);

	const caCount = $derived(cas.data?.length ?? 0);
	const expiringCAs = $derived(
		cas.data?.filter(
			(c) => c.notAfter && toDate(c.notAfter).getTime() < Date.now() + 7 * 24 * 60 * 60 * 1000
		).length ?? 0
	);
	const acceptedDaemons = $derived(
		daemons.data?.daemons.filter((d) => d.status === DaemonStatus.ACCEPTED).length ?? 0
	);
	const hasRecordings = $derived((recs.data?.total ?? 0) > 0);

	const greeting = $derived.by(() => {
		const hr = new Date().getHours();
		if (hr < 12) return 'Good morning';
		if (hr < 17) return 'Good afternoon';
		return 'Good evening';
	});
	const displayName = $derived(currentUser.data?.name || 'Operator');

	const healthIssues = $derived.by(() => {
		const issues: HealthIssue[] = [];
		if (isAdmin) {
			if (caCount === 0) {
				issues.push({
					id: 'no-ca',
					tone: 'danger',
					icon: Key,
					title: 'No certificate authority configured',
					description: 'The workspace needs a CA before SSH certificates can be signed.',
					ctaLabel: 'Configure CA',
					href: '/certificates'
				});
			} else if (expiringCAs > 0) {
				issues.push({
					id: 'ca-expiring',
					tone: 'warn',
					icon: TriangleAlert,
					title: 'Certificate authority expiring',
					description: `${expiringCAs} trust root${expiringCAs !== 1 ? 's' : ''} expire within 7 days.`,
					ctaLabel: 'Review CAs',
					href: '/certificates'
				});
			}
			if (pendingDaemons > 0) {
				issues.push({
					id: 'pending-daemons',
					tone: 'info',
					icon: Bot,
					title: 'Daemon approvals waiting',
					description: `${pendingDaemons} daemon${pendingDaemons !== 1 ? 's' : ''} awaiting approval to join the workspace.`,
					ctaLabel: 'Review',
					href: '/infrastructure/daemons'
				});
			}
			if (offlineDaemons > 0 && totalDaemons > 0) {
				issues.push({
					id: 'offline-daemons',
					tone: 'warn',
					icon: Server,
					title: 'Daemons offline',
					description: `${offlineDaemons} of ${totalDaemons} daemon${totalDaemons !== 1 ? 's' : ''} not connected.`,
					ctaLabel: 'Inspect',
					href: '/infrastructure/daemons'
				});
			}
		}
		return issues;
	});

	const setupSteps = $derived.by(() => {
		const steps: SetupStep[] = [
			{
				id: 'ca',
				label: 'Create a certificate authority',
				done: caCount > 0,
				href: '/certificates'
			},
			{
				id: 'daemon',
				label: 'Enroll and approve a daemon',
				done: acceptedDaemons > 0,
				href: '/infrastructure/daemons'
			},
			{
				id: 'target',
				label: 'Register a target server',
				done: accessTargets.length > 0,
				href: '/infrastructure/targets'
			},
			{
				id: 'connect',
				label: 'Connect your first session',
				done: hasRecordings,
				href: '/sessions'
			}
		];
		return steps;
	});

	const hostNames = $derived.by(() => {
		const map: Record<string, string> = {};
		for (const t of accessTargets) {
			if (!map[t.daemonId]) {
				map[t.daemonId] = t.metadata?.hostname || t.name;
			}
		}
		for (const a of accessAgents) {
			if (!map[a.id]) map[a.id] = a.name;
		}
		return map;
	});

	const myPrincipals = $derived([
		...new Set(accessTargets.flatMap((t) => (t.principals ?? []).map((p) => p.username)))
	]);
</script>

<WorkspaceModal bind:open={workspaceModal.open} draft={workspaceModal.draft} />
<JoinModal />

<div class="container mx-auto max-w-7xl space-y-6 p-6 lg:p-8">
	{#if workspaceID.current === ''}
		<Empty.Root class="h-[60vh] rounded-xl border bg-card text-card-foreground shadow-sm">
			<Empty.Header>
				<Empty.Media variant="icon">
					<Layers2 />
				</Empty.Media>
				<Empty.Title>No Workspace Selected</Empty.Title>
				<Empty.Description>
					Select a workspace or create a new one to manage your SSH infrastructure.
				</Empty.Description>
			</Empty.Header>
			<Empty.Content>
				<Button onclick={() => workspaceModal.openNew()}>Create Workspace</Button>
			</Empty.Content>
		</Empty.Root>
	{:else}
		<header class="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
			<div class="space-y-1">
				<h1 class="text-2xl font-bold tracking-tight md:text-3xl">
					{greeting}, {displayName}
				</h1>
				<p class="flex items-center gap-2 text-sm text-muted-foreground">
					{#if isAdmin}
						{#if healthIssues.length === 0}
							<span class="relative flex size-2">
								<span
									class="absolute inline-flex h-full w-full animate-ping rounded-full bg-success opacity-75"
								></span>
								<span class="relative inline-flex size-2 rounded-full bg-success"></span>
							</span>
							All systems normal.
							{reachableTargets.length}
							of {accessTargets.length}
							servers reachable.
						{:else}
							<TriangleAlert class="size-3.5 text-warning" />
							{healthIssues.length}
							{healthIssues.length === 1 ? 'thing needs' : 'things need'} attention below.
						{/if}
					{:else if !access.isPending}
						You have access to {accessTargets.length}
						server{accessTargets.length !== 1 ? 's' : ''}.
					{/if}
				</p>
			</div>
			<div class="flex items-center gap-2">
				{#if isAdmin}
					<Button variant="outline" href="/infrastructure/daemons">
						<Server />
						Enroll server
					</Button>
				{/if}
				<Button href="/sessions">
					<Terminal />
					Connect
				</Button>
			</div>
		</header>

		{#if isAdmin && healthIssues.length > 0}
			<HealthAlerts items={healthIssues} />
		{/if}

		{#if isAdmin}
			<div class="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
				<StatCard
					label="Servers"
					value={accessTargets.length}
					sub="{reachableTargets.length} reachable now"
					icon={Server}
					href="/infrastructure/targets"
					loading={access.isPending}
				/>
				<StatCard
					label="Daemons"
					value="{onlineAgents.length}/{totalDaemons}"
					sub={pendingDaemons > 0 ? `${pendingDaemons} awaiting approval` : 'tunnel gateways'}
					icon={Bot}
					href="/infrastructure/daemons"
					tone={pendingDaemons > 0 ? 'warn' : 'default'}
					loading={!daemons.data}
				/>
				<StatCard
					label="Members"
					value={members.data?.total ?? 0}
					sub="with workspace access"
					icon={Users}
					href="/access/members"
					loading={members.isPending}
				/>
				<StatCard
					label="Authorities"
					value={caCount}
					sub={caCount === 0
						? 'none configured yet'
						: expiringCAs > 0
							? `${expiringCAs} expire within 7 days`
							: 'signing healthy'}
					icon={IdCard}
					href="/certificates"
					tone={caCount === 0 ? 'danger' : expiringCAs > 0 ? 'warn' : 'success'}
					loading={cas.isPending}
				/>
			</div>
		{/if}

		<div class="grid gap-6 lg:grid-cols-3">
			<section class="space-y-4 lg:col-span-2">
				<SectionHeading
					title="Your servers"
					description="Everything you can reach with ephemeral SSH certificates."
				/>
				<ServersTable />
			</section>

			<aside class="space-y-6">
				{#if isAdmin}
					<OnboardingChecklist steps={setupSteps} />
				{/if}
				<SessionFeed
					hosts={hostNames}
					principals={isAdmin ? undefined : myPrincipals}
					title={isAdmin ? 'Recent sessions' : 'Your sessions'}
				/>
				{#if isAdmin}
					<ActivityFeed />
				{/if}
			</aside>
		</div>
	{/if}
</div>
