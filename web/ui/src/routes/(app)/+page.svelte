<script lang="ts">
	import { daemon } from '$lib/api/daemons.svelte';
	import { ca } from '$lib/api/certificates.svelte';
	import { target } from '$lib/api/targets.svelte';
	import { workspace } from '$lib/api/workspaces.svelte';
	import JoinModal from '$lib/components/modals/JoinModal.svelte';
	import WorkspaceModal from '$lib/components/modals/WorkspaceModal.svelte';
	import * as Empty from '$lib/components/ui/empty';
	import * as Item from '$lib/components/ui/item';
	import CopyButton from '$lib/components/ui/copy-button/copy-button.svelte';
	import { Badge } from '$lib/components/ui/badge';
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import * as ToggleGroup from '$lib/components/ui/toggle-group';
	import {
		Bot,
		Server,
		Layers2,
		TriangleAlert,
		Users,
		IdCard,
		ArrowRight,
		Activity,
		Shield,
		Search,
		X,
		Key,
		Dot,
		ChevronLeft,
		ChevronRight,
		CircleCheckBig
	} from '@lucide/svelte';
	import { user } from '$lib/api/user.svelte';
	import { DaemonStatus } from '$lib/gen/nokku/v1/daemon_pb';
	import { toDate } from '$lib/utils';
	import { goto } from '$app/navigation';
	import { workspaceID } from '$lib/store.svelte';

	let openWorkspaceModal = $state(false);

	const currentUser = $derived(user.self());
	const currentMember = $derived(workspace.getMember(currentUser.data?.id));
	const members = $derived(workspace.listMembers());
	const targets = $derived(target.list());
	const daemons = $derived(daemon.list());
	const cas = $derived(ca.list());

	const isAdmin = $derived(
		currentMember.data?.roleName === 'editor' || currentMember.data?.roleName === 'owner'
	);

	const access = $derived(target.access(currentUser.data?.id));
	const accessTargets = $derived(access.data?.targets);
	const accessAgents = $derived(access.data?.daemons);

	const stats = $derived.by(() => {
		const memberCount = members.data?.total || 0;
		const targetCount = targets.data?.total || 0;
		const agentCount = daemons.data?.total || 0;
		const caCount = cas.data?.length || 0;
		const onlineAgents = daemons.data?.daemons.filter((a) => a.online).length || 0;
		return { memberCount, targetCount, agentCount, caCount, onlineAgents };
	});

	const pendingAgents = $derived(
		daemons.data?.daemons.filter((a) => a.status === DaemonStatus.PENDING).length || 0
	);

	const expiringCAs = $derived(
		cas.data?.filter((c) =>
			c.notBefore ? toDate(c.notAfter).getTime() < Date.now() + 7 * 24 * 60 * 60 * 1000 : false
		).length || 0
	);

	const greeting = $derived.by(() => {
		const hr = new Date().getHours();
		if (hr < 12) return 'Good morning';
		if (hr < 17) return 'Good afternoon';
		return 'Good evening';
	});

	let searchQuery = $state('');
	let statusFilter = $state<'all' | 'online' | 'offline'>('all');
	let pageIdx = $state(0);
	const pageSize = 25;

	const filteredTargets = $derived.by(() => {
		if (!accessTargets) return [];
		return accessTargets
			.filter((t) => {
				const q = searchQuery.toLowerCase();
				const matchesSearch =
					t.name.toLowerCase().includes(q) ||
					t.metadata?.hostname?.toLowerCase().includes(q) ||
					t.endpoints?.some((e) => e.toLowerCase().includes(q)) ||
					t.principals?.some((p) => p.username.toLowerCase().includes(q));

				const isOnline = accessAgents?.some((a) => a.id === t.daemonId && a.online) || false;
				const matchesStatus =
					statusFilter === 'all' ||
					(statusFilter === 'online' && isOnline) ||
					(statusFilter === 'offline' && !isOnline);

				return matchesSearch && matchesStatus;
			})
			.sort((a, b) => {
				const aOnline =
					accessAgents?.some((aAgent) => aAgent.id === a.daemonId && aAgent.online) || false;
				const bOnline =
					accessAgents?.some((bAgent) => bAgent.id === b.daemonId && bAgent.online) || false;
				if (aOnline !== bOnline) return aOnline ? -1 : 1;
				return a.name.localeCompare(b.name);
			});
	});

	const totalPages = $derived(Math.max(1, Math.ceil(filteredTargets.length / pageSize)));
	const pageTargets = $derived(filteredTargets.slice(pageIdx * pageSize, (pageIdx + 1) * pageSize));

	function resetFilters() {
		searchQuery = '';
		statusFilter = 'all';
		pageIdx = 0;
	}
</script>

<WorkspaceModal bind:open={openWorkspaceModal} />
<JoinModal />

<div class="container mx-auto max-w-7xl space-y-8 p-6 lg:p-8">
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
				<Button onclick={() => (openWorkspaceModal = true)}>Create Workspace</Button>
			</Empty.Content>
		</Empty.Root>
	{:else}
		<!-- Welcome Hero Banner -->
		<div
			class="relative overflow-hidden rounded-2xl border border-primary/10 bg-linear-to-br from-primary/5 via-background to-muted/40 p-6 shadow-sm lg:p-8"
		>
			<div class="absolute -top-16 -right-16 size-48 rounded-full bg-primary/10 blur-3xl"></div>
			<div
				class="absolute -bottom-16 -left-16 size-48 rounded-full bg-emerald-500/5 blur-3xl"
			></div>

			<div class="relative z-10 flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
				<div class="space-y-4">
					<div
						class="inline-flex items-center gap-1.5 rounded-full bg-primary/10 px-3 py-1 text-xs font-semibold text-primary"
					>
						<Activity class="size-3" />
						Launchpad
					</div>
					<h1 class="text-3xl font-extrabold tracking-tight md:text-4xl">
						{greeting},
						<span class="bg-linear-to-r from-primary to-emerald-500 bg-clip-text text-transparent"
							>{currentUser.data?.name || currentUser.data?.username || 'Operator'}</span
						>
					</h1>
					<p class="max-w-xl text-sm text-muted-foreground md:text-base">
						Manage trust, sign SSH certificates, and launch secure terminal connections to your
						fleet instantly.
					</p>

					{#if isAdmin}
						<div
							class="flex flex-wrap items-center gap-x-2 gap-y-2 border-t border-primary/10 pt-3 text-xs text-muted-foreground select-none"
						>
							<Badge variant="secondary" class="text-[10px] font-bold">
								<Server class="text-muted-foreground/75" />
								{stats.targetCount}
								<span class="text-muted-foreground">targets</span>
								{#if stats.onlineAgents > 0}
									<Dot class="size-4 text-muted-foreground/30" />
									<span class="text-muted-foreground">{stats.onlineAgents} online</span>
								{/if}
							</Badge>
							<Dot class="size-4 text-muted-foreground/30" />
							<Badge variant="secondary" class="text-[10px] font-bold">
								<IdCard class="text-muted-foreground/75" />
								{stats.caCount}
								<span class="text-muted-foreground">CAs </span>
								{#if expiringCAs > 0}
									<Dot class="size-4 text-muted-foreground/30" />
									<span class="text-muted-foreground"> {expiringCAs} expiring</span>
									<TriangleAlert class="ml-1 size-4 text-amber-500" />
								{/if}
							</Badge>
							<Dot class="size-4 text-muted-foreground/30" />
							<Badge variant="secondary" class="text-[10px] font-bold">
								<Users class="text-muted-foreground/75" />
								{stats.memberCount}
								<span class="text-muted-foreground">members</span>
							</Badge>
						</div>
					{/if}
				</div>
			</div>
		</div>

		<!-- System Health & Onboarding -->
		<div class="grid gap-6 md:grid-cols-3">
			{#if isAdmin}
				<div class="space-y-4 md:col-span-2">
					<div class="flex items-center justify-between">
						<h2 class="flex items-center gap-2 text-lg font-semibold tracking-tight">
							<Activity class="size-4 text-primary" />
							System Health
						</h2>
						{#if pendingAgents === 0 && expiringCAs === 0 && stats.caCount > 0 && stats.targetCount > 0}
							<Badge
								variant="outline"
								class="gap-1.5 border-emerald-500/30 bg-emerald-500/5 text-emerald-500"
							>
								<span class="relative flex h-1.5 w-1.5">
									<span class="relative inline-flex h-1.5 w-1.5 rounded-full bg-emerald-500"></span>
								</span>
								All Systems Normal
							</Badge>
						{/if}
					</div>

					<div class="grid gap-3 sm:grid-cols-2">
						{#if stats.caCount === 0}
							<Item.Root
								variant="outline"
								class="min-h-40 flex-col items-stretch justify-between border-destructive/20 bg-destructive/5 p-4"
							>
								<div class="flex w-full items-start gap-3">
									<Item.Media class="shrink-0 rounded-md bg-destructive/10 p-1.5 text-destructive">
										<Key class="size-4" />
									</Item.Media>
									<Item.Content class="space-y-0.5">
										<Item.Title class="text-sm font-semibold">No active CA configured</Item.Title>
										<Item.Description class="text-xs">
											Workspace needs a Certificate Authority to sign SSH keys. Configure one to
											start.
										</Item.Description>
									</Item.Content>
								</div>
								<Item.Actions class="mt-2 w-full">
									<Button size="sm" variant="destructive" class="w-full" href="/certificates">
										Configure CA
										<ArrowRight data-icon="inline-end" />
									</Button>
								</Item.Actions>
							</Item.Root>
						{:else if expiringCAs > 0}
							<Item.Root
								variant="outline"
								class="min-h-[145px] flex-col items-stretch justify-between border-amber-500/20 bg-amber-500/5 p-4"
							>
								<div class="flex w-full items-start gap-3">
									<Item.Media class="shrink-0 rounded-md bg-amber-500/10 p-1.5 text-amber-500">
										<TriangleAlert class="size-4" />
									</Item.Media>
									<Item.Content class="space-y-0.5">
										<Item.Title class="text-sm font-semibold">CA Certificate Expiring</Item.Title>
										<Item.Description class="text-xs">
											{expiringCAs} trust root certificate(s) expire within 7 days.
										</Item.Description>
									</Item.Content>
								</div>
								<Item.Actions class="mt-2 w-full">
									<Button
										size="sm"
										variant="outline"
										class="w-full border-amber-500/30 bg-amber-500/5 text-amber-600 hover:bg-amber-500/10 dark:text-amber-500"
										href="/certificates"
									>
										Renew Trust Roots
										<ArrowRight data-icon="inline-end" />
									</Button>
								</Item.Actions>
							</Item.Root>
						{:else}
							<Item.Root
								variant="outline"
								class="min-h-[145px] flex-col items-stretch justify-between p-4"
							>
								<div class="flex w-full items-start gap-3">
									<Item.Media class="shrink-0 rounded-md bg-emerald-500/10 p-1.5 text-emerald-500">
										<CircleCheckBig class="size-4" />
									</Item.Media>
									<Item.Content class="space-y-0.5">
										<Item.Title class="text-sm font-semibold">Certificate Authorities</Item.Title>
										<Item.Description class="text-xs">
											{stats.caCount} CAs active. Ephemeral SSH certificate signing is healthy.
										</Item.Description>
									</Item.Content>
								</div>
								<Item.Actions class="mt-2 w-full">
									<Button
										size="sm"
										variant="secondary"
										class="w-full text-xs text-muted-foreground hover:text-foreground"
										href="/certificates"
									>
										Manage Certificates
									</Button>
								</Item.Actions>
							</Item.Root>
						{/if}

						{#if stats.targetCount === 0}
							<Item.Root
								variant="outline"
								class="min-h-[145px] flex-col items-stretch justify-between border-destructive/20 bg-destructive/5 p-4"
							>
								<div class="flex w-full items-start gap-3">
									<Item.Media class="shrink-0 rounded-md bg-destructive/10 p-1.5 text-destructive">
										<Server class="size-4" />
									</Item.Media>
									<Item.Content class="space-y-0.5">
										<Item.Title class="text-sm font-semibold">No servers enrolled</Item.Title>
										<Item.Description class="text-xs">
											Enroll target servers to establish secure reverse tunnels and access them.
										</Item.Description>
									</Item.Content>
								</div>
								<Item.Actions class="mt-2 w-full">
									<Button
										size="sm"
										variant="destructive"
										class="w-full"
										href="/infrastructure?tab=targets"
									>
										Enroll Server
										<ArrowRight data-icon="inline-end" />
									</Button>
								</Item.Actions>
							</Item.Root>
						{:else if pendingAgents > 0}
							<Item.Root
								variant="outline"
								class="min-h-[145px] flex-col items-stretch justify-between border-blue-500/20 bg-blue-500/5 p-4"
							>
								<div class="flex w-full items-start gap-3">
									<Item.Media class="shrink-0 rounded-md bg-blue-500/10 p-1.5 text-blue-500">
										<Bot class="size-4" />
									</Item.Media>
									<Item.Content class="space-y-0.5">
										<Item.Title class="text-sm font-semibold">Pending Daemon Approvals</Item.Title>
										<Item.Description class="text-xs">
											{pendingAgents} target daemon(s) are awaiting approval to join the workspace.
										</Item.Description>
									</Item.Content>
								</div>
								<Item.Actions class="mt-2 w-full">
									<Button
										size="sm"
										variant="outline"
										class="w-full border-blue-500/30 bg-blue-500/5 text-blue-600 hover:bg-blue-500/10 dark:text-blue-500"
										href="/infrastructure?tab=daemons"
									>
										Review & Approve
										<ArrowRight data-icon="inline-end" />
									</Button>
								</Item.Actions>
							</Item.Root>
						{:else}
							<Item.Root
								variant="outline"
								class="min-h-[145px] flex-col items-stretch justify-between p-4"
							>
								<div class="flex w-full items-start gap-3">
									<Item.Media class="shrink-0 rounded-md bg-emerald-500/10 p-1.5 text-emerald-500">
										<CircleCheckBig class="size-4" />
									</Item.Media>
									<Item.Content class="space-y-0.5">
										<Item.Title class="text-sm font-semibold">Server Infrastructure</Item.Title>
										<Item.Description class="text-xs">
											{stats.targetCount} targets registered. {stats.onlineAgents} daemons online.
										</Item.Description>
									</Item.Content>
								</div>
								<Item.Actions class="mt-2 w-full">
									<Button
										size="sm"
										variant="ghost"
										class="w-full text-xs text-muted-foreground hover:text-foreground"
										href="/infrastructure"
									>
										Manage Servers
									</Button>
								</Item.Actions>
							</Item.Root>
						{/if}
					</div>
				</div>
			{:else}
				<div class="space-y-4 md:col-span-2">
					<h2 class="flex items-center gap-2 text-lg font-semibold tracking-tight">
						<Shield class="size-4 text-emerald-500" />
						Security Posture
					</h2>
					<div class="grid gap-3 sm:grid-cols-2">
						<Item.Root variant="outline" class="min-h-[145px] flex-1 items-start p-4">
							<Item.Media class="shrink-0 rounded-md bg-emerald-500/10 p-1.5 text-emerald-500">
								<CircleCheckBig class="size-4" />
							</Item.Media>
							<Item.Content class="space-y-0.5">
								<Item.Title class="text-sm font-semibold">Secure SSH Access</Item.Title>
								<Item.Description class="text-xs">
									Connections use secure, ephemeral SSH certificates signed by the workspace CA. No
									static keys are kept on servers.
								</Item.Description>
							</Item.Content>
						</Item.Root>
						<Item.Root
							variant="outline"
							class="min-h-[145px] flex-1 flex-col items-stretch justify-between p-4"
						>
							<div class="flex w-full items-start gap-3">
								<Item.Media class="shrink-0 rounded-md bg-primary/10 p-1.5 text-primary">
									<Key class="size-4" />
								</Item.Media>
								<Item.Content class="space-y-0.5">
									<Item.Title class="text-sm font-semibold">Passkey Credentials</Item.Title>
									<Item.Description class="text-xs">
										Register a Passkey (TouchID, FaceID, YubiKey) for passwordless multi-factor
										authentication.
									</Item.Description>
								</Item.Content>
							</div>
							<Item.Actions class="mt-2 w-full">
								<Button size="sm" variant="outline" class="w-full" href="/profile/security">
									Configure Passkeys
									<ArrowRight data-icon="inline-end" />
								</Button>
							</Item.Actions>
						</Item.Root>
					</div>
				</div>
			{/if}

			<!-- Getting Started Tips -->
			<div class="space-y-4">
				<h2 class="flex items-center gap-2 text-lg font-semibold tracking-tight">
					<Activity class="size-4 text-muted-foreground" />
					Getting Started
				</h2>
				<div class="space-y-3.5 rounded-xl border bg-card p-4">
					<div class="flex gap-3">
						<div
							class="flex size-5 shrink-0 items-center justify-center rounded-full bg-muted font-mono text-[10px] font-bold"
						>
							1
						</div>
						<div class="space-y-0.5">
							<p class="text-xs font-semibold">Install the CLI</p>
							<p class="text-[11px] text-muted-foreground">
								Download the helper binary for your OS. It automatically signs and manages keys.
							</p>
						</div>
					</div>
					<div class="flex gap-3">
						<div
							class="flex size-5 shrink-0 items-center justify-center rounded-full bg-muted font-mono text-[10px] font-bold"
						>
							2
						</div>
						<div class="space-y-0.5">
							<p class="text-xs font-semibold">Authenticate</p>
							<p
								class="inline-block rounded bg-black/5 p-1 font-mono text-[11px] text-muted-foreground dark:bg-black/30"
							>
								$ nk login
							</p>
						</div>
					</div>
					<div class="flex gap-3">
						<div
							class="flex size-5 shrink-0 items-center justify-center rounded-full bg-muted font-mono text-[10px] font-bold"
						>
							3
						</div>
						<div class="space-y-0.5">
							<p class="text-xs font-semibold">Connect via SSH</p>
							<p
								class="inline-block rounded bg-black/5 p-1 font-mono text-[11px] text-muted-foreground dark:bg-black/30"
							>
								$ ssh username@server
							</p>
						</div>
					</div>
				</div>
			</div>
		</div>

		<!-- Server Fleet -->
		<div class="space-y-6">
			<div class="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
				<div class="space-y-1">
					<h2 class="text-xl font-bold tracking-tight">Your Servers</h2>
					<p class="text-sm text-muted-foreground">
						{#if access.isPending}
							Loading...
						{:else}
							Access to <span class="font-semibold text-foreground">{filteredTargets.length}</span>
							server{filteredTargets.length !== 1 ? 's' : ''}
							{#if filteredTargets.length !== (accessTargets?.length || 0)}
								<span class="text-muted-foreground/60">
									(filtered from {accessTargets?.length || 0})
								</span>
							{/if}
						{/if}
					</p>
				</div>

				<div class="flex items-center gap-3">
					<div class="relative w-full sm:w-64">
						<Search class="absolute top-2.5 left-2.5 size-4 text-muted-foreground" />
						<Input
							type="text"
							placeholder="Search by name, host..."
							class="h-9 pl-9"
							bind:value={searchQuery}
						/>
						{#if searchQuery}
							<Button
								variant="ghost"
								size="icon"
								class="absolute top-1.5 right-1.5 size-6 text-muted-foreground hover:text-foreground"
								onclick={() => (searchQuery = '')}
							>
								<X class="size-3.5" />
							</Button>
						{/if}
					</div>

					<ToggleGroup.Root
						type="single"
						variant="outline"
						value={statusFilter}
						onValueChange={(v) => {
							if (v) {
								statusFilter = v as 'all' | 'online' | 'offline';
								pageIdx = 0;
							}
						}}
					>
						<ToggleGroup.Item value="all" class="text-xs">All</ToggleGroup.Item>
						<ToggleGroup.Item value="online" class="text-xs">Online</ToggleGroup.Item>
						<ToggleGroup.Item value="offline" class="text-xs">Offline</ToggleGroup.Item>
					</ToggleGroup.Root>
				</div>
			</div>

			<!-- Targets Table -->
			{#if access.isPending}
				<div class="overflow-hidden rounded-xl border bg-card">
					<div class="space-y-3 p-4">
						{#each Array(6) as _, i (i)}
							<div class="flex items-center gap-4">
								<div class="h-5 w-48 animate-pulse rounded bg-muted"></div>
								<div class="h-5 w-16 animate-pulse rounded bg-muted"></div>
								<div class="h-5 w-32 animate-pulse rounded bg-muted"></div>
							</div>
						{/each}
					</div>
				</div>
			{:else if filteredTargets.length === 0}
				<Empty.Root class="rounded-xl border bg-card py-16 shadow-sm">
					<Empty.Header>
						<Empty.Media variant="icon">
							<Server />
						</Empty.Media>
						<Empty.Title>
							{searchQuery || statusFilter !== 'all' ? 'No servers found' : 'No servers available'}
						</Empty.Title>
						<Empty.Description>
							{#if searchQuery || statusFilter !== 'all'}
								Try adjusting your search or filters.
							{:else}
								You don't have access to any servers in this workspace yet.
							{/if}
						</Empty.Description>
					</Empty.Header>
					{#if searchQuery || statusFilter !== 'all'}
						<Empty.Content>
							<Button variant="outline" size="sm" onclick={resetFilters}>Reset Filters</Button>
						</Empty.Content>
					{/if}
				</Empty.Root>
			{:else}
				<div class="overflow-hidden rounded-xl border bg-card">
					<div class="overflow-x-auto">
						<table class="w-full border-collapse text-left text-sm">
							<thead>
								<tr class="border-b bg-muted/30 font-medium text-muted-foreground select-none">
									<th class="w-12 px-4 py-3"></th>
									<th class="px-4 py-3">Server</th>
									<th class="hidden px-4 py-3 sm:table-cell">Tags</th>
									<th class="px-4 py-3">Principals</th>
								</tr>
							</thead>
							<tbody class="divide-y">
								{#each pageTargets as targetItem (targetItem.id)}
									{@const agentItem = accessAgents?.find((a) => a.id === targetItem.daemonId)}
									{@const isOnline = agentItem?.online || false}
									{@const principalsList = targetItem.principals || []}
									{@const visiblePrincipals = principalsList.slice(0, 3)}
									{@const overflowCount = principalsList.length - 3}

									<tr
										class="group transition-colors hover:bg-muted/15 {!isOnline
											? 'opacity-60'
											: ''}"
									>
										<!-- Status indicator -->
										<td class="px-4 py-3">
											<div class="flex items-center justify-center">
												<span
													class="size-2 rounded-full {isOnline
														? 'bg-emerald-500'
														: 'bg-muted-foreground/30'}"
													title={isOnline ? 'Online' : 'Offline'}
												></span>
											</div>
										</td>

										<!-- Server name + hostname -->
										<td class="px-4 py-3">
											<div class="flex max-w-55 flex-col">
												<div class="flex items-center gap-2">
													<span class="truncate text-sm font-semibold text-foreground">
														{targetItem.name}
													</span>
													<span
														class="shrink-0 text-[10px] font-medium {isOnline
															? 'text-emerald-500'
															: 'text-muted-foreground'}"
													>
														{isOnline ? 'online' : 'offline'}
													</span>
												</div>
												{#if targetItem.metadata?.hostname}
													<span class="truncate text-xs text-muted-foreground">
														{targetItem.metadata.hostname}
													</span>
												{/if}
											</div>
										</td>

										<!-- Tags -->
										<td class="hidden px-4 py-3 sm:table-cell">
											{#if targetItem.tags && targetItem.tags.length > 0}
												<div class="flex flex-wrap gap-1">
													{#each targetItem.tags as tag (tag)}
														<Badge
															variant="secondary"
															class="px-1.5 py-0 text-[9px] leading-none font-medium"
														>
															{tag}
														</Badge>
													{/each}
												</div>
											{:else}
												<span class="text-xs text-muted-foreground/40 italic">—</span>
											{/if}
										</td>

										<!-- Principals -->
										<td class="px-4 py-3">
											{#if principalsList.length === 0}
												<span class="text-xs text-muted-foreground/40 italic">none</span>
											{:else}
												<div class="flex flex-wrap items-center gap-1">
													{#each visiblePrincipals as p (p.id || p.username)}
														<CopyButton text={`${p.username}@${targetItem.name}`} icon={false}>
															<Badge variant="secondary" class="font-mono text-[10px]">
																{p.username}
															</Badge>
														</CopyButton>
													{/each}
													{#if overflowCount > 0}
														<span class="text-[10px] text-muted-foreground">
															+{overflowCount} more
														</span>
													{/if}
												</div>
											{/if}
										</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>

					<!-- Pagination -->
					<div class="flex items-center justify-between border-t bg-muted/10 px-4 py-3">
						<span class="text-xs text-muted-foreground">
							{filteredTargets.length > 0
								? `${pageIdx * pageSize + 1}–${Math.min((pageIdx + 1) * pageSize, filteredTargets.length)} of ${filteredTargets.length}`
								: '0 results'}
						</span>
						<div class="flex items-center gap-2">
							<Button
								variant="outline"
								size="sm"
								class="h-8 w-8 p-0"
								disabled={pageIdx === 0}
								onclick={() => (pageIdx = Math.max(0, pageIdx - 1))}
							>
								<ChevronLeft class="size-4" />
							</Button>
							<span class="min-w-16 text-center text-xs text-muted-foreground">
								Page {pageIdx + 1} of {totalPages}
							</span>
							<Button
								variant="outline"
								size="sm"
								class="h-8 w-8 p-0"
								disabled={pageIdx >= totalPages - 1}
								onclick={() => (pageIdx = Math.min(totalPages - 1, pageIdx + 1))}
							>
								<ChevronRight class="size-4" />
							</Button>
						</div>
					</div>
				</div>
			{/if}
		</div>
	{/if}
</div>
