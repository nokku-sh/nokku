<script lang="ts">
	import { page } from '$app/state';
	import { principal } from '$lib/api/principals.svelte';
	import { target } from '$lib/api/targets.svelte';
	import DeleteConfirmationModal from '$lib/components/modals/DeleteConfirmationModal.svelte';
	import Badge from '$lib/components/ui/badge/badge.svelte';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import * as Empty from '$lib/components/ui/empty';
	import { InputGroupVariants } from '$lib/components/ui/input-group';
	import { Switch } from '$lib/components/ui/switch';
	import * as Tooltip from '$lib/components/ui/tooltip';
	import { PrincipalType, type Principal } from '$lib/gen/nokku/v1/principal_pb';
	import type { Target } from '$lib/gen/nokku/v1/target_pb';
	import {
		ChevronLeft,
		CircleAlert,
		ServerIcon,
		ShieldCheck,
		ShieldX,
		Terminal,
		UserX,
		Users
	} from '@lucide/svelte';
	import { Debounced } from 'runed';

	// URL Params
	const subjectID = $derived(page.url.searchParams.get('id') || '');
	const subjectName = $derived(page.url.searchParams.get('name') || 'Unknown');
	const subjectType = $derived(Number(page.url.searchParams.get('type') || '0') as PrincipalType);

	// State
	let search = $state('');
	const debounced = new Debounced(() => search, 500);

	let pageIdx = $state(0);
	const limit = 10;

	// Queries
	const queryOpts = $derived({ limit, offset: pageIdx * limit, query: debounced.current });
	const targets = target.list(() => queryOpts);

	// Only query access if we have a subject ID
	const access = $derived(target.access(subjectID));

	// Mutations
	const addToPrincipal = principal.addSubjects();
	const removeFromPrincipal = principal.removeSubjects();
	const revokeAccess = principal.revokeSubject();

	let openRevokeAllModal = $state(false);
	let selectedTargetId = $state<string>('');
	// Optimistic per-principal assignment toggles (principalId -> desired assigned).
	// Lets a switch flip immediately while the mutation is in flight; the server
	// refetch (global connect-query invalidation) becomes the source of truth.
	let pendingAssign = $state(new Map<string, boolean>());
	let targetPrincipals = principal.list(() => ({ targetId: selectedTargetId }));

	const displayedTargets = $derived(targets.data?.targets || []);
	const selectedTarget = $derived(displayedTargets.find((t) => t.id === selectedTargetId) || null);

	const accessibleTargetIds = $derived(new Set(access.data?.targets?.map((t) => t.id) || []));
	// access.data.targets carry each target's principals, so we can tell whether
	// this subject is directly assigned or only reaches the target via a team.
	const accessTargetsById = $derived(
		new Map<string, Target>((access.data?.targets || []).map((t) => [t.id, t]))
	);

	const totalPages = $derived(Math.ceil((targets.data?.total || 0) / limit));

	// Helpers
	function getSubjectTypeLabel(type: PrincipalType): string {
		switch (type) {
			case PrincipalType.USER:
				return 'User';
			case PrincipalType.TEAM:
				return 'Team';
			case PrincipalType.SERVICE_ACCOUNT:
				return 'Service Account';
			default:
				return 'Subject';
		}
	}

	function getSubjectIds(principal: Principal, type: PrincipalType): string[] {
		switch (type) {
			case PrincipalType.USER:
				return principal.userIds;
			case PrincipalType.TEAM:
				return principal.teamIds;
			case PrincipalType.SERVICE_ACCOUNT:
				return principal.serviceAccountIds;
			default:
				return [];
		}
	}

	function getSubjectCount(principal: Principal, type: PrincipalType): number {
		return getSubjectIds(principal, type).length;
	}

	const subjectTypeLabel = $derived(getSubjectTypeLabel(subjectType));
	const subjectTypeLower = $derived(subjectTypeLabel.toLowerCase());
	const subjectTypePlural = $derived(
		subjectType === PrincipalType.SERVICE_ACCOUNT ? 'service accounts' : `${subjectTypeLower}s`
	);

	// Effective assignment of this subject to a principal, honoring any
	// optimistic toggle still in flight.
	function isAssignedNow(p: Principal): boolean {
		const serverAssigned = getSubjectIds(p, subjectType).includes(subjectID);
		const pending = pendingAssign.get(p.id);
		return pending === undefined ? serverAssigned : pending;
	}

	// Per-target access for the sidebar: whether the subject reaches the target
	// and whether that's via a direct assignment or only through team membership.
	function getTargetAccess(t: Target): { accessible: boolean; direct: boolean } {
		const at = accessTargetsById.get(t.id);
		if (!at) return { accessible: false, direct: false };
		const direct = (at.principals || []).some((p) =>
			getSubjectIds(p, subjectType).includes(subjectID)
		);
		return { accessible: true, direct };
	}

	// Set this subject's assignment to a principal optimistically, then persist
	// it via the matching mutation. The pending entry is cleared once the
	// mutation settles and the server refetch reconciles.
	function setAssignment(p: Principal, assigned: boolean) {
		if (subjectID) pendingAssign.set(p.id, assigned);
		const mutate = assigned ? addToPrincipal : removeFromPrincipal;
		mutate.mutate(
			{ id: p.id, subjectIds: [subjectID], type: subjectType },
			{ onSettled: () => pendingAssign.delete(p.id) }
		);
	}

	function togglePrincipal(p: Principal) {
		setAssignment(p, !isAssignedNow(p));
	}

	function grantAllInTarget() {
		const principals = targetPrincipals.data?.principals || [];
		principals.forEach((p) => {
			if (!isAssignedNow(p)) setAssignment(p, true);
		});
	}

	function revokeAllInTarget() {
		const principals = targetPrincipals.data?.principals || [];
		principals.forEach((p) => {
			if (isAssignedNow(p)) setAssignment(p, false);
		});
	}

	function goBack() {
		window.history.back();
	}
</script>

<svelte:head>
	<title>Assign Access - {subjectName}</title>
</svelte:head>

<DeleteConfirmationModal
	bind:open={openRevokeAllModal}
	title="Revoke All Access"
	description="This will revoke all access globally for {subjectName}. This action cannot be undone."
	itemName={subjectName}
	onConfirm={() => revokeAccess.mutate({ subjectId: subjectID, type: subjectType })}
/>

<div class="flex flex-1 overflow-hidden bg-background">
	<!-- Left Panel: Targets Sidebar -->
	<div class="flex w-80 shrink-0 flex-col border-r bg-muted/10">
		<div class="border-b p-4">
			<div class="mb-4 flex items-center gap-2">
				<Button variant="ghost" size="icon" class="h-8 w-8" onclick={goBack} title="Go Back">
					<ChevronLeft size={16} />
				</Button>
				<h2 class="font-semibold tracking-tight">Targets</h2>
			</div>
			<InputGroupVariants
				variant="search"
				placeholder="Search targets..."
				bind:value={search}
				searchResults={targets.data?.total}
			/>
		</div>

		<div class="no-scrollbar flex-1 space-y-1 overflow-y-auto p-2">
			{#if targets.isLoading || access.isLoading}
				<div class="py-8 text-center text-sm text-muted-foreground">Loading targets...</div>
			{:else if displayedTargets.length === 0}
				<div
					class="flex flex-col items-center justify-center py-12 text-center text-muted-foreground"
				>
					<ServerIcon size={32} class="mb-3 opacity-20" />
					<p class="text-sm">
						{debounced.current ? 'No matches found.' : 'No available targets.'}
					</p>
				</div>
			{:else}
				{#each displayedTargets as tgt (tgt.id)}
					{@const { accessible, direct } = getTargetAccess(tgt)}
					{@const isSelected = selectedTargetId === tgt.id}

					<button
						class="flex w-full items-center gap-3 rounded-md px-3 py-2 text-left text-sm transition-colors hover:bg-muted/50 {isSelected
							? 'bg-primary/10 text-primary'
							: 'text-foreground'}"
						onclick={() => {
							selectedTargetId = tgt.id;
							pendingAssign.clear();
						}}
					>
						<div
							class="flex h-8 w-8 shrink-0 items-center justify-center rounded-md border bg-background shadow-sm {isSelected
								? 'border-primary/30'
								: ''}"
						>
							<ServerIcon size={14} class={accessible ? 'text-primary' : 'text-muted-foreground'} />
						</div>
						<div class="flex-1 overflow-hidden">
							<div class="truncate font-medium">{tgt.name}</div>
							{#if tgt.description}
								<div
									class="truncate text-xs opacity-70 {isSelected
										? 'text-primary/70'
										: 'text-muted-foreground'}"
								>
									{tgt.description}
								</div>
							{/if}
						</div>
						{#if !accessible}
							<Badge variant="secondary" class="h-5 shrink-0 px-1.5 text-[10px]">No Access</Badge>
						{:else if direct}
							<Badge variant="default" class="h-5 shrink-0 px-1.5 text-[10px]">Access</Badge>
						{:else}
							<Badge variant="outline" class="h-5 shrink-0 px-1.5 text-[10px]">Via Team</Badge>
						{/if}
					</button>
				{/each}
			{/if}
		</div>

		<!-- Pagination Footer -->
		<div class="flex items-center justify-between border-t bg-muted/5 p-3">
			<Button
				variant="outline"
				size="sm"
				class="h-8 text-xs text-muted-foreground"
				disabled={pageIdx === 0}
				onclick={() => (pageIdx = Math.max(0, pageIdx - 1))}
			>
				Previous
			</Button>
			<span class="text-xs text-muted-foreground">
				{totalPages > 0 ? `${pageIdx + 1} of ${totalPages}` : '0 of 0'}
			</span>
			<Button
				variant="outline"
				size="sm"
				class="h-8 text-xs text-muted-foreground"
				disabled={pageIdx >= totalPages - 1}
				onclick={() => (pageIdx = Math.min(totalPages - 1, pageIdx + 1))}
			>
				Next
			</Button>
		</div>
	</div>

	<!-- Right Panel: Main Content Area -->
	<div class="flex flex-1 flex-col overflow-hidden bg-background/50">
		<!-- Header showing Subject Info -->
		<div class="flex items-center justify-between border-b px-8 py-6 backdrop-blur-sm">
			<div class="flex items-center gap-4">
				<div
					class="flex h-14 w-14 items-center justify-center rounded-xl bg-primary/10 text-primary shadow-sm ring-1 ring-primary/20"
				>
					<ShieldCheck size={28} />
				</div>
				<div>
					<h1 class="text-2xl font-bold tracking-tight">{subjectName}</h1>
					<p class="text-sm font-medium text-muted-foreground">
						Managing <span class="capitalize">{subjectTypeLabel}</span> Access
					</p>
				</div>
			</div>
			<div class="flex items-center gap-3">
				{#if accessibleTargetIds.size > 0}
					<Button variant="destructive" onclick={() => (openRevokeAllModal = true)}>
						<UserX size={16} class="mr-2" />
						Revoke All Access
					</Button>
				{/if}
			</div>
		</div>

		<div class="flex-1 overflow-y-auto p-8">
			{#if !selectedTargetId || !selectedTarget}
				<Empty.Root class="h-[60vh] text-card-foreground">
					<Empty.Header>
						<Empty.Media variant="icon">
							<Terminal />
						</Empty.Media>
						<Empty.Title>No Target Selected</Empty.Title>
						<Empty.Description>
							Choose a target from the sidebar to view its principals and manage assignments for <span
								class="font-medium text-foreground">{subjectName}</span
							>.
						</Empty.Description>
					</Empty.Header>
				</Empty.Root>
			{:else}
				{@const allPrincipals = targetPrincipals.data?.principals || []}
				{@const assignedPrincipals = allPrincipals.filter((p) => isAssignedNow(p))}
				{@const allAssigned =
					assignedPrincipals.length === allPrincipals.length && allPrincipals.length > 0}
				{@const targetAccess = getTargetAccess(selectedTarget)}

				<!-- Details of selected target -->
				<div class="mx-auto max-w-5xl">
					<!-- Subheader -->
					<div class="mb-8">
						<h2 class="text-3xl font-bold tracking-tight">{selectedTarget.name}</h2>
						{#if selectedTarget.description}
							<p class="mt-2 text-lg text-muted-foreground">{selectedTarget.description}</p>
						{/if}
						{#if targetAccess.accessible && !targetAccess.direct}
							<p class="mt-3 flex items-center gap-2 text-sm text-muted-foreground">
								<Users size={16} class="shrink-0" />
								{subjectName} reaches this target through a team, so no direct assignments are shown here.
								Toggle switches to grant access directly.
							</p>
						{/if}
					</div>

					<!-- Stats Row -->
					<div class="mb-10 grid grid-cols-2 gap-4 md:grid-cols-4">
						<Card.Root class="bg-card/50 shadow-sm transition-colors hover:bg-card">
							<Card.Content class="px-5 py-2">
								<div class="text-sm font-medium text-muted-foreground">Total Principals</div>
								<div class="mt-2 text-3xl font-bold">{allPrincipals.length}</div>
							</Card.Content>
						</Card.Root>
						<Card.Root class="bg-card/50 shadow-sm transition-colors hover:bg-card">
							<Card.Content class="px-5 py-2">
								<div class="text-sm font-medium text-muted-foreground">
									Assigned to {subjectName}
								</div>
								<div
									class="mt-2 text-3xl font-bold {assignedPrincipals.length > 0
										? 'text-primary'
										: ''}"
								>
									{assignedPrincipals.length}
								</div>
							</Card.Content>
						</Card.Root>

						<!-- Placeholders for future metrics (e.g. Activity, Last Login) -->
						<Card.Root class="border-dashed bg-transparent opacity-60">
							<Card.Content
								class="flex h-full flex-col items-center justify-center p-5 text-center"
							>
								<div class="text-xs font-medium text-muted-foreground">Available Metric Slot</div>
								<div class="mt-1 text-[10px] text-muted-foreground/70">e.g. Active Sessions</div>
							</Card.Content>
						</Card.Root>
						<Card.Root class="border-dashed bg-transparent opacity-60">
							<Card.Content
								class="flex h-full flex-col items-center justify-center p-5 text-center"
							>
								<div class="text-xs font-medium text-muted-foreground">Available Metric Slot</div>
								<div class="mt-1 text-[10px] text-muted-foreground/70">e.g. Last Access Time</div>
							</Card.Content>
						</Card.Root>
					</div>

					<!-- Principals Assignment Section -->
					<div class="mb-6 flex items-end justify-between">
						<div>
							<h3 class="text-xl font-semibold tracking-tight">Available Principals</h3>
							<p class="mt-1 text-sm text-muted-foreground">
								Toggle switches to grant or revoke {subjectTypeLower} access to specific principals on
								this target.
							</p>
						</div>
						<div class="flex gap-2">
							<Button
								variant="outline"
								size="sm"
								onclick={grantAllInTarget}
								disabled={allAssigned || allPrincipals.length === 0}
							>
								<ShieldCheck size={16} class="mr-2" />
								Grant All
							</Button>
							<Button
								variant="outline"
								size="sm"
								class="border-destructive/20 text-destructive hover:bg-destructive/10 hover:text-destructive"
								onclick={revokeAllInTarget}
								disabled={assignedPrincipals.length === 0}
							>
								<ShieldX size={16} class="mr-2" />
								Revoke All
							</Button>
						</div>
					</div>

					<div class="grid gap-3">
						{#if targetPrincipals.data?.total === 0}
							<Empty.Root class="border border-dashed py-12">
								<Empty.Media variant="icon"><CircleAlert /></Empty.Media>
								<Empty.Title>No Principals Found</Empty.Title>
								<Empty.Description>
									This target does not have any syncable principals available.
								</Empty.Description>
							</Empty.Root>
						{:else}
							{#each targetPrincipals.data?.principals as principal (principal.id)}
								{@const isAssigned = isAssignedNow(principal)}
								{@const subjectCount = getSubjectCount(principal, subjectType)}

								<div
									class="group flex items-center justify-between rounded-xl border bg-card p-5 shadow-sm transition-all duration-200 hover:border-primary/40 hover:shadow-md {isAssigned
										? 'ring-1 ring-primary/20'
										: ''}"
								>
									<div class="flex flex-col">
										<div class="flex items-center gap-3">
											<div
												class="flex h-10 w-10 items-center justify-center rounded-lg bg-muted/50 text-foreground transition-colors group-hover:bg-primary/10 group-hover:text-primary"
											>
												<Terminal size={18} />
											</div>
											<div>
												<div class="flex items-center gap-2">
													<span class="font-mono text-base font-semibold">{principal.username}</span
													>
												</div>
												<Tooltip.Root>
													<Tooltip.Trigger class="text-left">
														<div
															class="mt-1 flex cursor-default items-center gap-1 text-xs text-muted-foreground"
														>
															<span class="font-medium">{subjectCount}</span>
															<span>
																{subjectCount === 1 ? subjectTypeLower : subjectTypePlural}
																have access globally
															</span>
														</div>
													</Tooltip.Trigger>
													<Tooltip.Content>
														<p class="text-xs">
															{subjectCount}
															{subjectCount === 1 ? subjectTypeLower : subjectTypePlural} are currently
															assigned to this principal across the workspace.
														</p>
													</Tooltip.Content>
												</Tooltip.Root>
											</div>
										</div>
									</div>

									<Switch checked={isAssigned} onCheckedChange={() => togglePrincipal(principal)} />
								</div>
							{/each}
						{/if}
					</div>
				</div>
			{/if}
		</div>
	</div>
</div>
