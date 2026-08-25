<script lang="ts">
	import {
		ChevronLeft,
		ChevronRight,
		Search,
		Server,
		SquareArrowOutUpRight,
		X
	} from '@lucide/svelte';
	import { target } from '$lib/api/targets.svelte';
	import { user } from '$lib/api/user.svelte';
	import CopyButton from '$lib/components/ui/copy-button/copy-button.svelte';
	import { Badge } from '$lib/components/ui/badge';
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Skeleton } from '$lib/components/ui/skeleton';
	import * as Empty from '$lib/components/ui/empty';
	import * as ToggleGroup from '$lib/components/ui/toggle-group';

	let searchQuery = $state('');
	let statusFilter = $state<'all' | 'online' | 'offline'>('all');
	let pageIdx = $state(0);
	const pageSize = 25;

	const currentUser = $derived(user.self());
	const access = $derived(target.access(currentUser.data?.id));
	const accessTargets = $derived(access.data?.targets);
	const accessAgents = $derived(access.data?.daemons);

	function isTargetOnline(daemonId: string): boolean {
		return accessAgents?.some((a) => a.id === daemonId && a.online) || false;
	}

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

				const online = isTargetOnline(t.daemonId);
				const matchesStatus =
					statusFilter === 'all' ||
					(statusFilter === 'online' && online) ||
					(statusFilter === 'offline' && !online);

				return matchesSearch && matchesStatus;
			})
			.sort((a, b) => {
				const aOnline = isTargetOnline(a.daemonId);
				const bOnline = isTargetOnline(b.daemonId);
				if (aOnline !== bOnline) return aOnline ? -1 : 1;
				return a.name.localeCompare(b.name);
			});
	});

	const totalPages = $derived(Math.max(1, Math.ceil(filteredTargets.length / pageSize)));
	const pageTargets = $derived(filteredTargets.slice(pageIdx * pageSize, (pageIdx + 1) * pageSize));
	const hasFilters = $derived(searchQuery !== '' || statusFilter !== 'all');

	function resetFilters() {
		searchQuery = '';
		statusFilter = 'all';
		pageIdx = 0;
	}
</script>

<div class="overflow-hidden rounded-xl border bg-card">
	<div class="flex flex-col gap-3 border-b bg-muted/10 p-3 sm:flex-row sm:items-center">
		<div class="relative flex-1">
			<Search class="absolute top-2.5 left-2.5 size-4 text-muted-foreground" />
			<Input
				type="text"
				placeholder="Search by name, host, principal..."
				class="h-9 pl-9"
				bind:value={searchQuery}
			/>
			{#if searchQuery}
				<Button
					variant="ghost"
					size="icon"
					class="absolute top-1.5 right-1.5 size-6 text-muted-foreground hover:text-foreground"
					onclick={() => (searchQuery = '')}
					aria-label="Clear search"
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

	{#if access.isPending}
		<div class="space-y-3 p-4">
			{#each Array(6) as _, i (i)}
				<div class="flex items-center gap-4">
					<Skeleton class="size-2 rounded-full" />
					<Skeleton class="h-5 w-48" />
					<Skeleton class="h-5 w-16" />
					<Skeleton class="ml-auto h-5 w-32" />
				</div>
			{/each}
		</div>
	{:else if filteredTargets.length === 0}
		<Empty.Root class="border-0 py-14">
			<Empty.Header>
				<Empty.Media variant="icon">
					<Server />
				</Empty.Media>
				<Empty.Title>
					{hasFilters ? 'No servers found' : 'No servers available'}
				</Empty.Title>
				<Empty.Description>
					{#if hasFilters}
						Try adjusting your search or filters.
					{:else}
						Servers you can access will show up here.
					{/if}
				</Empty.Description>
			</Empty.Header>
			{#if hasFilters}
				<Empty.Content>
					<Button variant="outline" size="sm" onclick={resetFilters}>Reset filters</Button>
				</Empty.Content>
			{/if}
		</Empty.Root>
	{:else}
		<div class="overflow-x-auto">
			<table class="w-full border-collapse text-left text-sm">
				<thead>
					<tr class="border-b font-medium text-muted-foreground select-none">
						<th class="w-12 px-4 py-3"></th>
						<th class="px-4 py-3">Server</th>
						<th class="hidden px-4 py-3 sm:table-cell">Tags</th>
						<th class="px-4 py-3">Principals</th>
						<th class="w-12 px-4 py-3"></th>
					</tr>
				</thead>
				<tbody class="divide-y">
					{#each pageTargets as t (t.id)}
						{@const online = isTargetOnline(t.daemonId)}
						{@const principalsList = t.principals || []}
						{@const visiblePrincipals = principalsList.slice(0, 3)}
						{@const overflowCount = principalsList.length - 3}

						<tr class="group transition-colors hover:bg-muted/15 {!online ? 'opacity-60' : ''}">
							<td class="px-4 py-3">
								<div class="flex items-center justify-center">
									<span
										class="size-2 rounded-full {online
											? 'bg-emerald-500'
											: 'bg-muted-foreground/30'}"
										title={online ? 'Reachable' : 'Unreachable'}
									></span>
								</div>
							</td>

							<td class="px-4 py-3">
								<div class="flex max-w-55 flex-col">
									<span class="truncate text-sm font-semibold">{t.name}</span>
									{#if t.metadata?.hostname}
										<span class="truncate text-xs text-muted-foreground">
											{t.metadata.hostname}
										</span>
									{/if}
								</div>
							</td>

							<td class="hidden px-4 py-3 sm:table-cell">
								{#if t.tags && t.tags.length > 0}
									<div class="flex flex-wrap gap-1">
										{#each t.tags as tag (tag)}
											<Badge variant="secondary" class="px-1.5 py-0 text-[9px] leading-none">
												{tag}
											</Badge>
										{/each}
									</div>
								{:else}
									<span class="text-xs text-muted-foreground/40 italic">&mdash;</span>
								{/if}
							</td>

							<td class="px-4 py-3">
								{#if principalsList.length === 0}
									<span class="text-xs text-muted-foreground/40 italic">none</span>
								{:else}
									<div class="flex flex-wrap items-center gap-1">
										{#each visiblePrincipals as p (p.id || p.username)}
											<CopyButton text={`${p.username}@${t.name}`} icon={false}>
												<Badge variant="secondary" class="font-mono text-[10px]">
													{p.username}
												</Badge>
											</CopyButton>
										{/each}
										{#if overflowCount > 0}
											<span class="text-[10px] text-muted-foreground">+{overflowCount}</span>
										{/if}
									</div>
								{/if}
							</td>

							<td class="px-4 py-3">
								<Button
									variant="ghost"
									size="icon"
									class="size-7 opacity-0 transition-opacity group-hover:opacity-100"
									href="/sessions"
									disabled={!online}
									title={online ? 'Open a session' : 'Host unreachable'}
								>
									<SquareArrowOutUpRight class="size-3.5" />
								</Button>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>

		<div class="flex items-center justify-between border-t bg-muted/10 px-4 py-3">
			<span class="text-xs text-muted-foreground">
				{filteredTargets.length > 0
					? `${pageIdx * pageSize + 1}\u2013${Math.min((pageIdx + 1) * pageSize, filteredTargets.length)} of ${filteredTargets.length}`
					: '0 results'}
			</span>
			<div class="flex items-center gap-2">
				<Button
					variant="outline"
					size="sm"
					class="h-8 w-8 p-0"
					disabled={pageIdx === 0}
					onclick={() => (pageIdx = Math.max(0, pageIdx - 1))}
					aria-label="Previous page"
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
					aria-label="Next page"
				>
					<ChevronRight class="size-4" />
				</Button>
			</div>
		</div>
	{/if}
</div>
