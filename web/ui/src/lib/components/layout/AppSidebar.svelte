<script lang="ts">
	import * as DropdownMenu from '$lib/components/ui/dropdown-menu';
	import * as Sidebar from '$lib/components/ui/sidebar';
	import { Check, ChevronsUpDown, ChevronRight, Plus, SlidersHorizontal } from '@lucide/svelte';
	import type { ComponentProps } from 'svelte';
	import { AppRoutes, SupportRoutes, canSee, type RouteItem } from './routes';
	import UserMenu from './UserMenu.svelte';
	import { workspace } from '$lib/api/workspaces.svelte';
	import { user } from '$lib/api/user.svelte';
	import UserAvatar from '$lib/components/blocks/UserAvatar.svelte';
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import * as Collapsible from '$lib/components/ui/collapsible';
	import WorkspaceModal from '../modals/WorkspaceModal.svelte';
	import { workspaceID } from '$lib/store.svelte';
	import { WorkspaceSchema } from '$lib/gen/nokku/v1/workspace_pb';
	import { createEntityModalState } from '$lib/hooks';
	import NokkuCaret from '$lib/assets/nokku_caret.svelte';

	let { ...restProps }: ComponentProps<typeof Sidebar.Root> = $props();

	const sidebar = Sidebar.useSidebar();

	const ws = workspace.get();
	const workspaces = workspace.list();
	const currentUser = user.self();
	const currentRoute = $derived(page.url.pathname);

	const visibleRoutes = $derived(
		Object.entries(AppRoutes)
			.map(([group, routes]) => [group, routes.filter((r) => canSee(r, ws.data?.role))] as const)
			.filter(([, routes]) => routes.length > 0)
	);

	const wsModal = createEntityModalState(WorkspaceSchema);
	const isRouteActive = (item: RouteItem) => {
		if (item.url === '/') {
			return currentRoute === '/';
		}
		const cleanUrl = item.url.replace(/\/$/, '');
		return (
			currentRoute === cleanUrl ||
			currentRoute === item.url ||
			currentRoute.startsWith(item.url + '/')
		);
	};
</script>

<WorkspaceModal bind:open={wsModal.open} draft={wsModal.draft} />

<Sidebar.Root collapsible="offcanvas" {...restProps}>
	<Sidebar.Header>
		<Sidebar.Menu>
			<Sidebar.MenuItem>
				<DropdownMenu.Root>
					<DropdownMenu.Trigger>
						{#snippet child({ props })}
							<Sidebar.MenuButton
								{...props}
								size="lg"
								class="data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground"
							>
								<div class="rounded-lg bg-terminal p-2.5 text-brand-caret">
									<NokkuCaret class="pl-0.5" />
								</div>
								<div class="grid flex-1 text-left text-sm leading-tight">
									<span class="truncate" title={ws.data?.name}>
										{ws.data?.name ?? 'Select workspace'}
									</span>
									<span class="truncate text-xs" title={ws.data?.description}>
										{ws.data?.description ?? ''}
									</span>
								</div>
								<ChevronsUpDown class="ml-auto" />
							</Sidebar.MenuButton>
						{/snippet}
					</DropdownMenu.Trigger>
					<DropdownMenu.Content
						class="min-w-56 overflow-hidden rounded-lg p-2"
						align="start"
						side={sidebar.isMobile ? 'bottom' : 'right'}
						sideOffset={4}
					>
						<DropdownMenu.Label class="text-xs text-muted-foreground">
							Workspaces
						</DropdownMenu.Label>

						{#each workspaces.data || [] as w (w.id)}
							<DropdownMenu.Item onSelect={() => (workspaceID.current = w.id)}>
								<span class="flex-1 truncate">{w.name}</span>
								{#if w.id === workspaceID.current}
									<Check class="text-primary" />
								{/if}
							</DropdownMenu.Item>
						{/each}
						<DropdownMenu.Separator />
						<DropdownMenu.Item onSelect={() => goto('/settings')}>
							<SlidersHorizontal />
							Workspace settings
						</DropdownMenu.Item>
						<DropdownMenu.Item
							onSelect={() => wsModal.openNew()}
							class="flex items-center gap-2 text-muted-foreground"
						>
							<Plus />
							Add workspace
						</DropdownMenu.Item>
					</DropdownMenu.Content>
				</DropdownMenu.Root>
			</Sidebar.MenuItem>
		</Sidebar.Menu>
	</Sidebar.Header>

	<Sidebar.Content>
		{#each visibleRoutes as [groupName, routes] (groupName)}
			<Sidebar.Group>
				<Sidebar.GroupLabel>{groupName}</Sidebar.GroupLabel>
				<Sidebar.GroupContent>
					<Sidebar.Menu>
						{#each routes as r (r.title)}
							{#if r.items && r.items.length > 0}
								<Collapsible.Root open={isRouteActive(r)} class="group/collapsible">
									<Sidebar.MenuItem>
										<Collapsible.Trigger>
											{#snippet child({ props })}
												<Sidebar.MenuButton
													{...props}
													tooltipContent={r.title}
													isActive={isRouteActive(r)}
												>
													<r.icon />
													<span>{r.title}</span>
													<ChevronRight
														class="ml-auto transition-transform duration-200 group-data-[state=open]/collapsible:rotate-90"
													/>
												</Sidebar.MenuButton>
											{/snippet}
										</Collapsible.Trigger>
										<Collapsible.Content>
											<Sidebar.MenuSub>
												{#each r.items as subItem (subItem.title)}
													<Sidebar.MenuSubItem>
														<Sidebar.MenuSubButton isActive={currentRoute === subItem.url}>
															{#snippet child({ props })}
																<a href={subItem.url} {...props}>
																	<span>{subItem.title}</span>
																</a>
															{/snippet}
														</Sidebar.MenuSubButton>
													</Sidebar.MenuSubItem>
												{/each}
											</Sidebar.MenuSub>
										</Collapsible.Content>
									</Sidebar.MenuItem>
								</Collapsible.Root>
							{:else}
								<Sidebar.MenuItem>
									<Sidebar.MenuButton tooltipContent={r.title} isActive={isRouteActive(r)}>
										{#snippet child({ props })}
											<a href={r.url} {...props}>
												<r.icon />
												<span>{r.title}</span>
											</a>
										{/snippet}
									</Sidebar.MenuButton>
								</Sidebar.MenuItem>
							{/if}
						{/each}
					</Sidebar.Menu>
				</Sidebar.GroupContent>
			</Sidebar.Group>
		{/each}

		<Sidebar.Group class="mt-auto">
			{#each Object.entries(SupportRoutes) as [groupName, routes] (groupName)}
				<Sidebar.GroupContent>
					<Sidebar.GroupLabel>{groupName}</Sidebar.GroupLabel>
					<Sidebar.Menu>
						{#each routes as r (r.title)}
							<Sidebar.MenuItem>
								<Sidebar.MenuButton tooltipContent={r.title} isActive={isRouteActive(r)}>
									{#snippet child({ props })}
										<a href={r.url} {...props}>
											<r.icon />
											<span>{r.title}</span>
										</a>
									{/snippet}
								</Sidebar.MenuButton>
							</Sidebar.MenuItem>
						{/each}
					</Sidebar.Menu>
				</Sidebar.GroupContent>
			{/each}
		</Sidebar.Group>
	</Sidebar.Content>

	<Sidebar.Footer>
		<Sidebar.Menu>
			<Sidebar.MenuItem>
				<UserMenu side={sidebar.isMobile ? 'bottom' : 'right'}>
					{#snippet trigger(props)}
						<Sidebar.MenuButton size="lg" {...props}>
							<UserAvatar user={currentUser.data} />
							<div class="flex min-w-0 flex-col text-sm leading-tight">
								<span class="truncate font-medium">
									{currentUser.data?.name || currentUser.data?.email.split('@')[0]}
								</span>
								<span class="truncate text-xs opacity-70">{currentUser.data?.email}</span>
							</div>
							<ChevronsUpDown class="ml-auto size-4" />
						</Sidebar.MenuButton>
					{/snippet}
				</UserMenu>
			</Sidebar.MenuItem>
		</Sidebar.Menu>
	</Sidebar.Footer>

	<Sidebar.Rail />
</Sidebar.Root>
