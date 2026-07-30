<script lang="ts">
	import { Button } from '$lib/components/ui/button';
	import * as DropdownMenu from '$lib/components/ui/dropdown-menu';
	import * as Sidebar from '$lib/components/ui/sidebar';
	import * as Empty from '$lib/components/ui/empty';
	import { ChevronsUpDown, ChevronRight, Layers2, LogOut, Pencil, Plus } from '@lucide/svelte';
	import type { ComponentProps } from 'svelte';
	import { AppRoutes, SupportRoutes, UserRoutes, type RouteItem } from './routes';
	import { workspace } from '$lib/api/workspaces.svelte';
	import { user } from '$lib/api/user.svelte';
	import { auth } from '$lib/api/auth.svelte';
	import UserAvatar from '../utils/UserAvatar.svelte';
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import * as Collapsible from '$lib/components/ui/collapsible';
	import WorkspaceModal from '../modals/WorkspaceModal.svelte';
	import { workspaceID } from '$lib/store.svelte';
	import NokkuCaret from '$lib/assets/nokku_caret.svelte';

	let { ...restProps }: ComponentProps<typeof Sidebar.Root> = $props();

	const sidebar = Sidebar.useSidebar();

	const ws = $derived(workspace.get());
	const workspaces = $derived(workspace.list());
	const currentUser = $derived(user.self());
	const logout = auth.logout();
	const currentRoute = $derived(page.url.pathname);

	let wsModal = $state(false);
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

<WorkspaceModal bind:open={wsModal} />

<Sidebar.Root collapsible="offcanvas" {...restProps}>
	<!-- Workspace Selection -->
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
								<div class="rounded-full bg-sidebar-primary p-2.5">
									<NokkuCaret class="pl-0.5 invert" />
								</div>
								<div class="grid flex-1 text-left text-sm leading-tight">
									<span class="truncate" title={ws.data?.name}>
										{ws.data?.name ?? 'Select Workspace'}
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
							<DropdownMenu.Item
								onSelect={() => (workspaceID.current = w.id)}
								class="flex items-center justify-between gap-2"
							>
								<div class="flex min-w-0 flex-1 items-center gap-2">
									<span class="truncate text-sm">{w.name}</span>
								</div>
								<Button
									variant="ghost"
									class="rounded-full"
									size="icon"
									onclick={() => goto('/settings')}
								>
									<Pencil />
								</Button>
							</DropdownMenu.Item>
						{/each}
						<DropdownMenu.Separator />
						<DropdownMenu.Item
							onSelect={() => (wsModal = true)}
							class="flex items-center gap-2 text-muted-foreground"
						>
							<Plus />
							Add Workspace
						</DropdownMenu.Item>
					</DropdownMenu.Content>
				</DropdownMenu.Root>
			</Sidebar.MenuItem>
		</Sidebar.Menu>
	</Sidebar.Header>

	<Sidebar.Content>
		{#if workspaceID.current !== null && workspaceID.current !== ''}
			{#each Object.entries(AppRoutes) as [groupName, routes] (groupName)}
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
		{:else}
			<!-- Empty state when no workspace is selected -->
			<Empty.Root>
				<Empty.Header>
					<Empty.Media variant="icon">
						<Layers2 />
					</Empty.Media>
					<Empty.Title>No Workspace Selected</Empty.Title>
					<Empty.Description>Select or create a workspace to get started</Empty.Description>
				</Empty.Header>
				<Empty.Content>
					<Button onclick={() => (wsModal = true)}>Create Workspace</Button>
				</Empty.Content>
			</Empty.Root>
		{/if}

		<!-- Bottom buttons -->
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

	<!-- User Profile -->
	<Sidebar.Footer>
		<Sidebar.Menu>
			<Sidebar.MenuItem>
				<DropdownMenu.Root>
					<DropdownMenu.Trigger>
						{#snippet child({ props })}
							<Sidebar.MenuButton size="lg" {...props}>
								<UserAvatar user={currentUser.data} />
								<div class="flex flex-col text-sm leading-tight">
									<span class="truncate font-semibold">{currentUser.data?.username}</span>
									<span class="truncate text-xs opacity-70">{currentUser.data?.email}</span>
								</div>
								<ChevronsUpDown class="ml-auto size-4" />
							</Sidebar.MenuButton>
						{/snippet}
					</DropdownMenu.Trigger>
					<DropdownMenu.Content
						class="w-[--bits-dropdown-menu-anchor-width] min-w-52 rounded-lg"
						side={sidebar.isMobile ? 'bottom' : 'right'}
						align="end"
						sideOffset={4}
					>
						<DropdownMenu.Label class="p-0 font-normal">
							<div class="flex items-center gap-2 px-1 py-1.5 text-sm">
								<UserAvatar user={currentUser.data} />
								<div class="grid flex-1 text-left text-sm leading-tight">
									<span class="truncate font-semibold">{currentUser.data?.username}</span>
									<span class="truncate text-xs opacity-70">{currentUser.data?.email}</span>
								</div>
							</div>
						</DropdownMenu.Label>
						<DropdownMenu.Separator />
						<DropdownMenu.Group>
							{#each UserRoutes as r (r.title)}
								{#if r.items}
									{#each r.items as subItem (subItem.title)}
										<DropdownMenu.Item onSelect={() => goto(subItem.url)}>
											<subItem.icon />
											<span>{subItem.title}</span>
										</DropdownMenu.Item>
									{/each}
								{:else}
									<DropdownMenu.Item onSelect={() => goto(r.url)}>
										<r.icon />
										<span>{r.title}</span>
									</DropdownMenu.Item>
								{/if}
							{/each}
						</DropdownMenu.Group>
						<DropdownMenu.Separator />
						<DropdownMenu.Item onSelect={() => logout.mutate({})}>
							<LogOut />
							<span>Log out</span>
						</DropdownMenu.Item>
					</DropdownMenu.Content>
				</DropdownMenu.Root>
			</Sidebar.MenuItem>
		</Sidebar.Menu>
	</Sidebar.Footer>

	<Sidebar.Rail />
</Sidebar.Root>
