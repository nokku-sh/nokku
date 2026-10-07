<script lang="ts">
	import * as Sidebar from '#lib/components/ui/sidebar/index.js';
	import { ChevronsUpDown, ChevronRight } from '@lucide/svelte';
	import type { ComponentProps } from 'svelte';
	import {
		AppRoutes,
		SupportRoutes,
		supportRoute,
		visibleRoutes as visible,
		type RouteItem
	} from './routes';
	import UserMenu from './UserMenu.svelte';
	import { dashboard } from '#lib/api/dashboard.svelte.js';
	import { util, workspace } from '#lib/api/workspaces.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import UserAvatar from '#lib/components/blocks/UserAvatar.svelte';
	import { page } from '$app/state';
	import * as Collapsible from '#lib/components/ui/collapsible/index.js';
	import NokkuCaret from '#lib/assets/nokku_caret.svelte';
	import { headline, issuesOf } from '#lib/components/dashboard/issues.js';
	import { toneText } from '#lib/tone.js';

	let { ...restProps }: ComponentProps<typeof Sidebar.Root> = $props();

	const sidebar = Sidebar.useSidebar();

	const ws = workspace.get();
	const info = util.instanceInfo();
	const support = $derived(supportRoute(info.data?.supportEmail));
	const currentUser = user.self();
	const currentRoute = $derived(page.url.pathname);

	// A heads-up on every page. Slower than the dashboard, it only has to hint.
	const can = user.can();
	const overview = dashboard.get(() => can.view, 60_000);
	const issues = $derived(overview.data && issuesOf(overview.data));
	const status = $derived(headline(issues));

	const visibleRoutes = $derived(
		Object.entries(AppRoutes)
			.map(([group, routes]) => [group, visible(routes, currentUser.data?.role)] as const)
			.filter(([, routes]) => routes.length > 0)
	);

	const isRouteActive = (item: RouteItem) =>
		currentRoute === item.url || (item.url !== '/' && currentRoute.startsWith(item.url + '/'));
</script>

<Sidebar.Root collapsible="offcanvas" {...restProps}>
	<Sidebar.Header>
		<Sidebar.Menu>
			<Sidebar.MenuItem>
				<Sidebar.MenuButton size="lg">
					{#snippet child({ props })}
						<a
							href="/"
							{...props}
							title={issues?.length ? issues.map((i) => i.title).join('\n') : ws.data?.description}
						>
							<div class="rounded-lg bg-terminal p-2.5 text-brand-caret">
								<NokkuCaret class="pl-0.5" />
							</div>
							<div class="grid flex-1 text-left text-sm leading-tight">
								<span class="truncate font-medium">{ws.data?.name ?? 'Nokku'}</span>
								{#if can.view}
									<span class={['truncate font-mono text-xs', toneText[status.tone]]}>
										<span class={[status.tone === 'success' && 'motion-safe:animate-breathe']}>
											{status.mark}
										</span>
										{status.text}
									</span>
								{:else}
									<span class="truncate text-xs text-muted-foreground">
										{ws.data?.description || 'Workspace'}
									</span>
								{/if}
							</div>
						</a>
					{/snippet}
				</Sidebar.MenuButton>
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
						{#each support ? [...routes, support] : routes as r (r.title)}
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
