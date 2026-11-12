<script lang="ts">
	import * as Sidebar from '#lib/components/ui/sidebar/index.js';
	import { ChevronsUpDown } from '@lucide/svelte';
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
	import NokkuCaret from '#lib/assets/nokku_caret.svelte';
	import { plural } from '#lib/api/bulk.js';
	import { useWaitingRequests } from '#lib/components/access/requests.svelte.js';
	import { headline, isFresh, issuesOf } from '#lib/components/dashboard/issues.js';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { displayName } from '#lib/utils.js';

	let { ...restProps }: ComponentProps<typeof Sidebar.Root> = $props();

	const sidebar = Sidebar.useSidebar();

	const ws = workspace.get();
	const info = util.instanceInfo();
	const support = $derived(supportRoute(info.data?.supportEmail));
	const currentUser = user.self();
	const currentRoute = $derived(page.url.pathname);

	// A heads-up on every page.
	const can = user.can();
	const overview = dashboard.get(() => can.view);
	const issues = $derived(overview.data && issuesOf(overview.data));
	const requests = useWaitingRequests();
	const status = $derived(headline(issues, isFresh(overview.data), requests.count));
	const waiting = $derived((issues?.length ?? 0) + requests.count);

	// Under the name: what the owner wrote about the workspace, or its address when they wrote nothing. The address
	// is always there and tells two workspaces of one name apart.
	const baseUrl = workspace.baseUrl();
	const host = $derived(baseUrl.data?.replace(/^https?:\/\//, ''));
	const statusTitle = $derived(
		[
			requests.count &&
				`${plural(requests.count, 'access request')} ${requests.count === 1 ? 'waits' : 'wait'} for an answer`,
			...(issues ?? []).map((i) => i.title)
		]
			.filter(Boolean)
			.join('\n')
	);

	const visibleRoutes = $derived(
		Object.entries(AppRoutes)
			.map(([group, routes]) => [group, visible(routes, currentUser.data?.role)] as const)
			.filter(([, routes]) => routes.length > 0)
	);

	// Only the deepest entry that holds the page is current, so /settings stays quiet on /settings/sso.
	const activeUrl = $derived(
		[...visibleRoutes.flatMap(([, routes]) => routes), ...(support ? [support] : [])]
			.map((r) => r.url)
			.filter((url) => currentRoute === url || (url !== '/' && currentRoute.startsWith(url + '/')))
			.sort((a, b) => b.length - a.length)[0]
	);
</script>

{#snippet entry(r: RouteItem)}
	<Sidebar.MenuItem>
		<Sidebar.MenuButton isActive={r.url === activeUrl}>
			{#snippet child({ props })}
				<a href={r.url} {...props}>
					<r.icon />
					<span>{r.title}</span>
					{#if r.shortcut}
						<!-- The jump key, for mouse users who never opened the palette. -->
						<span
							class="ml-auto hidden font-mono text-2xs text-muted-foreground pointer-fine:group-focus-within/menu-item:inline pointer-fine:group-hover/menu-item:inline"
							aria-hidden="true">g {r.shortcut}</span
						>
					{/if}
				</a>
			{/snippet}
		</Sidebar.MenuButton>
	</Sidebar.MenuItem>
{/snippet}

<Sidebar.Root collapsible="offcanvas" {...restProps}>
	<Sidebar.Header>
		<Sidebar.Menu>
			<Sidebar.MenuItem>
				<Sidebar.MenuButton size="lg">
					{#snippet child({ props })}
						<a href="/" {...props} title={statusTitle || ws.data?.description}>
							<div class="rounded-lg bg-terminal p-2.5 text-brand-caret">
								<NokkuCaret class="pl-0.5" />
							</div>
							<div class="grid flex-1 text-left text-sm leading-tight">
								<span class="truncate font-medium">{ws.data?.name ?? 'Nokku'}</span>
								<span
									class={[
										'truncate text-xs text-muted-foreground',
										!ws.data?.description && 'font-mono'
									]}
								>
									{ws.data?.description || host}
								</span>
							</div>
							<!-- Quiet while all is well. A number only when something waits, the list is on Home. -->
							{#if can.view && waiting > 0}
								<Badge
									variant={status.tone === 'destructive' ? 'destructive' : 'warning'}
									class="font-mono tabular-nums"
								>
									<span aria-hidden="true">{waiting}</span>
									<span class="sr-only">{status.text}</span>
								</Badge>
							{/if}
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
						{#each routes as r (r.url)}
							{@render entry(r)}
						{/each}
					</Sidebar.Menu>
				</Sidebar.GroupContent>
			</Sidebar.Group>
		{/each}
	</Sidebar.Content>

	<!-- Help stays in view however long the nav gets. -->
	<Sidebar.Footer>
		<Sidebar.Menu>
			{#each support ? [...SupportRoutes, support] : SupportRoutes as r (r.url)}
				{@render entry(r)}
			{/each}
			<Sidebar.MenuItem>
				<UserMenu side={sidebar.isMobile ? 'bottom' : 'right'}>
					{#snippet trigger(props)}
						<Sidebar.MenuButton size="lg" {...props}>
							<UserAvatar user={currentUser.data} />
							<div class="flex min-w-0 flex-col text-sm leading-tight">
								<span class="truncate font-medium">
									{displayName(currentUser.data)}
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
