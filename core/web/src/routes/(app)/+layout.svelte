<script lang="ts">
	import { fade } from 'svelte/transition';
	import { page } from '$app/state';
	import { beforeNavigate, goto, preloadCode } from '$app/navigation';
	import AppFooter from '#lib/components/layout/AppFooter.svelte';
	import AppHeader from '#lib/components/layout/AppHeader.svelte';
	import AppSidebar from '#lib/components/layout/AppSidebar.svelte';
	import CommandPalette from '#lib/components/layout/CommandPalette.svelte';
	import ConnectionBanner from '#lib/components/layout/ConnectionBanner.svelte';
	import { canVisit } from '#lib/components/layout/routes.js';
	import LicenseBanner from '#lib/components/layout/LicenseBanner.svelte';
	import PlanBanner from '#lib/components/layout/PlanBanner.svelte';
	import * as Sidebar from '#lib/components/ui/sidebar/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import AuthCard from '#lib/components/blocks/AuthCard.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import { useLiveChanges } from '#lib/api/changes.svelte.js';
	import { isLeaving } from '#lib/api/client.js';
	import { connection } from '#lib/api/connection.svelte.js';
	import { liveSessions } from '#lib/api/terminal.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import { util, workspace } from '#lib/api/workspaces.svelte.js';
	import { pendingDeviceCode, returnTo } from '#lib/store.svelte.js';
	import { Code, ConnectError } from '@connectrpc/connect';
	import { CloudOff, RotateCw, TriangleAlert } from '@lucide/svelte';
	import { toast } from 'svelte-sonner';

	let { children } = $props();

	// The host names the workspace, the session names the user. Both load once.
	const ws = workspace.get();
	const me = user.self();
	// Both are read every time. svelte-query only reports a property that was read, a short-circuit drops one.
	const booting = $derived([ws.data, me.data].some((d) => !d));
	// An expired session is already on its way to /login.
	const bootFailed = $derived(
		[ws.error, me.error].some((e) => e && ConnectError.from(e).code !== Code.Unauthenticated)
	);

	useLiveChanges(() => !booting);

	const RETURN_WINDOW = 30 * 60_000;

	// Most pages don't poll, so without a heartbeat an outage only shows on the next request.
	util.getVersion(() => (connection.down ? 10_000 : 15_000));

	// With the server gone a route import fails and SvelteKit swaps the app for the error page, so try it first.
	let cleared: string | undefined;
	beforeNavigate((nav) => {
		const to = nav.to;
		if (!connection.down || !to?.route.id || nav.willUnload || nav.type === 'popstate') return;
		if (to.route.id === nav.from?.route.id) return;
		if (cleared === to.url.href) {
			cleared = undefined;
			return;
		}
		nav.cancel();
		preloadCode(to.route.id).then(
			() => {
				cleared = to.url.href;
				void goto(to.url);
			},
			() =>
				toast.error("That page isn't loaded yet", {
					description: 'It needs the server, which does not answer right now.',
					id: 'route-unloaded'
				})
		);
	});

	// These lay out their own full-width canvas.
	const fullBleed = $derived(page.url.pathname === '/sessions');

	// The nav hides what the role cannot use, this covers a typed address. The server refuses the calls either way.
	$effect(() => {
		if (me.data && !canVisit(page.url.pathname, me.data.role)) {
			void goto('/', { replace: true });
		}
	});

	$effect(() => {
		if (page.url.pathname !== '/') return;
		const code = pendingDeviceCode.current;
		if (code) {
			pendingDeviceCode.current = null;
			goto(`/device?user_code=${code}`);
			return;
		}
		const back = returnTo.current;
		if (back) {
			returnTo.current = null;
			if (Date.now() - back.at < RETURN_WINDOW) goto(back.path, { replace: true });
		}
	});

	// A reload ends every shell in this tab, the browser asks first.
	function onbeforeunload(e: BeforeUnloadEvent) {
		if (!isLeaving() && liveSessions() > 0) e.preventDefault();
	}
</script>

<svelte:window {onbeforeunload} />

<CommandPalette />

{#if booting && bootFailed}
	<main class="flex min-h-dvh items-center justify-center p-4">
		<AuthCard
			title={connection.down ? "Can't reach Nokku" : 'Something went wrong'}
			description={connection.down
				? 'The control plane does not answer. SSH with a valid certificate keeps working.'
				: 'The workspace did not load. Try again in a moment.'}
			icon={connection.down ? CloudOff : TriangleAlert}
			tone="warning"
		>
			<Button
				onclick={() => {
					void ws.refetch();
					void me.refetch();
				}}
				disabled={ws.isFetching || me.isFetching}
			>
				{#if ws.isFetching || me.isFetching}
					<Spinner data-icon="inline-start" />
				{:else}
					<RotateCw data-icon="inline-start" />
				{/if}
				Try again
			</Button>
		</AuthCard>
	</main>
{:else if booting}
	<div class="flex h-dvh items-center justify-center">
		<Spinner class="size-6 text-primary" />
	</div>
{:else}
	<div class="flex h-screen overflow-hidden">
		<Sidebar.Provider>
			<AppSidebar variant="inset" />
			<Sidebar.Inset class="flex min-w-0 flex-1 flex-col overflow-hidden">
				<AppHeader />
				<ConnectionBanner />
				<LicenseBanner />
				<PlanBanner />

				<main class="flex min-h-0 flex-1 flex-col overflow-auto">
					{#key page.url.pathname}
						<div
							class={[
								'flex flex-1 flex-col',
								!fullBleed && 'container mx-auto max-w-6xl gap-6 p-6'
							]}
							in:fade={{ duration: 200 }}
						>
							{@render children?.()}
						</div>
					{/key}
				</main>

				<AppFooter />
			</Sidebar.Inset>
		</Sidebar.Provider>
	</div>
{/if}
