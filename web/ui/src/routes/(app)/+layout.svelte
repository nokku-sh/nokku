<script lang="ts">
	import { onMount } from 'svelte';
	import { fade } from 'svelte/transition';
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import AppFooter from '$lib/components/nav/AppFooter.svelte';
	import AppHeader from '$lib/components/nav/AppHeader.svelte';
	import AppSidebar from '$lib/components/nav/AppSidebar.svelte';
	import CommandPalette from '$lib/components/utils/CommandPalette.svelte';
	import * as Sidebar from '$lib/components/ui/sidebar';
	import { workspace } from '$lib/api/workspaces.svelte';
	import { pendingDeviceCode, workspaceID } from '$lib/store.svelte';

	let { children } = $props();

	const ws = workspace.list();

	onMount(() => {
		ws.refetch();
	});

	$effect(() => {
		if (page.url.pathname !== '/') return;
		const code = pendingDeviceCode.current;
		if (code) {
			pendingDeviceCode.current = undefined;
			goto(`/device?user_code=${code}`);
		}
	});

	$effect(() => {
		if (
			ws.isSuccess &&
			workspaceID.current === '' &&
			page.url.pathname !== '/' &&
			!page.url.pathname.startsWith('/profile')
		) {
			goto('/');
		}
	});
</script>

<CommandPalette />

<div class="flex h-screen overflow-hidden">
	<Sidebar.Provider>
		<AppSidebar variant="inset" />
		<Sidebar.Inset class="flex min-w-0 flex-1 flex-col overflow-hidden">
			<AppHeader />

			<main class="flex min-h-0 flex-1 flex-col overflow-auto">
				{#key page.url.pathname}
					<div class="flex flex-1 flex-col" in:fade={{ duration: 200 }}>
						{@render children?.()}
					</div>
				{/key}
			</main>

			<AppFooter />
		</Sidebar.Inset>
	</Sidebar.Provider>
</div>
