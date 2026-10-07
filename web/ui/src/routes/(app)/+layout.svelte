<script lang="ts">
	import { fade } from 'svelte/transition';
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import AppFooter from '#lib/components/layout/AppFooter.svelte';
	import AppHeader from '#lib/components/layout/AppHeader.svelte';
	import AppSidebar from '#lib/components/layout/AppSidebar.svelte';
	import CommandPalette from '#lib/components/layout/CommandPalette.svelte';
	import LicenseBanner from '#lib/components/layout/LicenseBanner.svelte';
	import * as Sidebar from '#lib/components/ui/sidebar/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import { user } from '#lib/api/user.svelte.js';
	import { workspace } from '#lib/api/workspaces.svelte.js';
	import { pendingDeviceCode } from '#lib/store.svelte.js';

	let { children } = $props();

	// The host names the workspace, the session names the user. Both load once.
	const ws = workspace.get();
	const me = user.self();
	const booting = $derived(!ws.data || !me.data);

	// These lay out their own full-width canvas.
	const fullBleed = $derived(page.url.pathname === '/sessions');

	$effect(() => {
		if (page.url.pathname !== '/') return;
		const code = pendingDeviceCode.current;
		if (code) {
			pendingDeviceCode.current = undefined;
			goto(`/device?user_code=${code}`);
		}
	});
</script>

<CommandPalette />

{#if booting}
	<div class="flex h-dvh items-center justify-center">
		<Spinner class="size-6 text-primary" />
	</div>
{:else}
	<div class="flex h-screen overflow-hidden">
		<Sidebar.Provider>
			<AppSidebar variant="inset" />
			<Sidebar.Inset class="flex min-w-0 flex-1 flex-col overflow-hidden">
				<AppHeader />
				<LicenseBanner />

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
