<script lang="ts">
	import { onMount } from 'svelte';
	import { fade } from 'svelte/transition';
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import AppFooter from '$lib/components/layout/AppFooter.svelte';
	import AppHeader from '$lib/components/layout/AppHeader.svelte';
	import AppSidebar from '$lib/components/layout/AppSidebar.svelte';
	import CommandPalette from '$lib/components/layout/CommandPalette.svelte';
	import * as Sidebar from '$lib/components/ui/sidebar';
	import { user } from '$lib/api/user.svelte';
	import { workspace } from '$lib/api/workspaces.svelte';
	import { Logo } from '$lib/assets';
	import LegalLinks from '$lib/components/blocks/LegalLinks.svelte';
	import ModeSwitch from '$lib/components/blocks/ModeSwitch.svelte';
	import UserAvatar from '$lib/components/blocks/UserAvatar.svelte';
	import UserMenu from '$lib/components/layout/UserMenu.svelte';
	import { Button } from '$lib/components/ui/button';
	import { Spinner } from '$lib/components/ui/spinner';
	import { ChevronDown } from '@lucide/svelte';
	import { pendingDeviceCode, workspaceID } from '$lib/store.svelte';

	let { children } = $props();

	const ws = workspace.list();
	const me = user.self();

	// The list picks a workspace when there is one, so empty means none exist yet.
	const booting = $derived(!ws.isSuccess && !workspaceID.current);
	const noWorkspace = $derived(ws.isSuccess && !workspaceID.current);

	// These lay out their own full-width canvas.
	const fullBleed = $derived(page.url.pathname === '/sessions');

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

{#if booting}
	<div class="flex h-dvh items-center justify-center">
		<Spinner class="size-6 text-primary" />
	</div>
{:else if noWorkspace}
	<!-- No sidebar without a workspace, every entry in it needs one. -->
	<div class="flex min-h-dvh flex-col">
		<header class="flex h-14 shrink-0 items-center justify-between border-b px-4 lg:px-6">
			<a href="/" class="flex items-center gap-2 font-mono text-sm font-semibold">
				<Logo class="w-7" />
				nokku
			</a>
			<div class="flex items-center gap-1">
				<ModeSwitch />
				<UserMenu>
					{#snippet trigger(props)}
						<Button {...props} variant="ghost" size="sm" class="gap-2">
							<UserAvatar user={me.data} class="size-6" />
							<span class="hidden max-w-40 truncate sm:inline"
								>{me.data?.name || me.data?.email}</span
							>
							<ChevronDown data-icon="inline-end" />
						</Button>
					{/snippet}
				</UserMenu>
			</div>
		</header>
		<main class="flex flex-1 flex-col">
			{#key page.url.pathname}
				<div
					class={[
						'flex flex-1 flex-col',
						page.url.pathname !== '/' && 'container mx-auto max-w-6xl gap-6 p-6'
					]}
					in:fade={{ duration: 200 }}
				>
					{@render children?.()}
				</div>
			{/key}
		</main>
		<footer class="border-t px-4 py-3 lg:px-6">
			<LegalLinks />
		</footer>
	</div>
{:else}
	<div class="flex h-screen overflow-hidden">
		<Sidebar.Provider>
			<AppSidebar variant="inset" />
			<Sidebar.Inset class="flex min-w-0 flex-1 flex-col overflow-hidden">
				<AppHeader />

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
