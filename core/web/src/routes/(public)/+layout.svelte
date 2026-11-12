<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { user } from '#lib/api/user.svelte.js';
	import ModeSwitch from '#lib/components/blocks/ModeSwitch.svelte';
	import AuthCard from '#lib/components/blocks/AuthCard.svelte';
	import LegalLinks from '#lib/components/blocks/LegalLinks.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import { LockOpen } from '@lucide/svelte';
	import { fade } from 'svelte/transition';

	let { children } = $props();

	// Session cookies and passkeys need https, so no sign-in can work without it. http://localhost counts as secure.
	const insecure = !window.isSecureContext;
	// The same address on https only exists on the default port.
	const secureURL = location.port
		? ''
		: `https://${location.host}${location.pathname}${location.search}`;

	const redirectRoutes = ['/login', '/signup'];
	const currentUser = user.self();

	$effect(() => {
		if (currentUser.isSuccess && currentUser.data && redirectRoutes.includes(page.url.pathname)) {
			goto('/');
		}
	});
</script>

<div class="flex min-h-dvh flex-col" in:fade={{ duration: 200 }}>
	<main class="flex w-full flex-1 flex-col items-center justify-center p-4">
		{#if insecure}
			<AuthCard
				title="Nokku needs https"
				description="This page was opened over plain http, so signing in cannot work. Open it over https. If that fails, the reverse proxy in front of Nokku has no certificate yet."
				icon={LockOpen}
				tone="destructive"
			>
				{#if secureURL}
					<Button href={secureURL} class="w-full">Open over https</Button>
				{/if}
			</AuthCard>
		{:else}
			{@render children?.()}
		{/if}
	</main>
	<footer class="flex items-center justify-between gap-4 px-4 py-3">
		<LegalLinks />
		<ModeSwitch />
	</footer>
</div>
