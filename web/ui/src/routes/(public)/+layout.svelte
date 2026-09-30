<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { user } from '$lib/api/user.svelte';
	import ModeSwitch from '$lib/components/blocks/ModeSwitch.svelte';
	import LegalLinks from '$lib/components/blocks/LegalLinks.svelte';
	import { fade } from 'svelte/transition';

	let { children } = $props();

	const redirectRoutes = ['/login', '/register', '/verify', '/recovery', '/reset'];
	const currentUser = user.self();

	$effect(() => {
		if (currentUser.isSuccess && currentUser.data && redirectRoutes.includes(page.url.pathname)) {
			goto('/');
		}
	});
</script>

<div class="flex min-h-dvh flex-col" in:fade={{ duration: 200 }}>
	<main class="flex w-full flex-1 flex-col items-center justify-center p-4">
		{@render children?.()}
	</main>
	<footer class="flex items-center justify-between gap-4 px-4 py-3">
		<LegalLinks />
		<ModeSwitch />
	</footer>
</div>
