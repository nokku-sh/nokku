<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { user } from '$lib/api/user.svelte';
	import ModeSwitch from '$lib/components/utils/ModeSwitch.svelte';
	import { fade } from 'svelte/transition';

	let { children } = $props();

	const redirectRoutes = ['/login', '/register', '/verify', '/recovery', '/reset'];
	const currentUser = user.self();

	$effect(() => {
		// Only redirect if user is authenticated AND on a public-only route
		if (currentUser.isSuccess && currentUser.data && redirectRoutes.includes(page.url.pathname)) {
			goto('/');
		}
	});
</script>

<main class="flex min-h-screen w-full items-center justify-center" in:fade={{ duration: 200 }}>
	{@render children?.()}

	<ModeSwitch class="fixed right-2 bottom-2" />
</main>
