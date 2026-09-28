<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { user } from '$lib/api/user.svelte';
	import ModeSwitch from '$lib/components/utils/ModeSwitch.svelte';
	import { PrivacyURL, ToSURL } from '$lib/config';
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

<main class="flex min-h-screen w-full items-center justify-center" in:fade={{ duration: 200 }}>
	<section class="flex flex-col p-4">
		{@render children?.()}

		<div class="mt-6 text-center text-xs text-balance text-muted-foreground">
			By clicking continue, you agree to our
			<a
				href={ToSURL}
				class="underline underline-offset-4 hover:text-primary"
				target="_blank"
				rel="noopener noreferrer">Terms of Service</a
			>
			and
			<a
				href={PrivacyURL}
				class="underline underline-offset-4 hover:text-primary"
				target="_blank"
				rel="noopener noreferrer">Privacy Policy</a
			>.
		</div>
	</section>

	<ModeSwitch class="fixed right-2 bottom-2" />
</main>
