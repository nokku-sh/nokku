<script lang="ts">
	import { page } from '$app/state';
	import { user } from '$lib/api/user.svelte';
	import { pendingDeviceCode } from '$lib/store.svelte';
	import { Button } from '$lib/components/ui/button/index.js';
	import * as Alert from '$lib/components/ui/alert';
	import { Check, LoaderCircle, TriangleAlert, X } from '@lucide/svelte';
	import Logo from '$lib/assets/logo.svelte';

	const currentUser = user.self();

	type DeviceVerifyResponse = { status?: string; error?: string };

	let code = $state((page.url.searchParams.get('user_code') ?? '').toUpperCase().trim());
	let input = $state('');
	let submitting = $state(false);
	let result = $state<'success' | 'error' | null>(null);
	let message = $state('');
	let submitted = false;

	function normalize(value: string) {
		const cleaned = value.toUpperCase().replace(/[^A-Z0-9]/g, '');
		return `${cleaned.slice(0, 4)}-${cleaned.slice(4, 8)}`.replace(/-$/, '').trim();
	}

	function onInput() {
		input = normalize(input);
	}

	function apply() {
		code = input.trim();
		if (code) pendingDeviceCode.current = code;
		history.replaceState(null, '', code ? `/device?user_code=${code}` : '/device');
		submit();
	}

	function submit() {
		if (!code || submitting) return;
		submitting = true;
		result = null;
		message = '';

		fetch('/auth/device/verify', {
			method: 'POST',
			credentials: 'include',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ user_code: code })
		})
			.then(async (response) => {
				const body = (await response.json()) as DeviceVerifyResponse;
				if (response.ok) {
					result = 'success';
					message = 'Device authorized — you can close this tab and return to your terminal.';
					pendingDeviceCode.current = undefined;
				} else {
					result = 'error';
					message =
						body.error === 'invalid or expired code'
							? 'This code is invalid or has expired. Start the login again in your CLI.'
							: (body.error ?? 'Something went wrong. Please try again.');
				}
			})
			.catch(() => {
				result = 'error';
				message = 'Something went wrong. Please try again.';
			})
			.finally(() => {
				submitting = false;
			});
	}

	// Auto-submit once the user is signed in and a code is present.
	$effect(() => {
		if (submitted || !currentUser.data || !code) return;
		submitted = true;
		submit();
	});

	// Remember the code across the sign-in round trip so the app layout can
	// bring the user back here after authenticating.
	$effect(() => {
		if (code && !currentUser.isLoading && !currentUser.data) {
			pendingDeviceCode.current = code;
		}
	});
</script>

<div
	class="m-auto h-fit w-full max-w-sm overflow-hidden rounded-[calc(var(--radius)+.125rem)] border bg-muted shadow-md shadow-zinc-950/5 dark:[--color-muted:var(--color-zinc-900)]"
>
	<div class="-m-px rounded-[calc(var(--radius)+.125rem)] border bg-card p-6 pb-6">
		<div class="text-center">
			<Logo class="mx-auto block w-10 py-2 dark:invert" />
			<h1 class="mt-4 mb-1 text-xl font-semibold">Authorize Device</h1>
			<p class="text-sm text-balance text-muted-foreground">
				Enter the code shown in your terminal to sign in with the nokku CLI.
			</p>
		</div>

		<div class="mt-6">
			{#if !currentUser.data}
				<Alert.Root variant="default">
					<TriangleAlert />
					<Alert.Title>Sign in to continue</Alert.Title>
					<Alert.Description>
						You need to be signed in to authorize a device. We'll bring you back here after you sign
						in.
					</Alert.Description>
				</Alert.Root>

				<div class="mt-4">
					<Button href="/login" class="w-full">Sign in</Button>
				</div>
			{:else}
				{#if result === 'success'}
					<div class="flex flex-col items-center gap-3 py-2 text-center">
						<div class="flex h-12 w-12 items-center justify-center rounded-full bg-emerald-500/10">
							<Check size={24} class="text-emerald-500" />
						</div>
						<p class="text-sm text-muted-foreground">{message}</p>
					</div>
				{:else if result === 'error'}
					<Alert.Root variant="destructive">
						<X />
						<Alert.Title>Could not authorize device</Alert.Title>
						<Alert.Description>{message}</Alert.Description>
					</Alert.Root>
				{:else}
					<div class="space-y-2">
						<label for="device-code" class="text-sm font-medium"> Code </label>
						<input
							id="device-code"
							type="text"
							bind:value={input}
							oninput={onInput}
							onkeydown={(event) => event.key === 'Enter' && !submitting && apply()}
							placeholder="ABCD-EFGH"
							autocomplete="off"
							spellcheck={false}
							maxlength={9}
							class="w-full rounded-md border bg-transparent px-3 py-2.5 text-center font-mono text-lg tracking-widest uppercase outline-none focus:ring-2 focus:ring-ring"
						/>
					</div>

					<Button class="mt-4 w-full" onclick={apply} disabled={submitting || !input}>
						{#if submitting}
							<LoaderCircle class="size-4 animate-spin" /> Authorizing...
						{:else}
							<Check class="size-4" /> Authorize
						{/if}
					</Button>
				{/if}
			{/if}
		</div>
	</div>

	<div class="p-3">
		<p class="text-center text-sm text-accent-foreground">
			<Button href="/login" variant="link" class="px-2">Sign in to a different account</Button>
		</p>
	</div>
</div>
