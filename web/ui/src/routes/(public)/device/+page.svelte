<script lang="ts">
	import { page } from '$app/state';
	import { user } from '$lib/api/user.svelte';
	import { pendingDeviceCode } from '$lib/store.svelte';
	import { Button } from '$lib/components/ui/button/index.js';
	import * as Alert from '$lib/components/ui/alert';
	import { Check, LoaderCircle, TriangleAlert, X, ShieldAlert } from '@lucide/svelte';
	import Logo from '$lib/assets/logo.svelte';

	const currentUser = user.self();

	type DeviceVerifyResponse = { status?: string; error?: string };

	const initialCode = (page.url.searchParams.get('user_code') ?? '').toUpperCase().trim();

	let code = $state(initialCode);
	let input = $state(initialCode);
	let submitting = $state(false);
	let result = $state<'success' | 'error' | 'denied' | null>(null);
	let message = $state('');

	function normalize(value: string) {
		const cleaned = value.toUpperCase().replace(/[^A-Z0-9]/g, '');
		return `${cleaned.slice(0, 4)}-${cleaned.slice(4, 8)}`.replace(/-$/, '').trim();
	}

	function onInput() {
		input = normalize(input);
	}

	function deny() {
		result = 'denied';
		message = 'Authorization request denied.';
		pendingDeviceCode.current = undefined;
		history.replaceState(null, '', '/device');
		submit('/auth/device/deny');
	}

	function apply() {
		code = input.trim();
		if (code) pendingDeviceCode.current = code;
		history.replaceState(null, '', code ? `/device?user_code=${code}` : '/device');
		submit();
	}

	function submit(path = '/auth/device/verify') {
		if (!code || submitting) return;
		submitting = true;
		result = null;
		message = '';

		const denied = path.endsWith('/deny');
		fetch(path, {
			method: 'POST',
			credentials: 'include',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ user_code: code })
		})
			.then(async (response) => {
				const body = (await response.json()) as DeviceVerifyResponse;
				if (response.ok) {
					pendingDeviceCode.current = undefined;
					if (denied) {
						result = 'denied';
						message = 'Authorization request denied.';
					} else {
						result = 'success';
						message = 'Device authorized! You can close this tab and return to your terminal.';
					}
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
				{#if initialCode && currentUser.data && !result}
					A device is requesting access to your nokku account.
				{:else}
					Enter the code shown in your terminal to sign in.
				{/if}
			</p>
		</div>

		<div class="mt-6">
			{#if !currentUser.data}
				<Alert.Root variant="default">
					<TriangleAlert class="size-4" />
					<Alert.Title>Sign in to continue</Alert.Title>
					<Alert.Description>
						You need to be signed in to authorize a device. We'll bring you back here after.
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
						<p class="text-sm font-medium text-emerald-600 dark:text-emerald-400">Success!</p>
						<p class="text-sm text-muted-foreground">{message}</p>
					</div>
				{:else if result === 'denied'}
					<div class="flex flex-col items-center gap-3 py-2 text-center">
						<div class="flex h-12 w-12 items-center justify-center rounded-full bg-rose-500/10">
							<X size={24} class="text-rose-500" />
						</div>
						<p class="text-sm font-medium text-rose-600 dark:text-rose-400">Denied</p>
						<p class="text-sm text-muted-foreground">Authorization request denied.</p>
					</div>
				{:else if result === 'error'}
					<Alert.Root variant="destructive">
						<X class="size-4" />
						<Alert.Title>Authorization failed</Alert.Title>
						<Alert.Description>{message}</Alert.Description>
					</Alert.Root>
					<Button variant="outline" class="mt-4 w-full" onclick={() => (result = null)}>
						Try Again
					</Button>
				{:else}
					{#if initialCode}
						<div class="rounded-lg border bg-muted/50 p-6 text-center">
							<p class="mb-2 text-xs font-semibold tracking-wider text-muted-foreground uppercase">
								Device Code
							</p>
							<div class="font-mono text-3xl font-bold tracking-widest text-foreground">
								{input}
							</div>
						</div>

						<div
							class="mt-4 flex items-start gap-3 rounded-md bg-amber-500/10 p-3 text-amber-600 dark:bg-amber-500/20 dark:text-amber-400"
						>
							<ShieldAlert class="mt-0.5 size-4 shrink-0" />
							<p class="text-xs leading-relaxed">
								Verify that this code exactly matches the one displayed in your terminal before
								approving.
							</p>
						</div>

						<div class="mt-6 flex flex-col gap-2">
							<Button class="w-full" onclick={apply} disabled={submitting}>
								{#if submitting}
									<LoaderCircle class="mr-2 size-4 animate-spin" /> Authorizing...
								{:else}
									<Check class="mr-2 size-4" /> Approve Access
								{/if}
							</Button>
							<Button variant="ghost" class="w-full" onclick={deny} disabled={submitting}>
								Deny
							</Button>
						</div>
					{:else}
						<div class="space-y-2">
							<label for="device-code" class="text-sm font-medium"> Enter Code </label>
							<input
								id="device-code"
								type="text"
								bind:value={input}
								oninput={onInput}
								onkeydown={(event) =>
									event.key === 'Enter' && !submitting && input.length >= 8 && apply()}
								placeholder="ABCD-EFGH"
								autocomplete="off"
								spellcheck={false}
								maxlength={9}
								class="w-full rounded-md border bg-transparent px-3 py-2.5 text-center font-mono text-lg tracking-widest uppercase outline-none focus:ring-2 focus:ring-ring"
							/>
						</div>

						<Button class="mt-4 w-full" onclick={apply} disabled={submitting || input.length < 8}>
							{#if submitting}
								<LoaderCircle class="mr-2 size-4 animate-spin" /> Authorizing...
							{:else}
								Continue
							{/if}
						</Button>
					{/if}
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
