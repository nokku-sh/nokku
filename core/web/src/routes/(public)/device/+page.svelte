<script lang="ts">
	import { page } from '$app/state';
	import { createQuery } from '@tanstack/svelte-query';
	import { user } from '#lib/api/user.svelte.js';
	import { leave } from '#lib/api/client.js';
	import { pendingDeviceCode } from '#lib/store.svelte.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Alert from '#lib/components/ext/alert/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import * as InputOTP from '#lib/components/ui/input-otp/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import AuthCard from '#lib/components/blocks/AuthCard.svelte';
	import { REGEXP_ONLY_DIGITS_AND_CHARS } from 'bits-ui';
	import { Check, LogIn, MonitorSmartphone, ShieldAlert, TriangleAlert, X } from '@lucide/svelte';

	const currentUser = user.self();

	type DeviceVerifyResponse = { status?: string; message?: string; redirect?: string };
	// loopback: nk waits on 127.0.0.1 and only a browser on its machine can hand it the answer.
	type DeviceRequester = { ip: string; user_agent: string; loopback: boolean };

	const initialCode = (page.url.searchParams.get('user_code') ?? '').toUpperCase().trim();

	let code = $state(initialCode);
	// The OTP input holds the 8 characters, the dash is only for display.
	let input = $state('');
	// A headless code is approved only when typed here, a link can come from anyone.
	let typed = $state(false);
	const formatted = $derived(input.length > 4 ? `${input.slice(0, 4)}-${input.slice(4)}` : input);
	let submitting = $state(false);
	let result = $state<'success' | 'error' | 'denied' | null>(null);
	let message = $state('');

	// Who asked for the code. Approve waits for it, so nobody approves blind.
	const requester = createQuery<DeviceRequester>(() => ({
		queryKey: ['device', code],
		queryFn: async () => {
			const response = await fetch(`/auth/device/info?user_code=${encodeURIComponent(code)}`, {
				credentials: 'include'
			});
			if (!response.ok) throw new Error('invalid or expired code');
			return response.json();
		},
		enabled: !!code && !!currentUser.data && !result,
		retry: false
	}));

	function deny() {
		result = 'denied';
		message = 'Authorization request denied.';
		pendingDeviceCode.current = null;
		history.replaceState(null, '', '/device');
		submit('/auth/device/deny');
	}

	function review() {
		code = formatted;
		typed = true;
		history.replaceState(null, '', `/device?user_code=${code}`);
	}

	function reset() {
		result = null;
		code = '';
		input = '';
		typed = false;
		history.replaceState(null, '', '/device');
	}

	const showCode = $derived(!!code && (!requester.data || requester.data.loopback || typed));

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
				// An old session must sign in again to approve, the code waits for it.
				if (response.status === 401 && !denied) {
					pendingDeviceCode.current = code;
					leave();
					return;
				}
				const body = (await response.json()) as DeviceVerifyResponse;
				if (response.ok) {
					pendingDeviceCode.current = null;
					// The answer goes to nk on this machine. On another one nothing listens there.
					if (body.redirect?.startsWith('http://127.0.0.1:')) {
						window.location.assign(body.redirect);
					}
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
						body.message === 'invalid or expired code'
							? 'This code is invalid or has expired. Start the login again in your terminal.'
							: (body.message ?? 'Something went wrong. Please try again.');
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

<AuthCard
	title="Authorize a device"
	description={showCode && currentUser.data && !result
		? 'A terminal wants to sign in to your Nokku account.'
		: 'Enter the code your terminal shows.'}
	icon={MonitorSmartphone}
>
	{#if !currentUser.data}
		<Alert.Root>
			<TriangleAlert />
			<Alert.Title>Sign in first</Alert.Title>
			<Alert.Description>We bring you back here right after.</Alert.Description>
		</Alert.Root>
		<Button href="/login">
			<LogIn data-icon="inline-start" />
			Sign in
		</Button>
	{:else if result === 'success'}
		<Alert.Root variant="success">
			<Check />
			<Alert.Title>Device authorized</Alert.Title>
			<Alert.Description>Close this tab and head back to your terminal.</Alert.Description>
		</Alert.Root>
	{:else if result === 'denied'}
		<Alert.Root variant="destructive">
			<X />
			<Alert.Title>Request denied</Alert.Title>
			<Alert.Description>The terminal was not signed in.</Alert.Description>
		</Alert.Root>
	{:else if result === 'error'}
		<Alert.Root variant="destructive">
			<X />
			<Alert.Title>Authorization failed</Alert.Title>
			<Alert.Description>{message}</Alert.Description>
		</Alert.Root>
		<Button variant="outline" onclick={reset}>Try again</Button>
	{:else if showCode}
		<div class="flex flex-col items-center gap-1 rounded-lg border bg-terminal p-5">
			<span class="spec-label">Device code</span>
			<span class="font-mono text-3xl font-bold tracking-widest text-terminal-accent">
				{code}
			</span>
		</div>
		{#if requester.isError}
			<Alert.Root variant="destructive">
				<X />
				<Alert.Title>Code not found</Alert.Title>
				<Alert.Description>
					This code is invalid or has expired. Start the login again in your terminal.
				</Alert.Description>
			</Alert.Root>
			<Button variant="outline" onclick={reset}>Enter another code</Button>
		{:else}
			{#if requester.data}
				<dl class="flex flex-col gap-2 rounded-lg border p-4 text-sm">
					<div class="flex justify-between gap-4">
						<dt class="text-muted-foreground">Requested from</dt>
						<dd class="font-mono">{requester.data.ip || 'unknown'}</dd>
					</div>
					<div class="flex justify-between gap-4">
						<dt class="text-muted-foreground">Client</dt>
						<dd class="truncate font-mono">{requester.data.user_agent || 'unknown'}</dd>
					</div>
				</dl>
			{:else}
				<Skeleton class="h-20 w-full" />
			{/if}
			<Alert.Root variant="warning">
				<ShieldAlert />
				<Alert.Description>
					Approve only if you started this sign-in and the code matches your terminal exactly.
				</Alert.Description>
			</Alert.Root>
			<div class="flex flex-col gap-2">
				<Button onclick={() => submit()} disabled={submitting || !requester.data}>
					{#if submitting}<Spinner data-icon="inline-start" />{:else}<Check
							data-icon="inline-start"
						/>{/if}
					Approve
				</Button>
				<Button variant="ghost" onclick={deny} disabled={submitting}>Deny</Button>
			</div>
		{/if}
	{:else}
		{#if code}
			<Alert.Root variant="warning">
				<ShieldAlert />
				<Alert.Title>Type the code yourself</Alert.Title>
				<Alert.Description>
					This sign-in came from a machine without a browser, so a link can't approve it. Type the
					code your terminal shows. If you didn't start a sign-in, close this tab.
				</Alert.Description>
			</Alert.Root>
		{/if}
		<form
			class="flex flex-col gap-4"
			onsubmit={(e) => {
				e.preventDefault();
				if (input.length === 8) review();
			}}
		>
			<Field.Field>
				<Field.Label for="device-code">Code</Field.Label>
				<InputOTP.Root
					id="device-code"
					class="w-full"
					maxlength={8}
					pattern={REGEXP_ONLY_DIGITS_AND_CHARS}
					bind:value={() => input, (v) => (input = v.toUpperCase())}
					pasteTransformer={(text) => text.toUpperCase().replace(/[^A-Z0-9]/g, '')}
				>
					{#snippet children({ cells })}
						<div class="flex w-full items-center gap-2">
							<InputOTP.Group class="flex-1">
								{#each cells.slice(0, 4) as cell, i (i)}
									<InputOTP.Slot {cell} class="h-11 flex-1 font-mono text-base" />
								{/each}
							</InputOTP.Group>
							<InputOTP.Separator />
							<InputOTP.Group class="flex-1">
								{#each cells.slice(4, 8) as cell, i (i)}
									<InputOTP.Slot {cell} class="h-11 flex-1 font-mono text-base" />
								{/each}
							</InputOTP.Group>
						</div>
					{/snippet}
				</InputOTP.Root>
			</Field.Field>
			<Button type="submit" disabled={input.length < 8}>Continue</Button>
		</form>
	{/if}

	{#snippet footer()}
		<a href="/login" class="font-medium text-primary hover:underline">Use a different account</a>
	{/snippet}
</AuthCard>
