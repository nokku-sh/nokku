<script lang="ts">
	import { page } from '$app/state';
	import { user } from '$lib/api/user.svelte';
	import { pendingDeviceCode } from '$lib/store.svelte';
	import { Button } from '$lib/components/ui/button';
	import * as Alert from '$lib/components/ui/alert';
	import * as Field from '$lib/components/ui/field';
	import * as InputOTP from '$lib/components/ui/input-otp';
	import { Spinner } from '$lib/components/ui/spinner';
	import AuthCard from '$lib/components/blocks/AuthCard.svelte';
	import { REGEXP_ONLY_DIGITS_AND_CHARS } from 'bits-ui';
	import { Check, LogIn, MonitorSmartphone, ShieldAlert, TriangleAlert, X } from '@lucide/svelte';

	const currentUser = user.self();

	type DeviceVerifyResponse = { status?: string; error?: string };

	const initialCode = (page.url.searchParams.get('user_code') ?? '').toUpperCase().trim();

	let code = $state(initialCode);
	// The OTP input holds the 8 characters, the dash is only for display.
	let input = $state(initialCode.replace(/[^A-Z0-9]/g, ''));
	const formatted = $derived(input.length > 4 ? `${input.slice(0, 4)}-${input.slice(4)}` : input);
	let submitting = $state(false);
	let result = $state<'success' | 'error' | 'denied' | null>(null);
	let message = $state('');

	function deny() {
		result = 'denied';
		message = 'Authorization request denied.';
		pendingDeviceCode.current = undefined;
		history.replaceState(null, '', '/device');
		submit('/auth/device/deny');
	}

	function apply() {
		code = formatted;
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

<AuthCard
	title="Authorize a device"
	description={initialCode && currentUser.data && !result
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
		<Button variant="outline" onclick={() => (result = null)}>Try again</Button>
	{:else if initialCode}
		<div class="flex flex-col items-center gap-1 rounded-lg border bg-terminal p-5">
			<span class="spec-label">Device code</span>
			<span class="font-mono text-3xl font-bold tracking-widest text-terminal-accent">
				{formatted}
			</span>
		</div>
		<Alert.Root variant="warning">
			<ShieldAlert />
			<Alert.Description>Approve only if this matches your terminal exactly.</Alert.Description>
		</Alert.Root>
		<div class="flex flex-col gap-2">
			<Button onclick={apply} disabled={submitting}>
				{#if submitting}<Spinner data-icon="inline-start" />{:else}<Check
						data-icon="inline-start"
					/>{/if}
				Approve
			</Button>
			<Button variant="ghost" onclick={deny} disabled={submitting}>Deny</Button>
		</div>
	{:else}
		<form
			class="flex flex-col gap-4"
			onsubmit={(e) => {
				e.preventDefault();
				if (input.length === 8) apply();
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
			<Button type="submit" disabled={submitting || input.length < 8}>
				{#if submitting}<Spinner data-icon="inline-start" />{/if}
				Continue
			</Button>
		</form>
	{/if}

	{#snippet footer()}
		<a href="/login" class="font-medium text-primary hover:underline">Use a different account</a>
	{/snippet}
</AuthCard>
