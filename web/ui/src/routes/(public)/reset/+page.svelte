<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { auth } from '#lib/api/auth.svelte.js';
	import { formatConnectError } from '#lib/api/error-formatter.js';
	import AuthCard from '#lib/components/blocks/AuthCard.svelte';
	import * as Alert from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import InputGroupVariants from '#lib/components/blocks/InputGroupVariants.svelte';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import { ConnectError } from '@connectrpc/connect';
	import { CircleAlert, CircleCheckBig, KeyRound, LogIn } from '@lucide/svelte';

	const token = page.url.searchParams.get('token');
	let newPassword = $state('');
	let confirmPassword = $state('');

	$effect(() => {
		if (!token) goto('/login');
	});

	const resetPassword = auth.resetPassword();
	const passwordsMatch = $derived(newPassword === confirmPassword && newPassword.length > 0);
	const isPasswordValid = $derived(newPassword.length >= 8);
	const canSubmit = $derived(passwordsMatch && isPasswordValid && !resetPassword.isPending);
	const error = $derived(
		resetPassword.error ? formatConnectError(ConnectError.from(resetPassword.error)) : undefined
	);

	function submit(e: SubmitEvent) {
		e.preventDefault();
		if (!canSubmit || !token) return;
		resetPassword.mutate({ token, newPassword });
	}
</script>

{#if resetPassword.isSuccess}
	<AuthCard
		title="Password updated"
		description="Sign in with your new password. Every session was signed out, including nk."
		icon={CircleCheckBig}
		tone="success"
	>
		<Button href="/login">
			<LogIn data-icon="inline-start" />
			Sign in
		</Button>
	</AuthCard>
{:else}
	<AuthCard title="Set a new password" description="At least 8 characters" icon={KeyRound}>
		<form class="flex flex-col gap-4" onsubmit={submit}>
			{#if error}
				<Alert.Root variant="destructive">
					<CircleAlert />
					<Alert.Title>{error.title}</Alert.Title>
					{#if error.description}<Alert.Description>{error.description}</Alert.Description>{/if}
				</Alert.Root>
			{/if}
			<Field.Group class="gap-4">
				<Field.Field data-invalid={newPassword.length > 0 && !isPasswordValid ? true : undefined}>
					<Field.Label for="password">New password</Field.Label>
					<InputGroupVariants
						variant="password"
						bind:value={newPassword}
						placeholder="At least 8 characters"
						inputProps={{ id: 'password', required: true, autocomplete: 'new-password' }}
					/>
					{#if newPassword.length > 0 && !isPasswordValid}
						<Field.Error>Use at least 8 characters.</Field.Error>
					{/if}
				</Field.Field>
				<Field.Field
					data-invalid={confirmPassword.length > 0 && !passwordsMatch ? true : undefined}
				>
					<Field.Label for="confirm-password">Confirm password</Field.Label>
					<InputGroupVariants
						variant="password"
						bind:value={confirmPassword}
						placeholder="Same again"
						inputProps={{ id: 'confirm-password', required: true, autocomplete: 'new-password' }}
					/>
					{#if confirmPassword.length > 0 && !passwordsMatch}
						<Field.Error>The passwords do not match.</Field.Error>
					{/if}
				</Field.Field>
			</Field.Group>
			<Button type="submit" disabled={!canSubmit}>
				{#if resetPassword.isPending}<Spinner data-icon="inline-start" />{/if}
				Set password
			</Button>
		</form>
	</AuthCard>
{/if}
