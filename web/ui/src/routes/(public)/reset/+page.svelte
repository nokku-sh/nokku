<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { auth } from '$lib/api/auth.svelte';
	import { Button } from '$lib/components/ui/button/index.js';
	import { InputGroupVariants } from '$lib/components/ui/input-group';
	import { Label } from '$lib/components/ui/label/index.js';
	import { CircleAlert, CircleCheckBig, KeyRound, RefreshCw, Undo2Icon } from '@lucide/svelte';

	// State
	const token = page.url.searchParams.get('token');
	let newPassword = $state('');
	let confirmPassword = $state('');

	// Get token from URL params
	$effect(() => {
		if (!token) goto('/login');
	});

	// Password validation
	const resetPassword = auth.resetPassword();
	const passwordsMatch = $derived(newPassword === confirmPassword && newPassword.length > 0);
	const isPasswordValid = $derived(newPassword.length >= 8);
	const canSubmit = $derived(passwordsMatch && isPasswordValid && !resetPassword.isPending);

	async function handleResetPassword() {
		if (!canSubmit || !token) return;
		resetPassword.mutate({ token, newPassword });
	}
</script>

<section class="flex flex-col dark:bg-transparent">
	{#if !resetPassword.isSuccess}
		<form
			onsubmit={handleResetPassword}
			class="m-auto h-fit w-full max-w-sm overflow-hidden rounded-[calc(var(--radius)+.125rem)] border bg-muted shadow-md shadow-zinc-950/5 dark:[--color-muted:var(--color-zinc-900)]"
		>
			<div
				class="-m-px flex flex-col gap-4 rounded-[calc(var(--radius)+.125rem)] border bg-card p-6"
			>
				<div class="flex flex-col items-center text-center">
					<div class="mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
						<KeyRound size={24} class="text-primary" />
					</div>
					<h1 class="text-2xl font-bold">Set new password</h1>
					<p class="text-balance text-muted-foreground">Enter your new password below</p>
				</div>

				{#if resetPassword.isError}
					<div class="rounded-lg border border-destructive/20 bg-destructive/5 p-3">
						<div class="flex items-center gap-2 text-sm text-destructive">
							<CircleAlert size={16} />
							{resetPassword.error}
						</div>
					</div>
				{/if}

				<div class="space-y-2">
					<Label for="password">New password</Label>
					<InputGroupVariants
						variant="password"
						bind:value={newPassword}
						placeholder="Enter new password"
						inputProps={{ required: true, autocomplete: 'new-password' }}
					/>
					{#if newPassword.length > 0 && !isPasswordValid}
						<p class="text-sm text-destructive">Password must be at least 8 characters</p>
					{/if}
				</div>

				<div class="space-y-2">
					<Label for="confirmPassword">Confirm password</Label>
					<InputGroupVariants
						variant="password"
						bind:value={confirmPassword}
						placeholder="Confirm new password"
						inputProps={{ required: true, autocomplete: 'new-password' }}
					/>
					{#if confirmPassword.length > 0 && !passwordsMatch}
						<p class="text-sm text-destructive">Passwords do not match</p>
					{/if}
				</div>

				<Button type="submit" class="w-full" disabled={!canSubmit}>
					{#if resetPassword.isPending}
						<RefreshCw size={16} class="animate-spin" />
						Resetting password...
					{:else}
						Reset password
					{/if}
				</Button>
			</div>

			<div class="p-3">
				<Button variant="link" class="w-full" href="/login" disabled={resetPassword.isPending}>
					Go back to login
					<Undo2Icon size={16} />
				</Button>
			</div>
		</form>
	{:else}
		<div
			class="m-auto h-fit w-full max-w-sm overflow-hidden rounded-[calc(var(--radius)+.125rem)] border bg-muted shadow-md shadow-zinc-950/5 dark:[--color-muted:var(--color-zinc-900)]"
		>
			<div
				class="-m-px flex flex-col gap-4 rounded-[calc(var(--radius)+.125rem)] border bg-card p-6 md:p-8"
			>
				<div class="flex flex-col items-center text-center">
					<div class="mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
						<CircleCheckBig class="text-primary" size={22} />
					</div>
					<h1 class="text-2xl font-bold">Success</h1>
					<p class="text-balance text-muted-foreground">
						Your password has been successfully updated
					</p>
				</div>
				<div class="rounded-lg bg-muted p-4 text-sm text-muted-foreground">
					<p class="mb-2 font-medium">What's next?</p>
					<ul class="space-y-1">
						<li>• You can now log in with your new password</li>
						<li>• Make sure to keep your password secure</li>
						<li>• Consider enabling two-factor authentication</li>
					</ul>
				</div>
			</div>

			<div class="p-3">
				<Button variant="link" class="w-full" href="/login" disabled={resetPassword.isPending}>
					Continue to login
					<Undo2Icon size={16} />
				</Button>
			</div>
		</div>
	{/if}

	<div class="mt-6 text-center text-xs text-balance text-muted-foreground">
		By continuing, you agree to our
		<a href="##" class="underline underline-offset-4 hover:text-primary">Terms of Service</a> and
		<a href="##" class="underline underline-offset-4 hover:text-primary">Privacy Policy</a>.
	</div>
</section>
