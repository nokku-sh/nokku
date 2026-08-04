<script lang="ts">
	import { Button } from '$lib/components/ui/button/index.js';
	import { Input } from '$lib/components/ui/input/index.js';
	import { CircleCheck, CircleX, RefreshCw, Mail, Undo2Icon } from '@lucide/svelte';
	import { page } from '$app/state';
	import { auth } from '$lib/api/auth.svelte';

	// State
	let token = page.url.searchParams.get('token');
	let email = $state('');

	const verifyEmail = auth.verifyEmail();
	const resendVerification = auth.resendVerification();

	// Auto-verify when component loads
	$effect(() => {
		if (token) verifyEmail.mutate({ token });
	});
</script>

<div
	class="m-auto h-fit w-full max-w-sm overflow-hidden rounded-[calc(var(--radius)+.125rem)] border bg-muted shadow-md shadow-zinc-950/5 dark:[--color-muted:var(--color-zinc-900)]"
>
	<div class="-m-px flex flex-col gap-4 rounded-[calc(var(--radius)+.125rem)] border bg-card p-6">
		{#if verifyEmail.isPending}
			<!-- Loading State -->
			<div class="flex flex-col items-center text-center">
				<div class="mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
					<RefreshCw size={24} class="animate-spin text-primary" />
				</div>
				<h1 class="text-2xl font-bold">Verifying your email</h1>
				<p class="text-balance text-muted-foreground">
					Please wait while we verify your email address...
				</p>
			</div>
		{:else if verifyEmail.isSuccess}
			<!-- Success State -->
			<div class="flex flex-col gap-5">
				<div class="flex flex-col items-center text-center">
					<div class="mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-chart-3">
						<CircleCheck size={24} class="text-muted" />
					</div>
					<h1 class="text-2xl font-bold">Email verified!</h1>
					<p class="text-balance text-muted-foreground">
						Your email address has been successfully verified. You can now sign in to your account.
					</p>
				</div>

				<div class="rounded-lg bg-muted p-4 text-sm text-muted-foreground">
					<p class="mb-2 font-medium">What's next?</p>
					<ul class="space-y-1">
						<li>• Your account is now fully activated</li>
						<li>• Sign in to get started</li>
					</ul>
				</div>

				<Button variant="link" class="w-full" href="/login">Continue to Sign In</Button>
			</div>
		{:else if verifyEmail.isError}
			<!-- Error State -->
			<div class="flex flex-col gap-5">
				<div class="flex flex-col items-center text-center">
					<div class="mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-chart-2">
						<CircleX size={24} class="text-muted" />
					</div>
					<h1 class="text-2xl font-bold">Verification failed</h1>
					<p class="text-balance text-muted-foreground">
						{verifyEmail.error}
					</p>
				</div>

				<div class="rounded-lg bg-muted p-4 text-sm text-muted-foreground">
					<p class="mb-2 font-medium">What can you do?</p>
					<ul class="space-y-1">
						<li>• Check if the link is complete and not broken</li>
						<li>• The verification link may have expired</li>
						<li>• Request a new verification email</li>
						<li>• Contact support if the problem persists</li>
					</ul>
				</div>

				<div class="space-y-4">
					<Input
						id="email"
						type="email"
						bind:value={email}
						placeholder="Enter your email"
						required
					/>
					<Button
						variant="outline"
						type="button"
						class="w-full"
						onclick={() => resendVerification.mutate({ email })}
					>
						<Mail size={16} />
						Send a new verification link
					</Button>
				</div>
			</div>
		{:else if page.url.searchParams.has('sent')}
			<div class="flex flex-col gap-5">
				<div class="flex flex-col items-center text-center">
					<div class="mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-chart-3">
						<Mail size={24} class="text-muted" />
					</div>
					<h1 class="text-2xl font-bold">Check your email</h1>
					<p class="text-balance text-muted-foreground">
						We've sent a verification link to your email. Click the link to activate your account.
					</p>
				</div>

				<div class="rounded-lg bg-muted p-4 text-sm text-muted-foreground">
					<p class="mb-2 font-medium">Didn't receive the email?</p>
					<ul class="space-y-1">
						<li>• Check your spam or junk folder</li>
						<li>• Make sure you entered the correct email address</li>
						<li>• The link expires after 15 minutes</li>
					</ul>
				</div>

				<div class="space-y-4">
					<Input
						id="email"
						type="email"
						bind:value={email}
						placeholder="Enter your email"
						required
					/>
					<Button
						variant="outline"
						type="button"
						class="w-full"
						onclick={() => resendVerification.mutate({ email })}
					>
						<Mail size={16} />
						Resend verification email
					</Button>
				</div>
			</div>
		{:else}
			<div class="flex flex-col gap-5">
				<div class="flex flex-col items-center text-center">
					<div class="mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-chart-2">
						<CircleX size={24} class="text-muted" />
					</div>
					<h1 class="text-2xl font-bold">No token found</h1>
					<p class="text-balance text-muted-foreground">Please provide a verification token</p>
				</div>
			</div>
		{/if}
	</div>

	<div class="p-3">
		<Button variant="link" class="w-full" href="/login" disabled={verifyEmail.isPending}>
			Go back to login
			<Undo2Icon size={16} />
		</Button>
	</div>
</div>
