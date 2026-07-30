<script lang="ts">
	import { goto } from '$app/navigation';
	import { Button } from '$lib/components/ui/button/index.js';
	import { Input } from '$lib/components/ui/input/index.js';
	import { Label } from '$lib/components/ui/label/index.js';
	import { Logo, GoogleIcon, GitHubIcon } from '$lib/assets';
	import { InputGroupVariants } from '$lib/components/ui/input-group';
	import { auth } from '$lib/api/auth.svelte';
	import { signupWithPasskey } from '$lib/api/passkey';
	import { toast } from 'svelte-sonner';
	import { KeyRound, ChevronDown, ChevronUp } from '@lucide/svelte';

	let name = $state('');
	let username = $state('');
	let email = $state('');
	let password = $state('');
	let confirmPassword = $state('');
	let showPassword = $state(false);

	const passwordsMatch = $derived(password === confirmPassword && password.length > 0);
	const isPasswordValid = $derived(password.length >= 8);

	const register = auth.register();
	let isPasskeySignup = $state(false);

	async function handleRegistration() {
		if (!passwordsMatch || !isPasswordValid) return;
		register.mutate({ name, username, email, password });
	}

	async function handlePasskeySignup() {
		if (!email || !username) {
			toast.error('Email and username are required');
			return;
		}

		isPasskeySignup = true;
		try {
			await signupWithPasskey({ email, username, name });
			await goto('/verify?sent=true');
		} catch (error) {
			toast.error(error instanceof Error ? error.message : 'Passkey signup failed');
		} finally {
			isPasskeySignup = false;
		}
	}
</script>

<section class="flex flex-col p-4">
	<div
		class="m-auto h-fit w-full max-w-md overflow-hidden rounded-[calc(var(--radius)+.125rem)] border bg-muted shadow-md shadow-zinc-950/5 dark:[--color-muted:var(--color-zinc-900)]"
	>
		<div class="-m-px rounded-[calc(var(--radius)+.125rem)] border bg-card p-6">
			<div class="text-center">
				<Logo class="mx-auto block w-10 py-2 dark:invert" />
				<h1 class="mt-4 mb-1 text-xl font-semibold">Welcome to Nokku!</h1>
				<p class="text-balance text-muted-foreground">Create an account to get started</p>
			</div>

			<div class="mt-4 space-y-4">
				<div class="space-y-2">
					<Label for="name" class="block text-sm">Full Name</Label>
					<Input
						id="name"
						type="text"
						bind:value={name}
						placeholder="John Doe"
						disabled={register.isPending || isPasskeySignup}
					/>
				</div>

				<div class="space-y-2">
					<Label for="username" class="block text-sm">Username</Label>
					<Input
						id="username"
						type="text"
						bind:value={username}
						placeholder="johndoe"
						required
						disabled={register.isPending || isPasskeySignup}
					/>
				</div>

				<div class="space-y-2">
					<Label for="email" class="block text-sm">Email</Label>
					<Input
						id="email"
						type="email"
						bind:value={email}
						placeholder="johndoe@example.com"
						required
						disabled={register.isPending || isPasskeySignup}
					/>
				</div>

				<Button
					type="button"
					class="w-full"
					onclick={handlePasskeySignup}
					disabled={register.isPending || isPasskeySignup}
				>
					<KeyRound size={16} />
					{isPasskeySignup ? 'Creating Account...' : 'Register with Passkey'}
				</Button>

				<div class="text-center">
					<button
						type="button"
						class="inline-flex cursor-pointer items-center gap-1 text-sm text-muted-foreground underline underline-offset-4 hover:text-primary"
						onclick={() => (showPassword = !showPassword)}
					>
						{#if showPassword}
							<ChevronUp size={14} /> Hide password fields
						{:else}
							<ChevronDown size={14} /> Set a password instead
						{/if}
					</button>
				</div>

				{#if showPassword}
					<form onsubmit={handleRegistration} class="space-y-4">
						<hr class="border-solid" />

						<div class="space-y-2">
							<Label for="password">Password</Label>
							<InputGroupVariants
								variant="password"
								bind:value={password}
								placeholder="Enter new password"
								inputProps={{ required: true, autocomplete: 'new-password' }}
							/>
							{#if password.length > 0 && !isPasswordValid}
								<p class="text-sm text-destructive">Password must be at least 8 characters</p>
							{/if}
						</div>

						<div class="space-y-2">
							<Label for="confirmPassword">Confirm Password</Label>
							<InputGroupVariants
								variant="password"
								bind:value={confirmPassword}
								placeholder="Confirm your password"
								inputProps={{ required: true, autocomplete: 'new-password' }}
							/>
							{#if confirmPassword.length > 0 && !passwordsMatch}
								<p class="text-sm text-destructive">Passwords do not match</p>
							{/if}
						</div>

						<Button type="submit" class="mt-2 w-full" disabled={register.isPending}>
							{register.isPending ? 'Creating Account...' : 'Sign Up'}
						</Button>
					</form>
				{/if}
			</div>

			<div class="my-6 grid grid-cols-[1fr_auto_1fr] items-center gap-3">
				<hr class="border-solid" />
				<span class="text-xs text-muted-foreground">Or sign up with</span>
				<hr class="border-solid" />
			</div>

			<div class="grid grid-cols-2 gap-3">
				<Button
					type="button"
					variant="secondary"
					onclick={() => (window.location.href = '/oauth/login?provider=google')}
					disabled={register.isPending || isPasskeySignup}
				>
					<GoogleIcon class="size-5" />
					<span>Google</span>
				</Button>
				<Button
					type="button"
					variant="secondary"
					onclick={() => (window.location.href = '/oauth/login?provider=github')}
					disabled={register.isPending || isPasskeySignup}
				>
					<GitHubIcon class="size-5" />
					<span>GitHub</span>
				</Button>
			</div>
		</div>

		<div class="p-3">
			<p class="text-center text-sm text-accent-foreground">
				Already have an account?
				<Button href="/login" variant="link" class="px-2">Sign In</Button>
			</p>
		</div>
	</div>

	<div class="mt-6 text-center text-xs text-balance text-muted-foreground">
		By clicking continue, you agree to our
		<a href="/terms" class="underline underline-offset-4 hover:text-primary">Terms of Service</a>
		and
		<a href="/privacy" class="underline underline-offset-4 hover:text-primary">Privacy Policy</a>.
	</div>
</section>
