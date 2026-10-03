<script lang="ts">
	import { goto } from '$app/navigation';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import * as Collapsible from '#lib/components/ui/collapsible/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import { GoogleIcon, GitHubIcon } from '#lib/assets/index.js';
	import LegalConsent from '#lib/components/blocks/LegalConsent.svelte';
	import AuthCard from '#lib/components/blocks/AuthCard.svelte';
	import InputGroupVariants from '#lib/components/blocks/InputGroupVariants.svelte';
	import { auth } from '#lib/api/auth.svelte.js';
	import { signupWithPasskey } from '#lib/api/passkey.js';
	import { toast } from 'svelte-sonner';
	import { ChevronDown, KeyRound, UserPlus } from '@lucide/svelte';

	let name = $state('');
	let email = $state('');
	let password = $state('');
	let confirmPassword = $state('');
	let showPassword = $state(false);

	const passwordsMatch = $derived(password === confirmPassword && password.length > 0);
	const isPasswordValid = $derived(password.length >= 8);

	const register = auth.register();
	let isPasskeySignup = $state(false);
	const busy = $derived(register.isPending || isPasskeySignup);

	function handleRegistration(e: SubmitEvent) {
		e.preventDefault();
		if (!passwordsMatch || !isPasswordValid) return;
		register.mutate({ name, email, password });
	}

	async function handlePasskeySignup() {
		if (!email) {
			toast.error('Email is required');
			return;
		}

		isPasskeySignup = true;
		try {
			await signupWithPasskey({ email, name });
			await goto(`/verify?sent=true&email=${encodeURIComponent(email)}`);
		} catch (error) {
			toast.error(error instanceof Error ? error.message : 'Passkey signup failed');
		} finally {
			isPasskeySignup = false;
		}
	}
</script>

<AuthCard
	title="Create your Nokku account"
	description="Passkeys first, passwords if you must"
	wide
>
	<Field.Group class="gap-4">
		<Field.Field>
			<Field.Label for="name">Full name</Field.Label>
			<Input
				id="name"
				autocomplete="name"
				bind:value={name}
				placeholder="Ada Lovelace"
				disabled={busy}
			/>
		</Field.Field>
		<Field.Field>
			<Field.Label for="email">Email</Field.Label>
			<Input
				id="email"
				type="email"
				autocomplete="email"
				bind:value={email}
				placeholder="you@company.com"
				required
				disabled={busy}
			/>
		</Field.Field>
	</Field.Group>

	<Button type="button" onclick={handlePasskeySignup} disabled={busy}>
		{#if isPasskeySignup}<Spinner data-icon="inline-start" />{:else}<KeyRound
				data-icon="inline-start"
			/>{/if}
		Sign up with a passkey
	</Button>

	<Collapsible.Root bind:open={showPassword} class="flex flex-col gap-4">
		<Collapsible.Trigger>
			{#snippet child({ props })}
				<Button {...props} variant="link" size="sm" class="self-center text-muted-foreground">
					<ChevronDown
						class={['transition-transform', showPassword && 'rotate-180']}
						data-icon="inline-start"
					/>
					{showPassword ? 'Hide password fields' : 'Set a password instead'}
				</Button>
			{/snippet}
		</Collapsible.Trigger>
		<Collapsible.Content>
			<form onsubmit={handleRegistration} class="flex flex-col gap-4">
				<Field.Group class="gap-4">
					<Field.Field data-invalid={password.length > 0 && !isPasswordValid ? true : undefined}>
						<Field.Label for="password">Password</Field.Label>
						<InputGroupVariants
							variant="password"
							bind:value={password}
							placeholder="At least 8 characters"
							inputProps={{ id: 'password', required: true, autocomplete: 'new-password' }}
						/>
						{#if password.length > 0 && !isPasswordValid}
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
				<Button type="submit" variant="secondary" disabled={busy}>
					{#if register.isPending}<Spinner data-icon="inline-start" />{:else}<UserPlus
							data-icon="inline-start"
						/>{/if}
					Sign up with a password
				</Button>
			</form>
		</Collapsible.Content>
	</Collapsible.Root>

	<Field.Separator>Or sign up with</Field.Separator>

	<div class="grid grid-cols-2 gap-3">
		<Button variant="secondary" href="/oidc/login?provider=google" data-sveltekit-reload>
			<GoogleIcon data-icon="inline-start" />
			Google
		</Button>
		<Button variant="secondary" href="/oauth/login?provider=github" data-sveltekit-reload>
			<GitHubIcon data-icon="inline-start" />
			GitHub
		</Button>
	</div>

	<LegalConsent lead="By signing up," />

	{#snippet footer()}
		Have an account? <a href="/login" class="font-medium text-primary hover:underline">Sign in</a>
	{/snippet}
</AuthCard>
