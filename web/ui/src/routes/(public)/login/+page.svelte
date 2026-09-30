<script lang="ts">
	import { goto } from '$app/navigation';
	import { loginWithPasskey } from '$lib/api/passkey';
	import * as Alert from '$lib/components/ui/alert';
	import { Button } from '$lib/components/ui/button';
	import { InputGroupVariants } from '$lib/components/ui/input-group';
	import { Input } from '$lib/components/ui/input';
	import * as Field from '$lib/components/ui/field';
	import { Spinner } from '$lib/components/ui/spinner';
	import LegalConsent from '$lib/components/blocks/LegalConsent.svelte';
	import AuthCard from '$lib/components/blocks/AuthCard.svelte';
	import { BinaryIcon, GlobeIcon, KeyRound, LogIn, Mail } from '@lucide/svelte';
	import { GoogleIcon, GitHubIcon, OIDCIcon, SAMLIcon } from '$lib/assets';
	import { toast } from 'svelte-sonner';
	import { sso } from '$lib/api/sso.svelte';
	import { auth } from '$lib/api/auth.svelte';
	import { isEmailUnverifiedError, emailUnverifiedMessage } from '$lib/api/error-formatter';
	import { useDebounce } from 'runed';

	let email = $state('');
	let password = $state('');

	const login = auth.login();
	const resendVerification = auth.resendVerification();
	const ssoCheck = sso.check();

	const showUnverified = $derived(login.isError && isEmailUnverifiedError(login.error));

	// Probe for an SSO provider while the email is typed.
	const checkSSO = useDebounce(() => {
		if (email.includes('@')) {
			ssoCheck.mutate(email);
		}
	}, 300);

	let enforceSSO = $derived(ssoCheck.isSuccess && ssoCheck.data?.enforce);
	let disablePasswordLogin = $derived(enforceSSO || login.isPending);

	function ssoLabel(p: { method: string; name: string }) {
		return p.name || (p.method === 'saml' ? 'SAML' : 'SSO');
	}

	function handleSSOLogin(p: { method: string; provider: string }) {
		// The domain tells the backend which workspace's provider is meant.
		const domain = ssoCheck.data?.domain ?? '';
		const q = domain ? `&domain=${encodeURIComponent(domain)}` : '';
		switch (p.method) {
			case 'oidc':
				window.location.href = `oidc/login?provider=${p.provider}${q}`;
				break;
			case 'saml':
				window.location.href = `saml/login?provider=${p.provider}${q}`;
				break;
			case 'oauth2':
				window.location.href = `oauth/login?provider=${p.provider}${q}`;
				break;
		}
	}

	function submit(e: SubmitEvent) {
		e.preventDefault();
		if (!disablePasswordLogin) login.mutate({ password, email });
	}

	async function handlePasskeyLogin() {
		try {
			await loginWithPasskey();
			await goto('/');
		} catch (error) {
			// Passkey login knows no email, the verify screen asks for one.
			if (error instanceof Error && error.message === emailUnverifiedMessage) {
				await goto('/verify?sent=true');
				return;
			}
			toast.error(error instanceof Error ? error.message : 'Passkey login failed');
		}
	}
</script>

<AuthCard title="Sign in to Nokku" description="Welcome back, pick up where you left off">
	<form class="flex flex-col gap-4" onsubmit={submit}>
		<Field.Group class="gap-4">
			<Field.Field>
				<Field.Label for="email">Email</Field.Label>
				<Input
					id="email"
					type="email"
					autocomplete="username webauthn"
					bind:value={email}
					required
					oninput={checkSSO}
					placeholder="you@company.com"
				/>
			</Field.Field>

			{#if !enforceSSO && !showUnverified}
				<Field.Field>
					<div class="flex items-center justify-between">
						<Field.Label for="password">Password</Field.Label>
						<a href="/recovery" class="text-xs text-primary hover:underline">Forgot it?</a>
					</div>
					<InputGroupVariants
						variant="password"
						bind:value={password}
						placeholder="Your password"
						inputProps={{ id: 'password', required: true, autocomplete: 'current-password' }}
					/>
				</Field.Field>
			{/if}
		</Field.Group>

		{#if showUnverified}
			<Alert.Root variant="info">
				<Mail />
				<Alert.Title>Check your email</Alert.Title>
				<Alert.Description>
					We sent a verification link to {email}. Confirm it to activate your account.
				</Alert.Description>
			</Alert.Root>
			<Button
				variant="outline"
				type="button"
				disabled={resendVerification.isPending}
				onclick={() => resendVerification.mutate({ email })}
			>
				{#if resendVerification.isPending}<Spinner data-icon="inline-start" />{:else}<Mail
						data-icon="inline-start"
					/>{/if}
				Resend verification email
			</Button>
		{:else if !enforceSSO}
			<Button type="submit" disabled={disablePasswordLogin}>
				{#if login.isPending}<Spinner data-icon="inline-start" />{:else}<LogIn
						data-icon="inline-start"
					/>{/if}
				Sign in
			</Button>
		{/if}

		{#if ssoCheck.isSuccess && ssoCheck.data?.hasSSO}
			{#each ssoCheck.data.providers as p (`${p.method}:${p.provider}`)}
				<Button
					type="button"
					variant="secondary"
					onclick={() => handleSSOLogin(p)}
					disabled={ssoCheck.isPending}
				>
					{#if p.method === 'oidc'}
						<OIDCIcon data-icon="inline-start" />
					{:else if p.method === 'saml'}
						<SAMLIcon data-icon="inline-start" />
					{:else}
						<GlobeIcon data-icon="inline-start" />
					{/if}
					{ssoLabel(p)}
				</Button>
			{/each}
		{/if}
	</form>

	<Field.Separator>Or continue with</Field.Separator>

	<div class="grid grid-cols-2 gap-3">
		<Button variant="secondary" href="/oidc/login?provider=google" data-sveltekit-reload>
			<GoogleIcon data-icon="inline-start" />
			Google
		</Button>
		<Button variant="secondary" href="/oauth/login?provider=github" data-sveltekit-reload>
			<GitHubIcon data-icon="inline-start" />
			GitHub
		</Button>
		<Button variant="secondary" class="col-span-2" onclick={handlePasskeyLogin}>
			<KeyRound data-icon="inline-start" />
			Passkey
		</Button>
		{#if !enforceSSO && email && login.isError && !showUnverified}
			<Button href="/login/backup" variant="outline" class="col-span-2">
				<BinaryIcon data-icon="inline-start" />
				Sign in with a backup code
			</Button>
		{/if}
	</div>

	<LegalConsent lead="Google, GitHub and SSO create an account on first sign-in. By continuing," />

	{#snippet footer()}
		New to Nokku? <a href="/register" class="font-medium text-primary hover:underline"
			>Create an account</a
		>
	{/snippet}
</AuthCard>
