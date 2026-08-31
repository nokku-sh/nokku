<script lang="ts">
	import { goto } from '$app/navigation';
	import { loginWithPasskey } from '$lib/api/passkey';
	import { Button } from '$lib/components/ui/button/index.js';
	import { InputGroupVariants } from '$lib/components/ui/input-group';
	import { Input } from '$lib/components/ui/input/index.js';
	import { Label } from '$lib/components/ui/label/index.js';
	import { BinaryIcon, GlobeIcon, KeyRound, LogIn } from '@lucide/svelte';
	import { GoogleIcon, GitHubIcon, OIDCIcon, SAMLIcon } from '$lib/assets';
	import { toast } from 'svelte-sonner';
	import { sso } from '$lib/api/sso.svelte';
	import { auth } from '$lib/api/auth.svelte';
	import { useDebounce } from 'runed';
	import Logo from '$lib/assets/logo.svelte';

	// State
	let email = $state('');
	let password = $state('');

	const login = auth.login();
	const ssoCheck = sso.check();

	// Home Realm Discovery: probe for a workspace SSO provider as the email is
	// typed, so the matching button appears without submitting the form.
	// Discovery is kagi's /auth/sso/discover endpoint.
	const checkSSO = useDebounce(() => {
		if (email.includes('@')) {
			ssoCheck.mutate(email);
		}
	}, 300);

	let enforceSSO = $derived(ssoCheck.isSuccess && ssoCheck.data?.enforce);
	let disablePasswordLogin = $derived(enforceSSO || login.isPending);

	function handleSSOLogin(p: { method: string; provider: string }) {
		// The verified email domain tells kagi which workspace's provider is
		// meant: the login itself runs without workspace context.
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

	async function handlePasskeyLogin() {
		try {
			await loginWithPasskey();
			await goto('/');
		} catch (error) {
			toast.error(error instanceof Error ? error.message : 'Passkey login failed');
		}
	}
</script>

<div
	class="m-auto h-fit w-full max-w-sm overflow-hidden rounded-[calc(var(--radius)+.125rem)] border bg-muted shadow-md shadow-zinc-950/5 dark:[--color-muted:var(--color-zinc-900)]"
>
	<div class="-m-px rounded-[calc(var(--radius)+.125rem)] border bg-card p-6 pb-6">
		<div class="text-center">
			<Logo class="mx-auto block w-10 py-2 dark:invert" />
			<h1 class="mt-4 mb-1 text-xl font-semibold">Sign In to Nokku</h1>
			<p class="text-sm">Welcome back! Sign in to continue</p>
		</div>

		<div class="mt-6 space-y-4">
			<div class="space-y-2">
				<Label for="email">Email</Label>
				<Input
					id="email"
					type="email"
					bind:value={email}
					required
					oninput={checkSSO}
					placeholder="Enter your email"
				/>
			</div>

			{#if !enforceSSO}
				<div class="space-y-0.5">
					<div class="flex items-center justify-between">
						<Label for="password" class="text-sm">Password</Label>
						<Button href="/recovery" variant="link" size="sm" class="text-sm">
							Forgot your Password?
						</Button>
					</div>
					<InputGroupVariants
						variant="password"
						bind:value={password}
						placeholder="Enter your password"
						inputProps={{ required: true }}
					/>
				</div>
			{/if}

			<div class="space-y-2 transition-transform">
				{#if !enforceSSO}
					<Button
						type="submit"
						class="w-full"
						disabled={disablePasswordLogin}
						onclick={() => login.mutate({ password, email })}
					>
						<LogIn size={16} />
						Sign In
					</Button>
				{/if}

				{#if ssoCheck.isSuccess && ssoCheck.data?.hasSSO}
					{#each ssoCheck.data.providers as p (`${p.method}:${p.provider}`)}
						<Button
							type="button"
							variant="secondary"
							class="group flex w-full items-center gap-2"
							onclick={() => handleSSOLogin(p)}
							disabled={ssoCheck.isPending}
						>
							{#if p.method === 'oidc'}
								<OIDCIcon size={16} />
							{:else if p.method === 'saml'}
								<SAMLIcon size={16} />
							{:else}
								<GlobeIcon size={16} />
							{/if}
						</Button>
					{/each}
				{/if}
			</div>
		</div>

		<div class="my-6 grid grid-cols-[1fr_auto_1fr] items-center gap-3">
			<hr class="border-solid" />
			<span class="text-xs text-muted-foreground">Or continue with</span>
			<hr class="border-solid" />
		</div>

		<div class="mb-3 grid grid-cols-2 gap-3">
			<Button
				variant="secondary"
				onclick={() => (window.location.href = '/oidc/login?provider=google')}
			>
				<GoogleIcon class="size-5" />
				<span>Google</span>
			</Button>
			<Button
				variant="secondary"
				onclick={() => (window.location.href = '/oauth/login?provider=github')}
			>
				<GitHubIcon class="size-5" />
				<span>GitHub</span>
			</Button>
		</div>

		<div class="flex flex-col gap-3">
			<Button
				variant="secondary"
				class="group flex w-full items-center gap-2"
				onclick={handlePasskeyLogin}
			>
				<KeyRound
					size={16}
					class="transition-transform duration-300 group-hover:scale-110 group-hover:rotate-12"
				/>
				<span>Passkey</span>
			</Button>

			{#if !enforceSSO && email && login.isError}
				<Button href="/login/backup" variant="outline" class="group flex w-full items-center gap-2">
					<BinaryIcon
						size={16}
						class="transition-transform duration-300 group-hover:scale-110 group-hover:rotate-12"
					/>
					Sign in with a backup code
				</Button>
			{/if}
		</div>
	</div>

	<div class="p-3">
		<p class="text-center text-sm text-accent-foreground">
			Don't have an account?
			<Button href="/register" variant="link" class="px-2">Sign up</Button>
		</p>
	</div>
</div>
