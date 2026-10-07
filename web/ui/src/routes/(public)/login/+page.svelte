<script lang="ts">
	import { goto } from '$app/navigation';
	import { auth } from '#lib/api/auth.svelte.js';
	import { loginWithPasskey } from '#lib/api/passkey.js';
	import { OIDCIcon } from '#lib/assets/index.js';
	import AuthCard from '#lib/components/blocks/AuthCard.svelte';
	import LegalConsent from '#lib/components/blocks/LegalConsent.svelte';
	import * as Alert from '#lib/components/ext/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import { KeyRound, Mail, MailCheck } from '@lucide/svelte';
	import { toast } from 'svelte-sonner';

	const options = auth.options();
	const request = auth.requestMagicLink();

	let email = $state('');
	let passkeyBusy = $state(false);

	// The provider is the only way in once SSO is required, so the rest is
	// left out rather than greyed out.
	const providers = $derived(options.data?.providers ?? []);
	const providersOnly = $derived(
		!!options.data && !options.data.magicLink && !options.data.passkey
	);

	function submit(e: SubmitEvent) {
		e.preventDefault();
		request.mutate({ email: email.trim() });
	}

	async function withPasskey() {
		if (!window.PublicKeyCredential) {
			toast.error('Passkeys not supported', { description: 'Try a current browser.' });
			return;
		}
		passkeyBusy = true;
		try {
			await loginWithPasskey();
			await goto('/');
		} catch (error) {
			const cancelled = error instanceof DOMException && error.name === 'NotAllowedError';
			if (!cancelled)
				toast.error(error instanceof Error ? error.message : 'Passkey sign-in failed');
		} finally {
			passkeyBusy = false;
		}
	}
</script>

{#if options.isLoading}
	<AuthCard title="Sign in" description="One moment">
		<Skeleton class="h-10 w-full" />
		<Skeleton class="h-10 w-full" />
	</AuthCard>
{:else if options.isError}
	<AuthCard
		title="No workspace here"
		description="This address does not belong to a Nokku workspace. Check the link you were given."
		icon={Mail}
		tone="destructive"
	/>
{:else if request.isSuccess}
	<AuthCard
		title="Check your email"
		description={`If ${email} has an account here, a sign-in link is on its way. It works for 15 minutes and may land in spam.`}
		icon={MailCheck}
		tone="success"
	>
		<Button variant="outline" onclick={() => request.reset()}>
			<Mail data-icon="inline-start" />
			Use a different email
		</Button>
	</AuthCard>
{:else}
	<AuthCard
		title={`Sign in to ${options.data?.workspaceName || 'Nokku'}`}
		description="Welcome back, pick up where you left off"
	>
		{#if options.data?.magicLink}
			<form class="flex flex-col gap-4" onsubmit={submit}>
				<Field.Field>
					<Field.Label for="email">Email</Field.Label>
					<Input
						id="email"
						type="email"
						autocomplete="username webauthn"
						bind:value={email}
						required
						placeholder="you@company.com"
					/>
				</Field.Field>
				<Button type="submit" disabled={request.isPending || !email}>
					{#if request.isPending}<Spinner data-icon="inline-start" />{:else}<Mail
							data-icon="inline-start"
						/>{/if}
					Send me a sign-in link
				</Button>
			</form>
		{/if}

		{#if options.data?.magicLink && (options.data.passkey || providers.length)}
			<Field.Separator>Or continue with</Field.Separator>
		{/if}

		{#if providersOnly}
			<Alert.Root variant="info">
				<KeyRound />
				<Alert.Title>Single sign-on required</Alert.Title>
				<Alert.Description
					>This workspace signs everyone in through its identity provider.</Alert.Description
				>
			</Alert.Root>
		{/if}

		<div class="flex flex-col gap-3">
			{#if options.data?.passkey}
				<Button
					variant={options.data.magicLink ? 'secondary' : 'default'}
					onclick={withPasskey}
					disabled={passkeyBusy}
				>
					{#if passkeyBusy}<Spinner data-icon="inline-start" />{:else}<KeyRound
							data-icon="inline-start"
						/>{/if}
					Passkey
				</Button>
			{/if}
			{#each providers as p (p.providerId)}
				<Button
					variant={providersOnly ? 'default' : 'secondary'}
					href={`/oidc/login?provider=${encodeURIComponent(p.providerId)}`}
					data-sveltekit-reload
				>
					<OIDCIcon data-icon="inline-start" />
					{p.name || p.providerId}
				</Button>
			{/each}
		</div>

		{#if providers.length}
			<LegalConsent lead="Single sign-on may create an account on first sign-in. By continuing," />
		{/if}

		{#snippet footer()}
			Invited? Open the link you were sent, it creates your account.
		{/snippet}
	</AuthCard>
{/if}
