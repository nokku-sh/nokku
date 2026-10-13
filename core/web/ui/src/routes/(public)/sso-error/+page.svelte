<script lang="ts">
	import { afterNavigate, goto } from '$app/navigation';
	import { page } from '$app/state';
	import AuthCard from '#lib/components/blocks/AuthCard.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import { CircleAlert, LogIn } from '@lucide/svelte';

	type ErrorInfo = { title: string; description: string };

	// Keys must match the messages iam's fail() call sites send.
	const codes: Record<string, ErrorInfo> = {
		'login canceled': {
			title: 'Sign-in cancelled',
			description: 'The sign-in was cancelled at your identity provider.'
		},
		'invalid or expired login': {
			title: 'Invalid sign-in request',
			description: 'The sign-in session expired or was tampered with. Please try again.'
		},
		'provider not configured': {
			title: 'Provider configuration error',
			description:
				'Your workspace identity provider is not configured correctly. Contact your workspace admin.'
		},
		'provider unavailable': {
			title: 'Provider unreachable',
			description: 'The identity provider could not be reached. Please try again later.'
		},
		'login refused': {
			title: 'Sign-in not allowed',
			description: 'This account cannot sign in here. Contact your workspace admin.'
		},
		'internal error': {
			title: 'Sign-in failed',
			description: 'Something went wrong on our side. Please try again later.'
		},
		'login failed': {
			title: 'Sign-in failed',
			description: 'The identity provider could not complete the sign-in. Please try again later.'
		},
		'identity rejected': {
			title: 'Sign-in not allowed',
			description:
				'Your identity provider account is not set up to sign in here yet. Contact your workspace admin.'
		},
		'email not verified': {
			title: 'Email not verified',
			description:
				'Your identity provider has not verified your email address. Verify it there, then try again.'
		},
		'owner link required': {
			title: 'Link this sign-in first',
			description:
				'The workspace owner connects an identity provider by hand. Sign in with your passkey or a sign-in link, then link the provider under Profile, Security.'
		},
		unknown: {
			title: 'Authentication failed',
			description: 'Something went wrong during sign-in. Please try again.'
		}
	};

	const code = page.url.searchParams.get('error') ?? 'unknown';
	const info = $derived(codes[code] ?? codes.unknown);

	afterNavigate(({ shallow }) => {
		if (shallow) return;

		// Strip the param so a refresh or back navigation doesn't re-show it.
		goto('/sso-error', { shallow: true, replace: true });
	});
</script>

<AuthCard title={info.title} description={info.description} icon={CircleAlert} tone="destructive">
	<Button href="/login">
		<LogIn data-icon="inline-start" />
		Back to sign in
	</Button>
</AuthCard>
