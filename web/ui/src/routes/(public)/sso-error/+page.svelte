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
		'provider discovery failed': {
			title: 'Provider unreachable',
			description: 'The identity provider could not be reached. Please try again later.'
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
		'provider metadata invalid': {
			title: 'Provider configuration error',
			description:
				'Your workspace identity provider is not configured correctly. Contact your workspace admin.'
		},
		'no SSO endpoint in metadata': {
			title: 'Provider configuration error',
			description:
				'Your workspace identity provider is not configured correctly. Contact your workspace admin.'
		},
		'request creation failed': {
			title: 'Sign-in failed',
			description: 'The sign-in request could not be created. Please try again.'
		},
		'request signing failed': {
			title: 'Sign-in failed',
			description: 'The sign-in request could not be created. Please try again.'
		},
		'response verification failed': {
			title: 'Could not verify your identity',
			description: 'The identity provider response failed verification. Please try again.'
		},
		'assertion has no subject': {
			title: 'Missing identity',
			description: 'Your identity provider response did not include a user identity.'
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
