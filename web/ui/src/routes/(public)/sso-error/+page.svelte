<script lang="ts">
	import { afterNavigate, replaceState } from '$app/navigation';
	import { page } from '$app/state';
	import * as Alert from '$lib/components/ui/alert';
	import { Button } from '$lib/components/ui/button/index.js';
	import { CircleAlert } from '@lucide/svelte';
	import Logo from '$lib/assets/logo.svelte';

	type ErrorInfo = { title: string; description: string };

	// Keys are the error messages the backend's SSO flows append to the
	// redirect (see the iam.Fail call sites).
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

	afterNavigate(() => {
		// Strip the error param once shown: a refresh shouldn't re-show the
		// error, and back-navigation shouldn't land on it again. Uses the
		// SvelteKit-aware helper so the router state stays in sync.
		replaceState('/sso-error', {});
	});
</script>

<div
	class="m-auto h-fit w-full max-w-sm overflow-hidden rounded-[calc(var(--radius)+.125rem)] border bg-muted shadow-md shadow-zinc-950/5 dark:[--color-muted:var(--color-zinc-900)]"
>
	<div class="-m-px rounded-[calc(var(--radius)+.125rem)] border bg-card p-6 pb-6">
		<div class="text-center">
			<Logo class="mx-auto block w-10 py-2 dark:invert" />
			<h1 class="mt-4 mb-1 text-xl font-semibold">Sign In to Nokku</h1>
		</div>

		<div class="mt-6">
			<Alert.Root variant="destructive">
				<CircleAlert />
				<Alert.Title>{info.title}</Alert.Title>
				<Alert.Description>{info.description}</Alert.Description>
			</Alert.Root>
		</div>
	</div>

	<div class="p-3">
		<Button href="/login" variant="default" class="w-full">Back to Sign In</Button>
	</div>
</div>
