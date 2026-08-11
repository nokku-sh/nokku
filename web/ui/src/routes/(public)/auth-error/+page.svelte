<script lang="ts">
	import { page } from '$app/state';
	import * as Alert from '$lib/components/ui/alert';
	import { Button } from '$lib/components/ui/button/index.js';
	import { CircleAlert } from '@lucide/svelte';
	import Logo from '$lib/assets/logo.svelte';

	type ErrorInfo = { title: string; description: string };

	const codes: Record<string, ErrorInfo> = {
		sso_required: {
			title: 'Single Sign-On required',
			description:
				'Your workspace requires signing in through its identity provider. Go back and use the SSO option for your email domain.'
		},
		access_denied: {
			title: 'Sign-in cancelled',
			description: 'The sign-in was cancelled at your identity provider.'
		},
		invalid_state: {
			title: 'Invalid sign-in request',
			description: 'The sign-in session expired or was tampered with. Please try again.'
		},
		invalid_request: {
			title: 'Invalid sign-in request',
			description: 'The sign-in request could not be processed. Please try again.'
		},
		provider_config_failed: {
			title: 'Provider configuration error',
			description:
				'Your workspace identity provider is not configured correctly. Contact your workspace admin.'
		},
		token_exchange_failed: {
			title: 'Provider unreachable',
			description: 'The identity provider could not complete the sign-in. Please try again later.'
		},
		github_fetch_failed: {
			title: 'GitHub sign-in failed',
			description: 'Your GitHub profile could not be loaded. Please try again.'
		},
		token_verification_failed: {
			title: 'Could not verify your identity',
			description: 'The identity provider response failed verification. Please try again.'
		},
		no_id_token: {
			title: 'Could not verify your identity',
			description: 'The identity provider did not return the expected credentials.'
		},
		invalid_claims: {
			title: 'Invalid profile data',
			description:
				'The identity provider returned unexpected profile data. Contact your workspace admin.'
		},
		invalid_assertion: {
			title: 'Invalid sign-in response',
			description: 'The identity provider response was rejected. Please try again.'
		},
		invalid_attributes: {
			title: 'Missing profile information',
			description:
				'Your identity provider did not provide the required profile attributes (such as email). Contact your workspace admin.'
		},
		missing_name_id: {
			title: 'Missing identity',
			description:
				'The identity provider response did not include a user identity. Contact your workspace admin.'
		},
		user_failed: {
			title: 'Sign-in failed',
			description:
				'Your account could not be signed in. It may not be provisioned for this workspace.'
		},
		unknown: {
			title: 'Authentication failed',
			description: 'Something went wrong during sign-in. Please try again.'
		}
	};

	const code = page.url.searchParams.get('error') ?? 'unknown';
	const info = $derived(codes[code] ?? codes.unknown);

	// Strip the error param once shown: a refresh shouldn't re-show the
	// error, and back-navigation shouldn't land on it again.
	history.replaceState(null, '', '/auth-error');
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
