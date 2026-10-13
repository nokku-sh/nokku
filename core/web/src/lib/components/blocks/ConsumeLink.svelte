<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { auth } from '#lib/api/auth.svelte.js';
	import { formatConnectError } from '#lib/api/error-formatter.js';
	import AuthCard from '#lib/components/blocks/AuthCard.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import { ConnectError } from '@connectrpc/connect';
	import { CircleX, LogIn, Mail } from '@lucide/svelte';

	interface Props {
		/** What the page says while the token is checked. */
		title: string;
		/** Where an expired link sends people to ask for a new one. */
		retryHref: string;
		retryLabel: string;
		/** Where a link that worked lands. */
		next?: string;
	}

	let { title, retryHref, retryLabel, next = '/' }: Props = $props();

	const token = page.url.searchParams.get('token');
	const consume = auth.consumeMagicLink();

	// Fetched on open, not on a button, since the mailed link is the whole proof.
	$effect(() => {
		if (token && consume.isIdle) {
			consume.mutate({ token }, { onSuccess: () => void goto(next) });
		}
	});

	const error = $derived(
		consume.error ? formatConnectError(ConnectError.from(consume.error)).description : undefined
	);
</script>

{#if !token}
	<AuthCard
		title="Nothing to open"
		description="This page needs the link from your email."
		icon={CircleX}
		tone="destructive"
	>
		<Button href="/login">
			<LogIn data-icon="inline-start" />
			Back to sign in
		</Button>
	</AuthCard>
{:else if consume.isError}
	<AuthCard
		title="That link did not work"
		description={`${error ?? 'The link is invalid'}. Links work once and expire after 15 minutes, so ask for a fresh one.`}
		icon={CircleX}
		tone="destructive"
	>
		<Button href={retryHref}>
			<Mail data-icon="inline-start" />
			{retryLabel}
		</Button>
	</AuthCard>
{:else}
	<AuthCard {title} description="One moment" icon={Mail}>
		<Spinner class="size-6 self-center text-primary" />
	</AuthCard>
{/if}
