<script lang="ts">
	import { page } from '$app/state';
	import { auth } from '#lib/api/auth.svelte.js';
	import { formatConnectError } from '#lib/api/error-formatter.js';
	import AuthCard from '#lib/components/blocks/AuthCard.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import { ConnectError } from '@connectrpc/connect';
	import { CircleCheck, CircleX, LogIn, Mail, Undo2Icon } from '@lucide/svelte';

	const token = page.url.searchParams.get('token');
	let email = $state(page.url.searchParams.get('email') ?? '');

	const verifyEmail = auth.verifyEmail();
	const resendVerification = auth.resendVerification();

	$effect(() => {
		if (token) verifyEmail.mutate({ token });
	});

	const error = $derived(
		verifyEmail.error ? formatConnectError(ConnectError.from(verifyEmail.error)).title : undefined
	);

	function resend(e: SubmitEvent) {
		e.preventDefault();
		resendVerification.mutate({ email });
	}
</script>

{#snippet back()}
	<a
		href="/login"
		class="inline-flex items-center gap-1.5 font-medium text-primary hover:underline"
	>
		<Undo2Icon class="size-3.5" /> Back to sign in
	</a>
{/snippet}

{#snippet resendForm(label: string)}
	<form class="flex flex-col gap-3" onsubmit={resend}>
		<Field.Field>
			<Field.Label for="email">Email</Field.Label>
			<Input
				id="email"
				type="email"
				autocomplete="email"
				bind:value={email}
				placeholder="you@company.com"
				required
			/>
		</Field.Field>
		<Button type="submit" variant="outline" disabled={resendVerification.isPending}>
			{#if resendVerification.isPending}<Spinner data-icon="inline-start" />{:else}<Mail
					data-icon="inline-start"
				/>{/if}
			{label}
		</Button>
	</form>
{/snippet}

{#if verifyEmail.isPending}
	<AuthCard title="Verifying your email" description="One moment" icon={Mail}>
		<Spinner class="size-6 self-center text-primary" />
	</AuthCard>
{:else if verifyEmail.isSuccess}
	<AuthCard
		title="Email verified"
		description="Your account is active. Sign in to get started."
		icon={CircleCheck}
		tone="success"
	>
		<Button href="/login">
			<LogIn data-icon="inline-start" />
			Sign in
		</Button>
	</AuthCard>
{:else if verifyEmail.isError}
	<AuthCard
		title="That link did not work"
		description={`${error ?? 'Verification failed'}. Links expire after 15 minutes, so ask for a fresh one.`}
		icon={CircleX}
		tone="destructive"
		footer={back}
	>
		{@render resendForm('Send a new link')}
	</AuthCard>
{:else if page.url.searchParams.has('sent')}
	<AuthCard
		title="Check your email"
		description="Click the link we sent to activate your account. It works for 15 minutes, and it may land in spam."
		icon={Mail}
		footer={back}
	>
		{@render resendForm('Resend the link')}
	</AuthCard>
{:else}
	<AuthCard
		title="Nothing to verify"
		description="This page needs the link from your verification email."
		icon={CircleX}
		tone="destructive"
		footer={back}
	/>
{/if}
