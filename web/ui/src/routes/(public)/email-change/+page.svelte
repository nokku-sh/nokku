<script lang="ts">
	import { page } from '$app/state';
	import { auth } from '#lib/api/auth.svelte.js';
	import { formatConnectError } from '#lib/api/error-formatter.js';
	import AuthCard from '#lib/components/blocks/AuthCard.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import { ConnectError } from '@connectrpc/connect';
	import { CircleCheck, CircleX, LogIn, Mail, ShieldAlert, Undo2Icon } from '@lucide/svelte';

	const token = page.url.searchParams.get('token');
	const cancel = page.url.searchParams.has('cancel');

	const confirmChange = auth.confirmEmailChange();
	const cancelChange = auth.cancelEmailChange();
	const mutation = cancel ? cancelChange : confirmChange;

	const error = $derived(
		mutation.error ? formatConnectError(ConnectError.from(mutation.error)).title : undefined
	);
</script>

{#snippet back()}
	<a href="/" class="inline-flex items-center gap-1.5 font-medium text-primary hover:underline">
		<Undo2Icon class="size-3.5" /> Back to Nokku
	</a>
{/snippet}

{#if !token}
	<AuthCard
		title="Nothing to do here"
		description="This page needs the link from your email."
		icon={CircleX}
		tone="destructive"
		footer={back}
	/>
{:else if mutation.isSuccess && cancel}
	<AuthCard
		title="Change canceled"
		description="Your account keeps this email address. If the change had already gone through, it was undone and every session was signed out. Sign in and change your password."
		icon={CircleCheck}
		tone="success"
	>
		<Button href="/login">
			<LogIn data-icon="inline-start" />
			Sign in
		</Button>
	</AuthCard>
{:else if mutation.isSuccess}
	<AuthCard
		title="Email address changed"
		description="You sign in with the new address from now on."
		icon={CircleCheck}
		tone="success"
		footer={back}
	/>
{:else if mutation.isError}
	<AuthCard
		title="That link did not work"
		description={`${error ?? 'The request failed'}. Start the change again from your profile.`}
		icon={CircleX}
		tone="destructive"
		footer={back}
	/>
{:else if cancel}
	<AuthCard
		title="Cancel the email change?"
		description="Someone asked to change the email address of your account. Canceling keeps this address, and undoes the change if it already happened."
		icon={ShieldAlert}
		tone="warning"
		footer={back}
	>
		<Button
			variant="destructive"
			disabled={mutation.isPending}
			onclick={() => mutation.mutate({ token })}
		>
			{#if mutation.isPending}<Spinner data-icon="inline-start" />{/if}
			This wasn't me, cancel it
		</Button>
	</AuthCard>
{:else}
	<AuthCard
		title="Confirm your new email address"
		description="Your account switches to this address once you confirm."
		icon={Mail}
		footer={back}
	>
		<Button disabled={mutation.isPending} onclick={() => mutation.mutate({ token })}>
			{#if mutation.isPending}<Spinner data-icon="inline-start" />{/if}
			Confirm address
		</Button>
	</AuthCard>
{/if}
