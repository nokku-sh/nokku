<script lang="ts">
	import { auth } from '$lib/api/auth.svelte';
	import AuthCard from '$lib/components/blocks/AuthCard.svelte';
	import { Button } from '$lib/components/ui/button';
	import * as Field from '$lib/components/ui/field';
	import { Input } from '$lib/components/ui/input';
	import { Spinner } from '$lib/components/ui/spinner';
	import { BinaryIcon, MailCheck, Mail, Undo2Icon } from '@lucide/svelte';

	let email = $state('');
	const forgotPassword = auth.forgotPassword();

	function submit(e: SubmitEvent) {
		e.preventDefault();
		forgotPassword.mutate({ email });
	}

	function tryAgain() {
		email = '';
		forgotPassword.reset();
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

{#if forgotPassword.isSuccess}
	<AuthCard
		title="Check your email"
		description={`If ${email} has an account, a reset link is on its way. It works for 15 minutes.`}
		icon={MailCheck}
		tone="success"
		footer={back}
	>
		<Button variant="outline" onclick={tryAgain}>
			<Mail data-icon="inline-start" />
			Use a different email
		</Button>
	</AuthCard>
{:else}
	<AuthCard
		title="Reset your password"
		description="We will email you a link to set a new one"
		icon={Mail}
		footer={back}
	>
		<form class="flex flex-col gap-4" onsubmit={submit}>
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
			<Button type="submit" disabled={forgotPassword.isPending}>
				{#if forgotPassword.isPending}<Spinner data-icon="inline-start" />{/if}
				Send reset link
			</Button>
		</form>

		<Field.Separator>Or</Field.Separator>

		<Button href="/login/backup" variant="outline">
			<BinaryIcon data-icon="inline-start" />
			Sign in with a backup code
		</Button>
	</AuthCard>
{/if}
