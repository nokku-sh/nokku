<script lang="ts">
	import { workspace } from '#lib/api/workspaces.svelte.js';
	import AuthCard from '#lib/components/blocks/AuthCard.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import { Mail, MailCheck, Search } from '@lucide/svelte';

	const find = workspace.find();

	let email = $state('');

	function submit(e: SubmitEvent) {
		e.preventDefault();
		find.mutate({ email: email.trim() });
	}
</script>

{#if find.isSuccess}
	<AuthCard
		title="Check your email"
		description={`If ${email} has an account in a workspace, its address is on the way. Open it and bookmark it. The mail may land in spam.`}
		icon={MailCheck}
		tone="success"
	>
		<Button variant="outline" onclick={() => find.reset()}>
			<Mail data-icon="inline-start" />
			Use a different email
		</Button>
	</AuthCard>
{:else}
	<AuthCard
		title="Find your workspace"
		description="Every workspace has an address of its own. Enter your email and we send you yours."
		icon={Search}
	>
		<form class="flex flex-col gap-4" onsubmit={submit}>
			<Field.Field>
				<Field.Label for="find-email">Email</Field.Label>
				<Input
					id="find-email"
					type="email"
					autocomplete="email"
					bind:value={email}
					required
					placeholder="you@company.com"
				/>
			</Field.Field>
			<Button type="submit" disabled={find.isPending || !email}>
				{#if find.isPending}<Spinner data-icon="inline-start" />{:else}<Mail
						data-icon="inline-start"
					/>{/if}
				Send me my workspaces
			</Button>
		</form>

		{#snippet footer()}
			New here? <a href="/signup" class="text-primary hover:underline">Create a workspace</a>
		{/snippet}
	</AuthCard>
{/if}
