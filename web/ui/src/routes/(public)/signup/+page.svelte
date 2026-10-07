<script lang="ts">
	import { util, workspace } from '#lib/api/workspaces.svelte.js';
	import AuthCard from '#lib/components/blocks/AuthCard.svelte';
	import LegalConsent from '#lib/components/blocks/LegalConsent.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import * as InputGroup from '#lib/components/ui/input-group/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import { CircleX, MailCheck, Rocket } from '@lucide/svelte';

	const info = util.instanceInfo();
	const create = workspace.create();

	let name = $state('');
	let slug = $state('');
	let slugTouched = $state(false);
	let ownerName = $state('');
	let ownerEmail = $state('');

	const slugPattern = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
	const host = $derived(location.host);

	function slugOf(s: string) {
		return s
			.toLowerCase()
			.replace(/[^a-z0-9]+/g, '-')
			.replace(/^-|-$/g, '')
			.slice(0, 63);
	}
	function onNameInput() {
		if (!slugTouched) slug = slugOf(name);
	}

	const valid = $derived(
		!!name.trim() && slugPattern.test(slug) && !!ownerName.trim() && ownerEmail.includes('@')
	);

	function submit(e: SubmitEvent) {
		e.preventDefault();
		create.mutate({
			slug,
			name: name.trim(),
			ownerName: ownerName.trim(),
			ownerEmail: ownerEmail.trim()
		});
	}
</script>

{#if info.isLoading}
	<AuthCard title="Create a workspace" description="One moment">
		<Skeleton class="h-10 w-full" />
		<Skeleton class="h-10 w-full" />
	</AuthCard>
{:else if !info.data?.signup}
	<AuthCard
		title="Sign-up is not open here"
		description="This Nokku has its workspace already. Ask its admin for an invitation."
		icon={CircleX}
		tone="destructive"
	>
		<Button href="/login" variant="outline">Back to sign in</Button>
	</AuthCard>
{:else if create.isSuccess}
	<AuthCard
		title="Check your email"
		description={`Your workspace lives at ${create.data.url}. A sign-in link is on its way to ${ownerEmail}, it works for 24 hours.`}
		icon={MailCheck}
		tone="success"
	>
		<Button href={create.data.url} variant="outline" data-sveltekit-reload>
			Go to {create.data.url.replace(/^https?:\/\//, '')}
		</Button>
	</AuthCard>
{:else}
	<AuthCard
		title="Create your workspace"
		description="Your servers, people and certificates, at an address of your own"
		icon={Rocket}
		wide
	>
		<form class="flex flex-col gap-4" onsubmit={submit}>
			<Field.Group class="gap-4">
				<Field.Field>
					<Field.Label for="ws-name">Workspace name</Field.Label>
					<Input id="ws-name" bind:value={name} oninput={onNameInput} placeholder="Acme" required />
				</Field.Field>
				<Field.Field data-invalid={!!slug && !slugPattern.test(slug)}>
					<Field.Label for="ws-slug">Address</Field.Label>
					<InputGroup.Root>
						<InputGroup.Input
							id="ws-slug"
							bind:value={slug}
							oninput={() => (slugTouched = true)}
							placeholder="acme"
							class="font-mono"
							required
						/>
						<InputGroup.Addon align="inline-end">.{host}</InputGroup.Addon>
					</InputGroup.Root>
					<Field.Description
						>Lowercase letters, digits and dashes. Fixed once created.</Field.Description
					>
				</Field.Field>
				<div class="grid gap-4 sm:grid-cols-2">
					<Field.Field>
						<Field.Label for="owner-name">Your name</Field.Label>
						<Input
							id="owner-name"
							autocomplete="name"
							bind:value={ownerName}
							placeholder="Ada Lovelace"
							required
						/>
					</Field.Field>
					<Field.Field>
						<Field.Label for="owner-email">Your email</Field.Label>
						<Input
							id="owner-email"
							type="email"
							autocomplete="email"
							bind:value={ownerEmail}
							placeholder="you@company.com"
							required
						/>
					</Field.Field>
				</div>
			</Field.Group>
			<Button type="submit" disabled={!valid || create.isPending}>
				{#if create.isPending}<Spinner data-icon="inline-start" />{:else}<Rocket
						data-icon="inline-start"
					/>{/if}
				Create workspace
			</Button>
		</form>

		<LegalConsent lead="By creating a workspace," />

		{#snippet footer()}
			Have a workspace? Open its address to sign in.
		{/snippet}
	</AuthCard>
{/if}
