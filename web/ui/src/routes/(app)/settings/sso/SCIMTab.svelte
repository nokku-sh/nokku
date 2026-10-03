<script lang="ts">
	import { page } from '$app/state';
	import { scim } from '#lib/api/scim.svelte.js';
	import FormModal from '#lib/components/blocks/FormModal.svelte';
	import SecretReveal from '#lib/components/blocks/SecretReveal.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import InputGroupVariants from '#lib/components/blocks/InputGroupVariants.svelte';
	import * as Item from '#lib/components/ui/item/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { confirm } from '#lib/hooks/index.js';
	import { workspaceID } from '#lib/store.svelte.js';
	import { formatTs } from '#lib/utils.js';
	import { KeyRound, Plus, Trash2, UsersRound } from '@lucide/svelte';

	const tokens = scim.listTokens();
	const createToken = scim.createToken();
	const deleteToken = scim.deleteToken();

	let createOpen = $state(false);
	let label = $state('');
	let created = $state<string>();

	const baseURL = $derived(`${page.url.origin}/scim/v2/${workspaceID.current}`);

	// Stays open to show the secret once.
	async function create() {
		const res = await createToken.mutateAsync({
			workspaceId: workspaceID.current,
			label: label.trim()
		});
		created = res.token ?? '';
		label = '';
		return false;
	}

	function revoke(id: string, name: string) {
		void confirm({
			title: `Revoke ${name || 'this token'}?`,
			description:
				'The identity provider using it loses access right away. Provisioning stops until it gets a new token.',
			confirmText: 'Revoke',
			onConfirm: () => deleteToken.mutateAsync({ workspaceId: workspaceID.current, tokenId: id })
		});
	}
</script>

<FormModal
	bind:open={createOpen}
	title="Create a connector token"
	description="Your identity provider uses it to talk to the SCIM connector."
	icon={UsersRound}
	onOpenChange={(open) => !open && (created = undefined)}
	onSubmit={create}
	submitLabel="Create token"
	submitDisabled={!label.trim()}
>
	{#if created}
		<SecretReveal
			values={[{ label: 'Bearer token', value: created }]}
			note="Copy it now, it is only shown once. If it gets lost, revoke it and create a new one."
		/>
	{:else}
		<Field.Field>
			<Field.Label for="scim-token-label">Label</Field.Label>
			<Input id="scim-token-label" placeholder="Okta production" bind:value={label} />
			<Field.Description>Name it after the identity provider that uses it.</Field.Description>
		</Field.Field>
	{/if}
	{#snippet footer()}
		{#if created}
			<Button type="button" onclick={() => (createOpen = false)}>Done</Button>
		{:else}
			<Button type="submit" disabled={!label.trim() || createToken.isPending}>Create token</Button>
		{/if}
	{/snippet}
</FormModal>

<div class="flex flex-col gap-4">
	<Card.Root>
		<Card.Header>
			<Card.Title>Connector</Card.Title>
			<Card.Description>
				Point your identity provider's SCIM client here. It pushes users and groups into this
				workspace.
			</Card.Description>
		</Card.Header>
		<Card.Content>
			<Field.Field>
				<Field.Label>Base URL</Field.Label>
				<InputGroupVariants
					variant="copy-input"
					value={baseURL}
					readonly
					class="font-mono text-xs"
				/>
			</Field.Field>
		</Card.Content>
	</Card.Root>

	<Card.Root>
		<Card.Header>
			<Card.Title>Connector tokens</Card.Title>
			<Card.Description>The secret is shown once, when you create it.</Card.Description>
			<Card.Action>
				<Button size="sm" onclick={() => (createOpen = true)}>
					<Plus data-icon="inline-start" />
					Create token
				</Button>
			</Card.Action>
		</Card.Header>
		<Card.Content>
			{#if tokens.isLoading}
				<Skeleton class="h-16 w-full" />
			{:else if !tokens.data?.length}
				<Empty.Root class="border border-dashed">
					<Empty.Header>
						<Empty.Media variant="icon"><KeyRound /></Empty.Media>
						<Empty.Title>No connector tokens</Empty.Title>
						<Empty.Description>
							Create one and paste it into your identity provider to start provisioning.
						</Empty.Description>
					</Empty.Header>
				</Empty.Root>
			{:else}
				<Item.Group class="divide-y rounded-lg border">
					{#each tokens.data as t (t.id)}
						<Item.Root size="sm" class="rounded-none">
							<Item.Media variant="icon"><KeyRound /></Item.Media>
							<Item.Content>
								<Item.Title>{t.label}</Item.Title>
								<Item.Description>
									Created {formatTs(t.createdAt)} · {t.lastUsedAt
										? `last used ${formatTs(t.lastUsedAt, 'relative')}`
										: 'never used'}
								</Item.Description>
							</Item.Content>
							<Item.Actions>
								<Button
									size="icon-sm"
									variant="ghost"
									aria-label={`Revoke ${t.label}`}
									onclick={() => revoke(t.id ?? '', t.label)}
								>
									<Trash2 />
								</Button>
							</Item.Actions>
						</Item.Root>
					{/each}
				</Item.Group>
			{/if}
		</Card.Content>
	</Card.Root>
</div>
