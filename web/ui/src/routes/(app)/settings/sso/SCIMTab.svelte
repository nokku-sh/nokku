<script lang="ts">
	import { page } from '$app/state';
	import { scim } from '$lib/api/scim.svelte';
	import { workspaceID } from '$lib/store.svelte';
	import { formatTs } from '$lib/utils';
	import { Button } from '$lib/components/ui/button';
	import * as Alert from '$lib/components/ui/alert';
	import * as Card from '$lib/components/ui/card';
	import * as Dialog from '$lib/components/ui/dialog';
	import * as Empty from '$lib/components/ui/empty';
	import * as Field from '$lib/components/ui/field';
	import * as Table from '$lib/components/ui/table';
	import { Input } from '$lib/components/ui/input';
	import InputGroupVariants from '$lib/components/ui/input-group/input-group-variants.svelte';
	import DeleteConfirmationModal from '$lib/components/modals/DeleteConfirmationModal.svelte';
	import { CircleAlert, KeyRound, Plus, Trash2, UsersRound } from '@lucide/svelte';

	const tokens = $derived(scim.listTokens());
	const createToken = scim.createToken();
	const deleteToken = scim.deleteToken();

	let showCreate = $state(false);
	let label = $state('');
	let created = $state<{ token: string; baseUrl: string } | null>(null);
	let deleteTarget = $state<{ id: string; label: string } | null>(null);

	const baseURL = $derived(`${page.url.origin}/scim/v2/${workspaceID.current}`);

	async function handleCreate() {
		const trimmed = label.trim();
		if (!trimmed) return;
		try {
			const res = await createToken.mutateAsync({
				workspaceId: workspaceID.current,
				label: trimmed
			});
			created = { token: res.token ?? '', baseUrl: res.baseUrl ?? baseURL };
			label = '';
		} catch {
			// The mutation cache toasts connect errors.
		}
	}

	function handleClose() {
		showCreate = false;
		created = null;
	}
</script>

<DeleteConfirmationModal
	open={deleteTarget !== null}
	title="Revoke Token"
	description="The identity provider using this token will lose access immediately. Provisioning stops until a new token is configured."
	itemName={deleteTarget?.label}
	submitText="Revoke"
	onConfirm={() => {
		if (deleteTarget) {
			deleteToken.mutate({ workspaceId: workspaceID.current, tokenId: deleteTarget.id });
		}
	}}
/>

<Card.Root class="mb-4">
	<Card.Header>
		<Card.Title>Connector</Card.Title>
		<Card.Description>
			Point your identity provider's SCIM client at this URL. It provisions users and groups into
			this workspace as your IdP pushes them.
		</Card.Description>
	</Card.Header>
	<Card.Content class="flex flex-col gap-4">
		<Field.Field>
			<Field.Label>Base URL</Field.Label>
			<Field.Content>
				<InputGroupVariants
					variant="copy-input"
					value={baseURL}
					readonly
					class="font-mono text-xs"
				/>
			</Field.Content>
		</Field.Field>
	</Card.Content>
</Card.Root>

<Card.Root>
	<Card.Header class="flex flex-row items-center justify-between">
		<div class="flex flex-col gap-1.5">
			<Card.Title>Connector tokens</Card.Title>
			<Card.Description>
				Tokens authenticate the connector. The secret is shown once at creation.
			</Card.Description>
		</div>
		<Button size="sm" onclick={() => (showCreate = true)}>
			<Plus data-icon="inline-start" />
			Create Token
		</Button>
	</Card.Header>
	<Card.Content>
		{#if !tokens.data?.length}
			<Empty.Root class="border border-dashed">
				<Empty.Header>
					<Empty.Media variant="icon">
						<KeyRound />
					</Empty.Media>
					<Empty.Title>No connector tokens</Empty.Title>
					<Empty.Description>
						Create a token and paste it into your identity provider to start provisioning.
					</Empty.Description>
				</Empty.Header>
				<Empty.Content>
					<Button variant="outline" onclick={() => (showCreate = true)}>
						<Plus data-icon="inline-start" />
						Create Token
					</Button>
				</Empty.Content>
			</Empty.Root>
		{:else}
			<Table.Root>
				<Table.Header>
					<Table.Row>
						<Table.Head>Label</Table.Head>
						<Table.Head>Created</Table.Head>
						<Table.Head>Last used</Table.Head>
						<Table.Head class="w-12"></Table.Head>
					</Table.Row>
				</Table.Header>
				<Table.Body>
					{#each tokens.data as t (t.id)}
						<Table.Row>
							<Table.Cell class="font-medium">{t.label}</Table.Cell>
							<Table.Cell class="text-muted-foreground">{formatTs(t.createdAt)}</Table.Cell>
							<Table.Cell class="text-muted-foreground">
								{#if t.lastUsedAt}
									{formatTs(t.lastUsedAt, 'withTime')}
								{:else}
									<span class="italic">never</span>
								{/if}
							</Table.Cell>
							<Table.Cell>
								<Button
									size="sm"
									variant="ghost"
									class="text-destructive hover:text-destructive"
									onclick={() => (deleteTarget = { id: t.id ?? '', label: t.label ?? '' })}
									title="Revoke Token"
								>
									<Trash2 />
								</Button>
							</Table.Cell>
						</Table.Row>
					{/each}
				</Table.Body>
			</Table.Root>
		{/if}
	</Card.Content>
</Card.Root>

<Dialog.Root bind:open={showCreate}>
	<Dialog.Content class="sm:max-w-lg">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2">
				<UsersRound size={20} />
				Create Connector Token
			</Dialog.Title>
			<Dialog.Description>
				Authenticate your identity provider against the SCIM connector.
			</Dialog.Description>
		</Dialog.Header>

		{#if !created}
			<Field.FieldGroup>
				<Field.Field>
					<Field.FieldLabel for="scim-token-label">Label</Field.FieldLabel>
					<Field.Content>
						<Input
							id="scim-token-label"
							placeholder="Okta production"
							bind:value={label}
							onkeydown={(e) => e.key === 'Enter' && handleCreate()}
						/>
					</Field.Content>
					<Field.FieldDescription>
						Name the token after the identity provider that uses it.
					</Field.FieldDescription>
				</Field.Field>
				<Button onclick={handleCreate} disabled={createToken.isPending || !label.trim()}>
					Create Token
				</Button>
			</Field.FieldGroup>
		{:else}
			<Field.Field>
				<Field.Label>Bearer Token</Field.Label>
				<Field.Content>
					<InputGroupVariants variant="copy-input" value={created.token} readonly />
				</Field.Content>
			</Field.Field>
			<Alert.Root>
				<CircleAlert size={16} />
				<Alert.Title>Shown only once</Alert.Title>
				<Alert.Description>
					Copy the token now. You will not be able to see it again; revoking it is the only way out
					if it is lost.
				</Alert.Description>
			</Alert.Root>
			<Dialog.Footer>
				<Button onclick={handleClose}>Done</Button>
			</Dialog.Footer>
		{/if}
	</Dialog.Content>
</Dialog.Root>
