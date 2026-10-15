<script lang="ts">
	import { scim } from '#lib/api/scim.svelte.js';
	import FormModal from '#lib/components/blocks/FormModal.svelte';
	import LoadError from '#lib/components/blocks/LoadError.svelte';
	import SecretReveal from '#lib/components/blocks/SecretReveal.svelte';
	import InputGroupVariants from '#lib/components/blocks/InputGroupVariants.svelte';
	import * as Alert from '#lib/components/ext/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import * as Item from '#lib/components/ui/item/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { confirm } from '#lib/hooks/index.js';
	import { requiredPlan, upgradeLink } from '#lib/plans.js';
	import { formatTs } from '#lib/utils.js';
	import { ArrowRight, KeyRound, Plus, ShieldAlert, Trash2, UsersRound } from '@lucide/svelte';

	interface Props {
		readonly?: boolean;
		mode?: string;
		/** Whether the plan has SCIM, undefined while it loads. */
		available?: boolean;
	}

	let { readonly = false, mode, available }: Props = $props();

	const tokens = scim.listTokens();
	const createToken = scim.createToken();
	const deleteToken = scim.deleteToken();
	const scimURL = scim.baseUrl();

	let createOpen = $state(false);
	let label = $state('');
	let created = $state<{ token: string; baseUrl: string }>();

	const plan = $derived(requiredPlan('scim', mode));
	const upgrade = $derived(upgradeLink('scim', mode));
	// Tokens keep provisioning after a downgrade, so they stay listed and revocable.
	const lapsed = $derived(available === false && !!tokens.data?.length);

	// Stays open to show the secret once.
	async function create() {
		const res = await createToken.mutateAsync({ label: label.trim() });
		created = { token: res.token, baseUrl: res.baseUrl };
		label = '';
		return false;
	}

	function revoke(id: string, name: string) {
		void confirm({
			title: `Revoke ${name || 'this token'}?`,
			description:
				'The identity provider using it loses access right away. Provisioning stops until it gets a new token.',
			confirmText: 'Revoke',
			onConfirm: () => deleteToken.mutateAsync({ id })
		});
	}
</script>

{#snippet upgradeButton()}
	{#if !readonly}
		<Button
			variant="outline"
			size="sm"
			href={upgrade.href}
			target={upgrade.external ? '_blank' : undefined}
			rel={upgrade.external ? 'noopener' : undefined}
		>
			{upgrade.label}
			<ArrowRight data-icon="inline-end" />
		</Button>
	{/if}
{/snippet}

<FormModal
	bind:open={createOpen}
	title="Create a SCIM token"
	description="Your identity provider sends it with every provisioning request."
	icon={UsersRound}
	onOpenChange={(open) => !open && (created = undefined)}
	onSubmit={create}
	submitLabel="Create token"
	submitDisabled={!label.trim()}
>
	{#if created}
		<SecretReveal
			values={[
				{ label: 'Base URL', value: created.baseUrl },
				{ label: 'Bearer token', value: created.token }
			]}
			note="Paste both into your identity provider. The token is only shown once. If it gets lost, revoke it and create a new one."
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

{#if available === undefined || tokens.isLoading}
	<div class="flex flex-col gap-4">
		<Skeleton class="h-32 w-full rounded-xl" />
		<Skeleton class="h-40 w-full rounded-xl" />
	</div>
{:else if available === false && !tokens.isError && !tokens.data?.length}
	<Empty.Root class="border border-dashed">
		<Empty.Header>
			<Empty.Media variant="icon"><UsersRound /></Empty.Media>
			<Empty.Title>Available on {plan}</Empty.Title>
			<Empty.Description>
				SCIM keeps users and groups in sync with your identity provider, so leavers lose access
				without anyone touching Nokku. Okta, Entra ID and other SCIM directories work.
			</Empty.Description>
		</Empty.Header>
		<Empty.Content>{@render upgradeButton()}</Empty.Content>
	</Empty.Root>
{:else}
	<div class="flex flex-col gap-4">
		{#if lapsed}
			<Alert.Root variant="warning">
				<ShieldAlert />
				<Alert.Title>SCIM is not on your plan anymore</Alert.Title>
				<Alert.Description class="flex flex-col items-start gap-3">
					<p>
						The tokens below still provision users until you revoke them. New tokens need {plan}.
					</p>
					{@render upgradeButton()}
				</Alert.Description>
			</Alert.Root>
		{/if}

		<Card.Root>
			<Card.Header>
				<Card.Title><h2>SCIM endpoint</h2></Card.Title>
				<Card.Description>
					Point your identity provider's SCIM client here. It pushes users and groups into this
					workspace.
				</Card.Description>
			</Card.Header>
			<Card.Content>
				<Field.Field>
					<Field.Label for="scim-base-url">Base URL</Field.Label>
					{#if scimURL.data}
						<InputGroupVariants
							variant="copy-input"
							value={scimURL.data}
							readonly
							class="font-mono text-xs"
							copyLabel="SCIM base URL"
							inputProps={{ id: 'scim-base-url' }}
						/>
					{:else if scimURL.isError}
						<p class="text-sm text-destructive" role="alert">The base URL did not load.</p>
					{:else}
						<Skeleton class="h-8 w-full" />
					{/if}
					<Field.Description>
						Okta calls it the SCIM connector base URL, Entra ID the tenant URL.
					</Field.Description>
				</Field.Field>
			</Card.Content>
		</Card.Root>

		<Card.Root>
			<Card.Header>
				<Card.Title><h2>Bearer tokens</h2></Card.Title>
				<Card.Description>
					Each one is shown once, when you create it. Entra ID calls it the secret token.
				</Card.Description>
				{#if !readonly && available}
					<Card.Action>
						<Button size="sm" onclick={() => (createOpen = true)}>
							<Plus data-icon="inline-start" />
							Create token
						</Button>
					</Card.Action>
				{/if}
			</Card.Header>
			<Card.Content>
				{#if tokens.isError}
					<LoadError
						title="Tokens did not load"
						description="Provisioning with them is not affected."
						onRetry={() => tokens.refetch()}
					/>
				{:else if !tokens.data?.length}
					<Empty.Root class="border border-dashed">
						<Empty.Header>
							<Empty.Media variant="icon"><KeyRound /></Empty.Media>
							<Empty.Title>No tokens yet</Empty.Title>
							<Empty.Description>
								Create one, then paste it into your identity provider together with the base URL
								above.
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
								{#if !readonly}
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
								{/if}
							</Item.Root>
						{/each}
					</Item.Group>
				{/if}
			</Card.Content>
		</Card.Root>
	</div>
{/if}
