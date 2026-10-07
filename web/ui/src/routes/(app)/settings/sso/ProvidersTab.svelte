<script lang="ts">
	import { page } from '$app/state';
	import { sso } from '#lib/api/sso.svelte.js';
	import { workspace } from '#lib/api/workspaces.svelte.js';
	import { OIDCIcon } from '#lib/assets/index.js';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import InputGroupVariants from '#lib/components/blocks/InputGroupVariants.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import * as Item from '#lib/components/ui/item/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { Switch } from '#lib/components/ui/switch/index.js';
	import { WorkspaceSettingsSchema } from '#lib/gen/nokku/v1/workspace_pb.js';
	import type { SSOProvider } from '#lib/gen/nokku/v1/sso_pb.js';
	import { confirm } from '#lib/hooks/index.js';
	import { create } from '@bufbuild/protobuf';
	import { KeyRound, Pencil, Plus, Trash2 } from '@lucide/svelte';
	import ProviderModal from './ProviderModal.svelte';

	let { readonly = false }: { readonly?: boolean } = $props();

	const providers = sso.list();
	const remove = sso.delete();
	const ws = workspace.get();
	const update = workspace.update();

	let open = $state(false);
	let editing = $state<SSOProvider>();

	const callbackURL = page.url.origin + '/oidc/callback';
	const enforced = $derived(ws.data?.settings?.enforceSso ?? false);
	const anyEnabled = $derived((providers.data ?? []).some((p) => p.enabled));

	function add() {
		editing = undefined;
		open = true;
	}

	function edit(p: SSOProvider) {
		editing = p;
		open = true;
	}

	function askRemove(p: SSOProvider) {
		void confirm({
			title: `Remove ${p.name || p.providerId}?`,
			description:
				'Nobody can sign in through it anymore. Accounts it created stay, and keep their other sign-in methods.',
			confirmText: 'Remove',
			onConfirm: () => remove.mutateAsync({ providerId: p.providerId })
		});
	}

	function setEnforced(on: boolean) {
		const settings = create(WorkspaceSettingsSchema, ws.data?.settings);
		settings.enforceSso = on;
		update.mutate({ settings });
	}
</script>

<ProviderModal bind:open provider={editing} />

<div class="flex flex-col gap-4">
	<Card.Root>
		<Card.Header>
			<Card.Title>Identity providers</Card.Title>
			<Card.Description>
				OpenID Connect providers that can sign people in here. Each shows up as a button on the
				sign-in page.
			</Card.Description>
			<Card.Action>
				<Button size="sm" disabled={readonly} onclick={add}>
					<Plus data-icon="inline-start" />
					Add provider
				</Button>
			</Card.Action>
		</Card.Header>
		<Card.Content>
			{#if providers.isLoading}
				<Skeleton class="h-16 w-full" />
			{:else if !providers.data?.length}
				<Empty.Root class="border border-dashed">
					<Empty.Header>
						<Empty.Media variant="icon"><KeyRound /></Empty.Media>
						<Empty.Title>No provider yet</Empty.Title>
						<Empty.Description>
							Add Okta, Entra ID, Google Workspace or any other OpenID Connect provider.
						</Empty.Description>
					</Empty.Header>
				</Empty.Root>
			{:else}
				<Item.Group class="divide-y rounded-lg border">
					{#each providers.data as p (p.providerId)}
						<Item.Root size="sm" class="rounded-none">
							<Item.Media variant="icon"><OIDCIcon /></Item.Media>
							<Item.Content>
								<Item.Title class="flex items-center gap-2">
									{p.name || p.providerId}
									{#if !p.enabled}<Badge variant="muted">Disabled</Badge>{/if}
									{#if p.jitProvisioning}<Badge variant="outline">Creates accounts</Badge>{/if}
								</Item.Title>
								<Item.Description class="truncate font-mono text-xs">
									{p.providerId} · {p.issuerUrl}
								</Item.Description>
							</Item.Content>
							<Item.Actions>
								<Button
									size="icon-sm"
									variant="ghost"
									aria-label={`Edit ${p.name || p.providerId}`}
									disabled={readonly}
									onclick={() => edit(p)}
								>
									<Pencil />
								</Button>
								<Button
									size="icon-sm"
									variant="ghost"
									aria-label={`Remove ${p.name || p.providerId}`}
									disabled={readonly}
									onclick={() => askRemove(p)}
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

	<Card.Root>
		<Card.Header>
			<Card.Title>Require single sign-on</Card.Title>
			<Card.Description>
				Passkeys and email links stop working for everyone. Only accounts that sign in through a
				provider get in, so turn it on after your own sign-in works.
			</Card.Description>
			<Card.Action>
				<Switch
					checked={enforced}
					disabled={readonly || update.isPending || (!enforced && !anyEnabled)}
					aria-label="Require single sign-on"
					onCheckedChange={(on) =>
						on
							? confirm({
									title: 'Require single sign-on?',
									description:
										'From now on only your identity providers sign people in. Make sure your own account has signed in through one, or you lock yourself out.',
									confirmText: 'Require it',
									onConfirm: () => setEnforced(true)
								})
							: setEnforced(false)}
				/>
			</Card.Action>
		</Card.Header>
	</Card.Root>

	<Card.Root>
		<Card.Header>
			<Card.Title>Redirect URI</Card.Title>
			<Card.Description>
				Register this callback with every provider. It is the same for all of them.
			</Card.Description>
		</Card.Header>
		<Card.Content>
			<Field.Field>
				<Field.Label for="callback-url">Redirect URI</Field.Label>
				<InputGroupVariants
					variant="copy-input"
					value={callbackURL}
					readonly
					class="font-mono text-xs"
					inputProps={{ id: 'callback-url' }}
				/>
			</Field.Field>
		</Card.Content>
	</Card.Root>
</div>
