<script lang="ts">
	import { sso } from '#lib/api/sso.svelte.js';
	import { workspace } from '#lib/api/workspaces.svelte.js';
	import { OIDCIcon } from '#lib/assets/index.js';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import * as Item from '#lib/components/ui/item/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { Switch } from '#lib/components/ui/switch/index.js';
	import { WorkspaceSettingsSchema } from '#lib/gen/nokku/v1/workspace_pb.js';
	import type { SSOProvider } from '#lib/gen/nokku/v1/sso_pb.js';
	import { confirm } from '#lib/hooks/index.js';
	import { requiredPlan, upgradeLink } from '#lib/plans.js';
	import { create } from '@bufbuild/protobuf';
	import {
		ArrowRight,
		KeyRound,
		Pencil,
		Plus,
		RotateCw,
		Trash2,
		TriangleAlert
	} from '@lucide/svelte';
	import ProviderModal from './ProviderModal.svelte';
	import RedirectURI from './RedirectURI.svelte';

	interface Props {
		readonly?: boolean;
		mode?: string;
		/** Undefined while the plan loads. */
		enforceAvailable?: boolean;
	}

	let { readonly = false, mode, enforceAvailable }: Props = $props();

	const providers = sso.list();
	const remove = sso.delete();
	const ws = workspace.get();
	const update = workspace.update();

	let open = $state(false);
	let editing = $state<SSOProvider>();

	const enforced = $derived(ws.data?.settings?.enforceSso ?? false);
	const anyEnabled = $derived((providers.data ?? []).some((p) => p.enabled));
	const locked = $derived(enforceAvailable === false && !enforced);
	const upgrade = $derived(upgradeLink('enforce_sso', mode));

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
		if (!ws.data?.settings) return;
		const settings = create(WorkspaceSettingsSchema, ws.data.settings);
		settings.enforceSso = on;
		update.mutate({ settings });
	}
</script>

<ProviderModal bind:open provider={editing} {mode} />

<div class="flex flex-col gap-4">
	<Card.Root>
		<Card.Header>
			<Card.Title><h2>Redirect URI</h2></Card.Title>
			<Card.Description>
				{#if mode === 'saas'}
					Register it with every provider before you add one here. It belongs to this workspace,
					another workspace needs its own app at the provider.
				{:else}
					Register it with every provider before you add one here. It follows
					<code class="font-mono text-foreground">NOKKU_BASE_URL</code>, so update your providers
					when the address changes.
				{/if}
			</Card.Description>
		</Card.Header>
		<Card.Content>
			<RedirectURI id="callback-url" />
		</Card.Content>
	</Card.Root>

	<Card.Root>
		<Card.Header>
			<Card.Title><h2>Identity providers</h2></Card.Title>
			<Card.Description>
				OpenID Connect providers that can sign people in here. Each shows up as a button on the
				sign-in page.
			</Card.Description>
			{#if !readonly}
				<Card.Action>
					<Button size="sm" onclick={add}>
						<Plus data-icon="inline-start" />
						Add provider
					</Button>
				</Card.Action>
			{/if}
		</Card.Header>
		<Card.Content>
			{#if providers.isLoading}
				<Skeleton class="h-16 w-full" />
			{:else if providers.isError}
				<Empty.Root class="border border-dashed">
					<Empty.Header>
						<Empty.Media variant="icon" class="bg-destructive/10 text-destructive">
							<TriangleAlert />
						</Empty.Media>
						<Empty.Title>Providers did not load</Empty.Title>
						<Empty.Description>Sign-in through them is not affected.</Empty.Description>
					</Empty.Header>
					<Empty.Content>
						<Button variant="outline" size="sm" onclick={() => providers.refetch()}>
							<RotateCw data-icon="inline-start" />
							Try again
						</Button>
					</Empty.Content>
				</Empty.Root>
			{:else if !providers.data?.length}
				<Empty.Root class="border border-dashed">
					<Empty.Header>
						<Empty.Media variant="icon"><KeyRound /></Empty.Media>
						<Empty.Title>No provider yet</Empty.Title>
						<Empty.Description>
							Create an OpenID Connect app in Okta, Entra ID, Google Workspace or any other provider
							with the redirect URI above, then add it here.
						</Empty.Description>
					</Empty.Header>
				</Empty.Root>
			{:else}
				<Item.Group class="divide-y rounded-lg border">
					{#each providers.data as p (p.providerId)}
						<Item.Root size="sm" class="rounded-none">
							<Item.Media variant="icon"><OIDCIcon /></Item.Media>
							<Item.Content class="min-w-0">
								<Item.Title class="flex flex-wrap items-center gap-2">
									{p.name || p.providerId}
									{#if !p.enabled}<Badge variant="muted">Disabled</Badge>{/if}
									{#if p.jitProvisioning}<Badge variant="outline">Creates accounts</Badge>{/if}
								</Item.Title>
								<Item.Description class="truncate font-mono text-xs" title={p.issuerUrl}>
									{p.issuerUrl}
								</Item.Description>
							</Item.Content>
							{#if !readonly}
								<Item.Actions>
									<Button
										size="icon-sm"
										variant="ghost"
										aria-label={`Edit ${p.name || p.providerId}`}
										onclick={() => edit(p)}
									>
										<Pencil />
									</Button>
									<Button
										size="icon-sm"
										variant="ghost"
										aria-label={`Remove ${p.name || p.providerId}`}
										onclick={() => askRemove(p)}
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

	<Card.Root>
		<Card.Header>
			<Card.Title class="flex flex-wrap items-center gap-2">
				<h2>Require single sign-on</h2>
				{#if locked}<Badge variant="outline">{requiredPlan('enforce_sso', mode)}</Badge>{/if}
			</Card.Title>
			<Card.Description>
				Passkeys and email links stop working for everyone but the owner. The owner keeps both to
				fix a broken provider, so protect the owner's mailbox and passkey.
			</Card.Description>
			<Card.Action>
				<Switch
					checked={enforced}
					disabled={readonly ||
						!ws.data ||
						update.isPending ||
						enforceAvailable === undefined ||
						locked ||
						(!enforced && !anyEnabled)}
					aria-label="Require single sign-on"
					aria-describedby={locked ? 'enforce-locked' : undefined}
					onCheckedChange={(on) =>
						on
							? confirm({
									title: 'Require single sign-on?',
									description:
										'From now on only your identity providers sign people in. The owner can still use a passkey or an email link.',
									confirmText: 'Require it',
									onConfirm: () => setEnforced(true)
								})
							: setEnforced(false)}
				/>
			</Card.Action>
		</Card.Header>
		{#if locked}
			<Card.Footer class="flex flex-wrap items-center justify-between gap-2 border-t">
				<p id="enforce-locked" class="text-sm text-muted-foreground">
					{mode === 'saas'
						? `Your plan does not include it. ${requiredPlan('enforce_sso', mode)} does.`
						: 'It needs an Enterprise license on this server.'}
				</p>
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
			</Card.Footer>
		{:else if !readonly && !enforced && !anyEnabled && providers.data}
			<Card.Footer class="border-t">
				<p class="text-sm text-muted-foreground">Add and enable a provider first.</p>
			</Card.Footer>
		{/if}
	</Card.Root>
</div>
