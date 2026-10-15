<script lang="ts">
	import { sso } from '#lib/api/sso.svelte.js';
	import { workspace } from '#lib/api/workspaces.svelte.js';
	import { OIDCIcon } from '#lib/assets/index.js';
	import LoadError from '#lib/components/blocks/LoadError.svelte';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import * as Item from '#lib/components/ui/item/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { Switch } from '#lib/components/ui/switch/index.js';
	import { WorkspaceSettingsSchema } from '#lib/gen/nokku/v1/workspace_pb.js';
	import { confirm, sheetLink, useCreate, useSheet } from '#lib/hooks/index.js';
	import { requiredPlan, upgradeLink } from '#lib/plans.js';
	import { create as createMessage } from '@bufbuild/protobuf';
	import { ArrowRight, ChevronRight, KeyRound, Plus } from '@lucide/svelte';
	import AddProviderModal from './AddProviderModal.svelte';
	import ProviderSheet from './ProviderSheet.svelte';
	import TestResult from './TestResult.svelte';

	interface Props {
		readonly?: boolean;
		mode?: string;
		/** Undefined while the plan loads. */
		enforceAvailable?: boolean;
	}

	let { readonly = false, mode, enforceAvailable }: Props = $props();

	const providers = sso.list();
	const ws = workspace.get();
	const update = workspace.update();
	const create = useCreate();
	const sheet = useSheet();

	const enforced = $derived(ws.data?.settings?.enforceSso ?? false);
	const anyEnabled = $derived((providers.data ?? []).some((p) => p.enabled));
	const locked = $derived(enforceAvailable === false && !enforced);
	const upgrade = $derived(upgradeLink('enforce_sso', mode));

	function setEnforced(on: boolean) {
		if (!ws.data?.settings) return;
		const settings = createMessage(WorkspaceSettingsSchema, ws.data.settings);
		settings.enforceSso = on;
		update.mutate({ settings });
	}
</script>

{#if !readonly}
	<AddProviderModal bind:open={create.open} />
	<TestResult providers={providers.data} {mode} />
{/if}
<ProviderSheet {mode} />

<div class="flex flex-col gap-4">
	<Card.Root>
		<Card.Header>
			<Card.Title><h2>Identity providers</h2></Card.Title>
			<Card.Description>
				OpenID Connect providers that can sign people in here. Each shows up as a button on the
				sign-in page.
			</Card.Description>
			{#if !readonly}
				<Card.Action>
					<Button size="sm" onclick={() => (create.open = true)}>
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
				<LoadError
					title="Providers did not load"
					description="Sign-in through them is not affected."
					onRetry={() => providers.refetch()}
				/>
			{:else if !providers.data?.length}
				<Empty.Root class="border border-dashed">
					<Empty.Header>
						<Empty.Media variant="icon"><KeyRound /></Empty.Media>
						<Empty.Title>No provider yet</Empty.Title>
						<Empty.Description>
							Okta, Entra ID, Google Workspace and any other OpenID Connect provider work. Adding
							one shows the redirect URI to register with it.
						</Empty.Description>
					</Empty.Header>
				</Empty.Root>
			{:else}
				<Item.Group class="divide-y overflow-hidden rounded-lg border">
					{#each providers.data as p (p.providerId)}
						<Item.Root size="sm" class="rounded-none">
							{#snippet child({ props })}
								<a
									{...props}
									href={sheetLink(p.providerId)}
									onclick={(e) => {
										if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
										e.preventDefault();
										void sheet.show(p.providerId);
									}}
								>
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
									<ChevronRight class="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
								</a>
							{/snippet}
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
										'From now on only your identity providers sign people in. The owner can still use a passkey or an email link. Test a provider first, so you know sign-in works.',
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
