<script lang="ts">
	import { sso, testHref } from '#lib/api/sso.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import { OIDCIcon } from '#lib/assets/index.js';
	import FormModal from '#lib/components/blocks/FormModal.svelte';
	import InputGroupVariants from '#lib/components/blocks/InputGroupVariants.svelte';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import DangerZone from '#lib/components/sheets/DangerZone.svelte';
	import DetailList from '#lib/components/sheets/DetailList.svelte';
	import EntitySheet from '#lib/components/sheets/EntitySheet.svelte';
	import Section from '#lib/components/sheets/Section.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import * as Item from '#lib/components/ui/item/index.js';
	import { Switch } from '#lib/components/ui/switch/index.js';
	import * as Tabs from '#lib/components/ui/tabs/index.js';
	import { TagsInput } from '#lib/components/ui/tags-input/index.js';
	import { SSOProviderSchema } from '#lib/gen/nokku/v1/sso_pb.js';
	import { confirm, useAutoSave, useDraft, useSheet } from '#lib/hooks/index.js';
	import { FlaskConical, Globe, Info, KeyRound, LogIn, Plug, Settings2 } from '@lucide/svelte';
	import RedirectURI from './RedirectURI.svelte';

	let { mode }: { mode?: string } = $props();

	const sheet = useSheet();
	const can = user.can();
	const providers = sso.list();
	const entity = $derived(providers.data?.find((p) => p.providerId === sheet.id));
	const draft = useDraft(
		SSOProviderSchema,
		() => entity,
		(p) => p.providerId
	);
	const model = $derived(draft.current);

	const put = sso.put();
	const remove = sso.delete();

	const standardScopes = ['openid', 'email', 'profile'];
	const scopesValid = $derived(
		!!model && model.scopes.includes('openid') && model.scopes.includes('email')
	);

	// An empty secret keeps the stored one.
	async function request(connection?: {
		issuerUrl: string;
		clientId: string;
		clientSecret: string;
	}) {
		if (!model) return;
		await put.mutateAsync({
			providerId: model.providerId,
			name: model.name,
			enabled: model.enabled,
			issuerUrl: model.issuerUrl,
			clientId: model.clientId,
			scopes: model.scopes,
			jitProvisioning: model.jitProvisioning,
			clientSecret: '',
			...connection
		});
	}
	const autoSave = useAutoSave(() => request());
	const save = () => autoSave.save();

	// Creating accounts lets anyone the provider knows in, so turning it on asks first.
	function setJIT(on: boolean) {
		if (!model) return;
		if (!on) {
			model.jitProvisioning = false;
			save();
			return;
		}
		void confirm({
			title: `Create accounts through ${model.name}?`,
			description: `Anyone who can sign in to ${model.name} gets a member account here${mode === 'saas' ? ', and each one takes a seat' : ''}. Leave it off to invite people first.`,
			confirmText: 'Create accounts',
			onConfirm: () => {
				if (!model) return;
				model.jitProvisioning = true;
				save();
			}
		});
	}

	let connectionOpen = $state(false);
	let connection = $state({ issuerUrl: '', clientId: '', clientSecret: '' });
	const issuer = $derived(connection.issuerUrl.trim());
	const issuerValid = $derived(/^https?:\/\//.test(issuer) && URL.canParse(issuer));
	const issuerChanged = $derived(!!model && issuer !== model.issuerUrl);

	function editConnection() {
		if (!model) return;
		connection = { issuerUrl: model.issuerUrl, clientId: model.clientId, clientSecret: '' };
		connectionOpen = true;
	}

	async function saveConnection() {
		const next = {
			issuerUrl: issuer,
			clientId: connection.clientId.trim(),
			clientSecret: connection.clientSecret.trim()
		};
		await autoSave.track(() => request(next));
		if (!model) return;
		model.issuerUrl = next.issuerUrl;
		model.clientId = next.clientId;
	}

	function askRemove() {
		if (!model) return;
		const p = model;
		void confirm({
			title: `Remove ${p.name}?`,
			description:
				'Nobody can sign in through it anymore. Accounts it created stay, and keep their other sign-in methods.',
			confirmText: 'Remove',
			onConfirm: async () => {
				await remove.mutateAsync({ providerId: p.providerId });
				sheet.close();
			}
		});
	}
</script>

<FormModal
	bind:open={connectionOpen}
	title="Change connection"
	description="Use it when the app moved or the secret was rotated."
	icon={Plug}
	onSubmit={saveConnection}
	submitLabel="Save"
	submitDisabled={!issuerValid ||
		!connection.clientId.trim() ||
		(issuerChanged && !connection.clientSecret.trim())}
	classModal="sm:max-w-lg"
>
	<Field.Field data-invalid={!!issuer && !issuerValid}>
		<Field.Label for="provider-issuer">Issuer URL</Field.Label>
		<Input
			id="provider-issuer"
			bind:value={connection.issuerUrl}
			class="font-mono"
			aria-invalid={!!issuer && !issuerValid}
		/>
		{#if issuerChanged}
			<Field.Description>
				A new issuer unlinks everyone who signed in through the old one, and needs its secret.
			</Field.Description>
		{/if}
	</Field.Field>
	<div class="grid gap-4 sm:grid-cols-2">
		<Field.Field>
			<Field.Label for="provider-client-id">Client ID</Field.Label>
			<Input id="provider-client-id" bind:value={connection.clientId} class="font-mono" />
		</Field.Field>
		<Field.Field>
			<Field.Label for="provider-secret">Client secret</Field.Label>
			<InputGroupVariants
				variant="password"
				bind:value={connection.clientSecret}
				placeholder={issuerChanged ? ' ' : 'Unchanged'}
				inputProps={{ id: 'provider-secret', autocomplete: 'off' }}
			/>
		</Field.Field>
	</div>
</FormModal>

<EntitySheet
	open={sheet.open}
	onClose={() => sheet.close()}
	loading={providers.isLoading || (!!entity && !model)}
	missing={providers.isError || (!!providers.data && !entity)}
	title={model?.name ?? ''}
	onRename={can.own
		? (name) => {
				if (!model) return;
				model.name = name;
				save();
			}
		: undefined}
	detail={entity && URL.canParse(entity.issuerUrl) ? new URL(entity.issuerUrl).host : undefined}
	detailMono
	tabs={[
		{ value: 'overview', label: 'Overview', icon: Info },
		{ value: 'settings', label: 'Settings', icon: Settings2 }
	]}
	tab={sheet.tab}
	onTabChange={(t) => (sheet.tab = t)}
	saveState={autoSave.saveState}
	onRetry={autoSave.retry}
	saveHint={sheet.tab === 'settings'}
	readonly={!can.own}
	meta={{ id: entity?.providerId, createdAt: entity?.createdAt, updatedAt: entity?.updatedAt }}
>
	{#snippet media()}
		<div class="grid size-10 place-items-center rounded-lg bg-muted">
			<OIDCIcon class="size-5" />
		</div>
	{/snippet}

	{#snippet subtitle()}
		{#if model && !model.enabled}
			<Badge variant="muted">Disabled</Badge>
		{/if}
		{#if model?.jitProvisioning}
			<Badge variant="outline">Creates accounts</Badge>
		{/if}
	{/snippet}

	{#snippet actions()}
		{#if can.own && model}
			<Button size="sm" href={testHref(model.providerId)} data-sveltekit-reload>
				<FlaskConical data-icon="inline-start" />
				Test sign-in
			</Button>
		{/if}
	{/snippet}

	{#if model}
		<Tabs.Content value="overview" class="flex flex-col divide-y">
			<Section
				title="At the provider"
				icon={Globe}
				description={mode === 'saas'
					? 'Each workspace needs its own app at the provider.'
					: 'It follows NOKKU_BASE_URL. Update the provider when the address changes.'}
			>
				<RedirectURI id="provider-redirect" />
			</Section>
			<Section title="Connection" icon={Plug}>
				<DetailList
					items={[
						{ label: 'Issuer', value: model.issuerUrl, mono: true, copy: true, wide: true },
						{ label: 'Client ID', value: model.clientId, mono: true, copy: true },
						{ label: 'Scopes', value: model.scopes.join(' '), mono: true }
					]}
				/>
			</Section>
		</Tabs.Content>

		<Tabs.Content value="settings" class="flex flex-col divide-y">
			<Section title="Sign-in" icon={LogIn}>
				<Field.Group class="gap-4">
					<Field.Field orientation="horizontal">
						<Field.Content>
							<Field.Label for="provider-enabled">Enabled</Field.Label>
							<Field.Description>Shown on the sign-in page.</Field.Description>
						</Field.Content>
						<Switch
							id="provider-enabled"
							checked={model.enabled}
							disabled={!can.own}
							onCheckedChange={(v) => {
								model.enabled = v;
								save();
							}}
						/>
					</Field.Field>
					<Field.Field orientation="horizontal">
						<Field.Content>
							<Field.Label for="provider-jit">Create accounts on first sign-in</Field.Label>
							<Field.Description>Off means you invite people first.</Field.Description>
						</Field.Content>
						<Switch
							id="provider-jit"
							checked={model.jitProvisioning}
							disabled={!can.own}
							onCheckedChange={setJIT}
						/>
					</Field.Field>
					<Field.Field data-invalid={!scopesValid}>
						<Field.Label for="provider-scopes">Scopes</Field.Label>
						<TagsInput
							id="provider-scopes"
							value={model.scopes}
							onValueChange={(v) => {
								model.scopes = v;
								if (scopesValid) save();
							}}
							icon={KeyRound}
							suggestions={standardScopes}
							separator={/[\s,]+/}
							disabled={!can.own}
						/>
						<Field.Description>openid and email are required.</Field.Description>
					</Field.Field>
				</Field.Group>
			</Section>

			{#if can.own}
				<Section title="Connection" icon={Plug}>
					<Item.Root variant="outline" size="sm">
						<Item.Content>
							<Item.Title>Issuer, client ID and secret</Item.Title>
							<Item.Description
								>Change them when the app moves or the secret rotates.</Item.Description
							>
						</Item.Content>
						<Item.Actions>
							<Button variant="outline" size="sm" onclick={editConnection}>Change</Button>
						</Item.Actions>
					</Item.Root>
				</Section>

				<DangerZone
					actions={[
						{
							title: 'Remove provider',
							description: 'Nobody signs in through it anymore. Accounts it created stay.',
							label: 'Remove',
							onClick: askRemove
						}
					]}
				/>
			{/if}
		</Tabs.Content>
	{/if}
</EntitySheet>
