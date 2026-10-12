<script lang="ts">
	import { targetAccount as accountApi } from '#lib/api/target-accounts.svelte.js';
	import { serviceAccount as saApi } from '#lib/api/service_account.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import RolePicker from '#lib/components/access/RolePicker.svelte';
	import { SERVICE_ACCOUNT_MAX_ROLE } from '#lib/roles.js';
	import SubjectAccess from '#lib/components/access/SubjectAccess.svelte';
	import CreateServiceAccountTokenModal from '#lib/components/modals/CreateServiceAccountTokenModal.svelte';
	import CopyText from '#lib/components/blocks/CopyText.svelte';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { TagsInput } from '#lib/components/ui/tags-input/index.js';
	import * as Tabs from '#lib/components/ui/tabs/index.js';
	import { Textarea } from '#lib/components/ui/textarea/index.js';
	import { SubjectKind } from '#lib/gen/nokku/v1/target_account_pb.js';
	import {
		ServiceAccountSchema,
		type ServiceAccountToken
	} from '#lib/gen/nokku/v1/service_account_pb.js';
	import { confirm, useAutoSave, useDraft, useSheet } from '#lib/hooks/index.js';
	import { formatTs, toDate } from '#lib/utils.js';
	import {
		Bot,
		FileText,
		KeyRound,
		Plus,
		Settings2,
		ShieldCheck,
		Trash2,
		UserCog
	} from '@lucide/svelte';
	import DangerZone from './DangerZone.svelte';
	import EntitySheet from './EntitySheet.svelte';
	import Section from './Section.svelte';

	const sheet = useSheet();
	const can = user.can();
	const query = saApi.get(() => sheet.id);
	const entity = $derived(query.data);
	const draft = useDraft(ServiceAccountSchema, () => query.data);
	const model = $derived(draft.current);

	const update = saApi.update();
	const remove = saApi.delete();
	const revokeAll = accountApi.revokeSubject();
	const tokens = saApi.tokens.list(() => sheet.id);
	const tokenList = $derived(tokens.data ?? []);
	const revokeToken = saApi.tokens.revoke();

	const autoSave = useAutoSave(() => update.mutateAsync({ ...model }));
	const save = () => autoSave.save();

	let tokenOpen = $state(false);

	const soon = 14 * 24 * 3600 * 1000;
	function expiry(t: ServiceAccountToken): {
		variant: 'destructive' | 'warning' | 'outline';
		text: string;
	} {
		if (!t.expiresAt) return { variant: 'outline', text: 'Never expires' };
		const left = toDate(t.expiresAt).getTime() - Date.now();
		if (left < 0) return { variant: 'destructive', text: 'Expired' };
		return {
			variant: left < soon ? 'warning' : 'outline',
			text: `Expires ${formatTs(t.expiresAt, 'relative')}`
		};
	}

	function askRevoke(t: ServiceAccountToken) {
		if (!entity) return;
		void confirm({
			title: `Revoke ${t.label || 'this token'}?`,
			description: 'Automation using it stops signing in right away. Other tokens keep working.',
			confirmText: 'Revoke',
			onConfirm: () => revokeToken.mutateAsync({ serviceAccountId: entity.id, id: t.id })
		});
	}

	function askDelete() {
		if (!entity) return;
		void confirm({
			title: `Delete ${entity.name}?`,
			description: 'Every token stops working right away and every grant is removed.',
			typeToConfirm: entity.name,
			onConfirm: async () => {
				await remove.mutateAsync({ id: entity.id });
				sheet.close();
			}
		});
	}

	function askRevokeAll() {
		if (!entity) return;
		void confirm({
			title: `Revoke all access for ${entity.name}?`,
			description: 'It is removed from every login account on every target.',
			confirmText: 'Revoke all',
			onConfirm: () =>
				revokeAll.mutateAsync({ subjectId: entity.id, kind: SubjectKind.SERVICE_ACCOUNT })
		});
	}
</script>

<EntitySheet
	open={sheet.open}
	onClose={() => sheet.close()}
	loading={!model}
	missing={query.isError}
	title={model?.name ?? ''}
	onRename={can.edit
		? (name) => {
				if (!model) return;
				model.name = name;
				save();
			}
		: undefined}
	tabs={[
		{ value: 'access', label: 'Access', icon: ShieldCheck },
		{ value: 'tokens', label: 'Tokens', icon: KeyRound },
		{ value: 'settings', label: 'Settings', icon: Settings2 }
	]}
	tab={sheet.tab}
	onTabChange={(t) => (sheet.tab = t)}
	saveState={autoSave.saveState}
	saveHint={sheet.tab === 'settings'}
	readonly={!can.edit}
	meta={{ id: entity?.id, createdAt: entity?.createdAt, updatedAt: entity?.updatedAt }}
>
	{#snippet media()}
		<div class="flex size-10 items-center justify-center rounded-lg bg-chart-5/15 text-chart-5">
			<Bot class="size-5" />
		</div>
	{/snippet}

	{#snippet subtitle()}
		<span>
			{entity?.lastUsedAt ? `Last used ${formatTs(entity.lastUsedAt, 'relative')}` : 'Never used'}
		</span>
		{#if tokens.data}
			<span>· {tokenList.length} {tokenList.length === 1 ? 'token' : 'tokens'}</span>
		{/if}
	{/snippet}

	{#if model && entity}
		<Tabs.Content value="access" class="flex flex-col gap-5">
			<SubjectAccess subjectId={entity.id} kind={SubjectKind.SERVICE_ACCOUNT} name={entity.name} />
		</Tabs.Content>

		<Tabs.Content value="tokens" class="flex flex-col gap-2">
			{#if tokens.isLoading}
				<Skeleton class="h-20 w-full rounded-xl" />
				<Skeleton class="h-20 w-full rounded-xl" />
			{:else if !tokenList.length}
				<Empty.Root class="border border-dashed">
					<Empty.Header>
						<Empty.Media variant="icon"><KeyRound /></Empty.Media>
						<Empty.Title>No tokens</Empty.Title>
						<Empty.Description>
							Automation signs in as this account with a token. Create one and store it in your CI
							secrets.
						</Empty.Description>
					</Empty.Header>
					{#if can.edit}
						<Empty.Content>
							<Button size="sm" variant="outline" onclick={() => (tokenOpen = true)}>
								<Plus data-icon="inline-start" />
								Create token
							</Button>
						</Empty.Content>
					{/if}
				</Empty.Root>
			{:else}
				{#if can.edit}
					<div class="flex justify-end">
						<Button size="sm" variant="outline" onclick={() => (tokenOpen = true)}>
							<Plus data-icon="inline-start" />
							New token
						</Button>
					</div>
				{/if}
				{#each tokenList as t (t.id)}
					{@const e = expiry(t)}
					<div class="flex flex-col gap-2.5 rounded-xl border bg-card p-3">
						<div class="flex items-start gap-3">
							<div class="min-w-0 flex-1">
								<p class="flex flex-wrap items-center gap-1.5 text-sm font-medium">
									<span class="truncate">{t.label || 'Untitled'}</span>
									<Badge variant={e.variant} title={formatTs(t.expiresAt)}>{e.text}</Badge>
								</p>
								<p class="text-xs text-muted-foreground">
									Created {formatTs(t.createdAt, 'relative')}
									· {t.lastUsedAt
										? `last used ${formatTs(t.lastUsedAt, 'relative')}`
										: 'never used'}
								</p>
							</div>
							{#if can.edit}
								<Button
									variant="ghost"
									size="icon-sm"
									aria-label={`Revoke ${t.label || 'token'}`}
									onclick={() => askRevoke(t)}
								>
									<Trash2 />
								</Button>
							{/if}
						</div>
						<div class="text-xs text-muted-foreground">
							ID <CopyText value={t.id} mono />
						</div>
					</div>
				{/each}
			{/if}
		</Tabs.Content>

		<Tabs.Content value="settings" class="flex flex-col divide-y">
			<Section
				title="Workspace role"
				icon={UserCog}
				description="What it may change through the API."
			>
				<RolePicker
					value={model.role}
					max={SERVICE_ACCOUNT_MAX_ROLE}
					disabled={!can.edit}
					onChange={(role) => {
						model.role = role;
						save();
					}}
				/>
			</Section>

			<Section title="Details" icon={FileText}>
				<Field.Group class="gap-4">
					<Field.Field>
						<Field.Label for="sa-description">What it's for</Field.Label>
						<Textarea
							id="sa-description"
							bind:value={model.description}
							placeholder="Deploys from the main branch"
							rows={2}
							disabled={!can.edit}
							oninput={save}
						/>
					</Field.Field>
					<Field.Field>
						<Field.Label for="sa-tags">Tags</Field.Label>
						<TagsInput
							id="sa-tags"
							value={model.tags}
							disabled={!can.edit}
							onValueChange={(tags) => {
								model.tags = tags;
								save();
							}}
							placeholder="ci, ansible"
						/>
					</Field.Field>
				</Field.Group>
			</Section>

			<DangerZone
				actions={can.edit
					? [
							{
								title: 'Revoke all access',
								description: 'Remove it from every login account.',
								label: 'Revoke all',
								onClick: askRevokeAll
							},
							{
								title: 'Delete service account',
								description: 'Every token stops working right away.',
								label: 'Delete',
								onClick: askDelete
							}
						]
					: []}
			/>
		</Tabs.Content>

		<CreateServiceAccountTokenModal
			bind:open={tokenOpen}
			serviceAccountId={entity.id}
			name={entity.name}
		/>
	{/if}
</EntitySheet>
