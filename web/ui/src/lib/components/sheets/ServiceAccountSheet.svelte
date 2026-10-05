<script lang="ts">
	import { principal as principalApi } from '#lib/api/principals.svelte.js';
	import { serviceAccount as saApi } from '#lib/api/service_account.svelte.js';
	import RolePicker from '#lib/components/access/RolePicker.svelte';
	import SubjectAccess from '#lib/components/access/SubjectAccess.svelte';
	import * as Alert from '#lib/components/ui/alert/index.js';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { TagsInput } from '#lib/components/ui/tags-input/index.js';
	import * as Tabs from '#lib/components/ui/tabs/index.js';
	import { Textarea } from '#lib/components/ui/textarea/index.js';
	import { SubjectKind } from '#lib/gen/nokku/v1/principal_pb.js';
	import { ServiceAccountSchema } from '#lib/gen/nokku/v1/service_account_pb.js';
	import { confirm, useAutoSave, useDraft, useSheet } from '#lib/hooks/index.js';
	import { formatTs, toDate } from '#lib/utils.js';
	import { Bot, FileText, Settings2, ShieldCheck, TriangleAlert, UserCog } from '@lucide/svelte';
	import DangerZone from './DangerZone.svelte';
	import EntitySheet from './EntitySheet.svelte';
	import Section from './Section.svelte';

	const sheet = useSheet();
	const query = saApi.get(() => sheet.id);
	const entity = $derived(query.data);
	const draft = useDraft(ServiceAccountSchema, () => query.data);
	const model = $derived(draft.current);

	const update = saApi.update();
	const remove = saApi.delete();
	const revokeAll = principalApi.revokeSubject();

	const autoSave = useAutoSave(() => update.mutateAsync({ ...model }));
	const save = () => autoSave.save();

	const expiresAt = $derived(entity?.expiresAt ? toDate(entity.expiresAt) : undefined);
	const expired = $derived(!!expiresAt && expiresAt.getTime() < Date.now());
	const expiresSoon = $derived(
		!!expiresAt && !expired && expiresAt.getTime() - Date.now() < 14 * 24 * 3600 * 1000
	);

	function askDelete() {
		if (!entity) return;
		void confirm({
			title: `Delete ${entity.name}?`,
			description: 'Its token stops working right away and every grant is removed.',
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
	onRename={(name) => {
		if (!model) return;
		model.name = name;
		save();
	}}
	tabs={[
		{ value: 'access', label: 'Access', icon: ShieldCheck },
		{ value: 'settings', label: 'Settings', icon: Settings2 }
	]}
	tab={sheet.tab}
	onTabChange={(t) => (sheet.tab = t)}
	saveState={autoSave.saveState}
	saveHint={sheet.tab === 'settings'}
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
		{#if expired}
			<Badge variant="destructive">Expired</Badge>
		{:else if expiresSoon}
			<Badge variant="warning" title={formatTs(entity?.expiresAt)}>
				Expires {formatTs(entity?.expiresAt, 'relative')}
			</Badge>
		{:else}
			<span>
				· {entity?.expiresAt ? `Expires ${formatTs(entity.expiresAt)}` : 'Never expires'}
			</span>
		{/if}
	{/snippet}

	{#if model && entity}
		<Tabs.Content value="access" class="flex flex-col gap-5">
			{#if expired}
				<Alert.Root variant="destructive">
					<TriangleAlert />
					<Alert.Title>The token has expired</Alert.Title>
					<Alert.Description>
						Automation using it is failing. Create a new service account to get a fresh token.
					</Alert.Description>
				</Alert.Root>
			{/if}
			<SubjectAccess subjectId={entity.id} kind={SubjectKind.SERVICE_ACCOUNT} name={entity.name} />
		</Tabs.Content>

		<Tabs.Content value="settings" class="flex flex-col divide-y">
			<Section
				title="Workspace role"
				icon={UserCog}
				description="What it may change through the API."
			>
				<RolePicker
					value={model.roleName}
					onChange={(role) => {
						model.roleName = role;
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
							oninput={save}
						/>
					</Field.Field>
					<Field.Field>
						<Field.Label for="sa-tags">Tags</Field.Label>
						<TagsInput
							id="sa-tags"
							value={model.tags}
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
				actions={[
					{
						title: 'Revoke all access',
						description: 'Remove it from every login account.',
						label: 'Revoke all',
						onClick: askRevokeAll
					},
					{
						title: 'Delete service account',
						description: 'The token stops working immediately.',
						label: 'Delete',
						onClick: askDelete
					}
				]}
			/>
		</Tabs.Content>
	{/if}
</EntitySheet>
