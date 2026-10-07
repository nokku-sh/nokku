<script lang="ts">
	import { principal as principalApi } from '#lib/api/principals.svelte.js';
	import { team as teamApi } from '#lib/api/team.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import { users } from '#lib/api/workspaces.svelte.js';
	import SubjectAccess from '#lib/components/access/SubjectAccess.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Command from '#lib/components/ui/command/index.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { TagsInput } from '#lib/components/ui/tags-input/index.js';
	import * as Tabs from '#lib/components/ui/tabs/index.js';
	import { Textarea } from '#lib/components/ui/textarea/index.js';
	import Chip from '#lib/components/blocks/Chip.svelte';
	import SearchPopover from '#lib/components/blocks/SearchPopover.svelte';
	import UserAvatar from '#lib/components/blocks/UserAvatar.svelte';
	import { SubjectKind } from '#lib/gen/nokku/v1/principal_pb.js';
	import { TeamSchema } from '#lib/gen/nokku/v1/team_pb.js';
	import { confirm, useAutoSave, useDraft, useSheet } from '#lib/hooks/index.js';
	import { Check, FileText, Info, Settings2, ShieldCheck, UserPlus, Users } from '@lucide/svelte';
	import { Debounced } from 'runed';
	import DangerZone from './DangerZone.svelte';
	import EntitySheet from './EntitySheet.svelte';
	import Section from './Section.svelte';

	const PREVIEW = 40;

	const sheet = useSheet();
	const can = user.can();
	const query = teamApi.get(() => sheet.id);
	const entity = $derived(query.data);
	const draft = useDraft(TeamSchema, () => query.data);
	const model = $derived(draft.current);

	const members = teamApi.members(() => sheet.id);
	const memberIds = $derived(new Set((members.data ?? []).map((m) => m.id)));
	let showAll = $state(false);
	const shownMembers = $derived(showAll ? members.data : members.data?.slice(0, PREVIEW));

	let pickerOpen = $state(false);
	let search = $state('');
	const debounced = new Debounced(() => search, 250);
	const candidates = users.list(
		() => ({ query: debounced.current || undefined, limit: 20 }),
		() => pickerOpen
	);

	const update = teamApi.update();
	const remove = teamApi.delete();
	const addMember = teamApi.addMember();
	const removeMember = teamApi.removeMember();
	const revokeAll = principalApi.revokeSubject();

	const autoSave = useAutoSave(() => update.mutateAsync({ ...model }));
	const save = () => autoSave.save();

	function toggleMember(userId: string) {
		const mutation = memberIds.has(userId) ? removeMember : addMember;
		mutation.mutate({ teamId: sheet.id, userId });
	}

	function askDelete() {
		if (!entity) return;
		void confirm({
			title: `Delete ${entity.name}?`,
			description: 'Members keep their own access, but lose everything granted through this team.',
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
			description: 'The team is removed from every login account on every target.',
			confirmText: 'Revoke all',
			onConfirm: () => revokeAll.mutateAsync({ subjectId: entity.id, kind: SubjectKind.TEAM })
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
		{ value: 'overview', label: 'Overview', icon: Info },
		{ value: 'access', label: 'Access', icon: ShieldCheck },
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
		<div class="flex size-10 items-center justify-center rounded-lg bg-chart-2/15 text-chart-2">
			<Users class="size-5" />
		</div>
	{/snippet}

	{#snippet subtitle()}
		<span>
			{members.data?.length ?? entity?.memberCount ?? 0}
			{(members.data?.length ?? entity?.memberCount) === 1 ? 'member' : 'members'}
		</span>
	{/snippet}

	{#if model && entity}
		<Tabs.Content value="overview" class="flex flex-col divide-y">
			<Section
				title="Members"
				icon={Users}
				count={members.data?.length}
				description="Members get every login account granted to the team."
			>
				{#snippet action()}
					{#if can.edit}
						<SearchPopover
							bind:open={pickerOpen}
							bind:query={search}
							placeholder="Search members..."
							empty="Nobody matches."
							loading={candidates.isLoading}
							align="end"
						>
							{#snippet trigger(props)}
								<Button {...props} variant="ghost" size="sm">
									<UserPlus data-icon="inline-start" />
									Add
								</Button>
							{/snippet}
							<Command.Group>
								{#each candidates.data?.users ?? [] as m (m.id)}
									<Command.Item value={m.id} onSelect={() => toggleMember(m.id)}>
										<UserAvatar user={m} class="size-6" />
										<div class="flex min-w-0 flex-1 flex-col">
											<span class="truncate">{m.name}</span>
											<span class="truncate text-xs text-muted-foreground">{m.email}</span>
										</div>
										<Check class={memberIds.has(m.id) ? 'text-primary' : 'invisible'} />
									</Command.Item>
								{/each}
							</Command.Group>
						</SearchPopover>
					{/if}
				{/snippet}

				{#if shownMembers?.length}
					<div class="flex flex-wrap gap-1.5">
						{#each shownMembers as m (m.id)}
							<Chip
								label={m.name || m.email}
								href={`/access/users?id=${m.id}`}
								title={m.email}
								onRemove={can.edit
									? () => removeMember.mutate({ teamId: entity.id, userId: m.id })
									: undefined}
							>
								{#snippet leading()}
									<UserAvatar user={m} class="size-6" />
								{/snippet}
							</Chip>
						{/each}
					</div>
					{#if (members.data?.length ?? 0) > PREVIEW && !showAll}
						<Button variant="ghost" size="sm" class="self-start" onclick={() => (showAll = true)}>
							Show all {members.data?.length}
						</Button>
					{/if}
				{:else if !members.isLoading}
					<Empty.Root class="border border-dashed p-6">
						<Empty.Header>
							<Empty.Media variant="icon"><Users /></Empty.Media>
							<Empty.Description>
								{can.edit ? 'No members yet. Add people to share access.' : 'No members yet.'}
							</Empty.Description>
						</Empty.Header>
					</Empty.Root>
				{/if}
			</Section>
		</Tabs.Content>

		<Tabs.Content value="settings" class="flex flex-col divide-y">
			<Section title="Details" icon={FileText}>
				<Field.Group class="gap-4">
					<Field.Field>
						<Field.Label for="team-description">Description</Field.Label>
						<Textarea
							id="team-description"
							bind:value={model.description}
							placeholder="Owns production infrastructure"
							rows={2}
							disabled={!can.edit}
							oninput={save}
						/>
					</Field.Field>
					<Field.Field>
						<Field.Label for="team-tags">Tags</Field.Label>
						<TagsInput
							id="team-tags"
							value={model.tags}
							disabled={!can.edit}
							onValueChange={(tags) => {
								model.tags = tags;
								save();
							}}
							placeholder="platform, on-call"
						/>
					</Field.Field>
				</Field.Group>
			</Section>

			<DangerZone
				actions={can.edit
					? [
							{
								title: 'Revoke all access',
								description: 'Remove the team from every login account.',
								label: 'Revoke all',
								onClick: askRevokeAll
							},
							{
								title: 'Delete team',
								description: 'Members lose what they had through this team.',
								label: 'Delete',
								onClick: askDelete
							}
						]
					: []}
			/>
		</Tabs.Content>

		<Tabs.Content value="access">
			<SubjectAccess subjectId={entity.id} kind={SubjectKind.TEAM} name={entity.name} />
		</Tabs.Content>
	{/if}
</EntitySheet>
