<script lang="ts">
	import { principal as principalApi } from '#lib/api/principals.svelte.js';
	import { team as teamApi } from '#lib/api/team.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import { workspace } from '#lib/api/workspaces.svelte.js';
	import RolePicker from '#lib/components/access/RolePicker.svelte';
	import SubjectAccess from '#lib/components/access/SubjectAccess.svelte';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Command from '#lib/components/ui/command/index.js';
	import * as Tabs from '#lib/components/ui/tabs/index.js';
	import Chip from '#lib/components/blocks/Chip.svelte';
	import SearchPopover from '#lib/components/blocks/SearchPopover.svelte';
	import UserAvatar from '#lib/components/blocks/UserAvatar.svelte';
	import { SubjectKind } from '#lib/gen/nokku/v1/principal_pb.js';
	import { confirm, useSheet } from '#lib/hooks/index.js';
	import {
		BadgeCheck,
		Check,
		Crown,
		Info,
		Plus,
		ShieldCheck,
		UserCog,
		Users
	} from '@lucide/svelte';
	import { Debounced } from 'runed';
	import DangerZone, { type DangerAction } from './DangerZone.svelte';
	import EntitySheet from './EntitySheet.svelte';
	import Section from './Section.svelte';

	const sheet = useSheet();
	const query = workspace.getMember(() => sheet.id);
	const member = $derived(query.data);
	const me = user.self();
	const currentWorkspace = workspace.get();

	const userTeams = teamApi.listForUser(() => sheet.id);
	let pickerOpen = $state(false);
	let search = $state('');
	const debounced = new Debounced(() => search, 250);
	const teamResults = teamApi.list(
		() => ({ query: debounced.current || undefined, limit: 20 }),
		() => pickerOpen
	);
	const teamIds = $derived(new Set((userTeams.data ?? []).map((t) => t.id)));

	const updateMember = workspace.updateMember();
	const removeMember = workspace.removeMember();
	const updateOwner = workspace.updateOwner();
	const addToTeam = teamApi.addMember();
	const removeFromTeam = teamApi.removeMember();
	const revokeAll = principalApi.revokeSubject();

	const isOwner = $derived(member?.roleName === 'owner');
	const isMe = $derived(me.data?.id === member?.id);
	const iAmOwner = $derived(currentWorkspace.data?.role === 'owner');

	function toggleTeam(teamId: string) {
		if (!member) return;
		const mutation = teamIds.has(teamId) ? removeFromTeam : addToTeam;
		mutation.mutate({ teamId, userId: member.id });
	}

	const dangerActions = $derived.by<DangerAction[]>(() => {
		if (!member) return [];
		const actions: DangerAction[] = [
			{
				title: 'Revoke all access',
				description: 'Remove them from every login account. Team access stays.',
				label: 'Revoke all',
				onClick: () =>
					confirm({
						title: `Revoke all access for ${member.name}?`,
						description: 'Direct grants on every target are removed. Access through teams stays.',
						confirmText: 'Revoke all',
						onConfirm: () => revokeAll.mutateAsync({ subjectId: member.id, kind: SubjectKind.USER })
					})
			}
		];
		if (iAmOwner && !isOwner) {
			actions.push({
				title: 'Make owner',
				description: 'Hand over the workspace. You become an admin.',
				label: 'Transfer',
				onClick: () =>
					confirm({
						title: `Make ${member.name} the owner?`,
						description:
							'They get full control, including single sign-on, billing and deleting the workspace. You become an admin, and only they can hand it back.',
						confirmText: 'Transfer ownership',
						typeToConfirm: member.email,
						onConfirm: () => updateOwner.mutateAsync({ newOwner: member.id })
					})
			});
		}
		if (!isOwner) {
			actions.push({
				title: isMe ? 'Leave workspace' : 'Remove from workspace',
				description: 'Access is revoked right away. They can be invited again.',
				label: isMe ? 'Leave' : 'Remove',
				onClick: () =>
					confirm({
						title: isMe ? 'Leave this workspace?' : `Remove ${member.name}?`,
						description: 'All their access here is revoked right away.',
						confirmText: isMe ? 'Leave' : 'Remove',
						typeToConfirm: member.email,
						onConfirm: async () => {
							await removeMember.mutateAsync({ userId: member.id });
							sheet.close();
						}
					})
			});
		}
		return actions;
	});
</script>

<EntitySheet
	open={sheet.open}
	onClose={() => sheet.close()}
	loading={!member}
	missing={query.isError}
	title={member?.name || member?.email || ''}
	tabs={[
		{ value: 'overview', label: 'Overview', icon: Info },
		{ value: 'access', label: 'Access', icon: ShieldCheck }
	]}
	tab={sheet.tab}
	onTabChange={(t) => (sheet.tab = t)}
	meta={{ id: member?.id, createdAt: member?.createdAt, updatedAt: member?.updatedAt }}
>
	{#snippet media()}
		<UserAvatar user={member} class="size-10" />
	{/snippet}

	{#snippet subtitle()}
		<span class="truncate">{member?.email}</span>
		{#if member?.emailVerified}
			<BadgeCheck class="size-3.5 text-success" aria-label="Email verified" />
		{:else}
			<Badge variant="warning">Unverified</Badge>
		{/if}
		{#if isOwner}
			<Badge variant="secondary"><Crown data-icon="inline-start" />Owner</Badge>
		{/if}
		{#if isMe}
			<Badge variant="outline">You</Badge>
		{/if}
	{/snippet}

	{#if member}
		<Tabs.Content value="overview" class="flex flex-col divide-y">
			<Section
				title="Workspace role"
				icon={UserCog}
				description={isOwner
					? 'The owner can do everything. Ownership changes through a transfer.'
					: 'What they may change in this workspace.'}
			>
				{#if !isOwner}
					<RolePicker
						value={member.roleName}
						disabled={updateMember.isPending}
						onChange={(roleName) => updateMember.mutate({ userId: member.id, roleName })}
					/>
				{/if}
			</Section>

			<Section
				title="Teams"
				icon={Users}
				count={userTeams.data?.length}
				description="They get every login account granted to these teams."
			>
				{#snippet action()}
					<SearchPopover
						bind:open={pickerOpen}
						bind:query={search}
						placeholder="Search teams..."
						empty="No team matches."
						loading={teamResults.isLoading}
						align="end"
					>
						{#snippet trigger(props)}
							<Button {...props} variant="ghost" size="sm">
								<Plus data-icon="inline-start" />
								Add to team
							</Button>
						{/snippet}
						<Command.Group>
							{#each teamResults.data?.teams ?? [] as t (t.id)}
								<Command.Item value={t.id} onSelect={() => toggleTeam(t.id)}>
									<Users />
									<span class="truncate">{t.name}</span>
									<Check class={['ml-auto', teamIds.has(t.id) ? 'text-primary' : 'invisible']} />
								</Command.Item>
							{/each}
						</Command.Group>
					</SearchPopover>
				{/snippet}

				{#if userTeams.data?.length}
					<div class="flex flex-wrap gap-1.5">
						{#each userTeams.data as t (t.id)}
							<Chip
								label={t.name}
								href={`/access/teams?id=${t.id}`}
								onRemove={() => toggleTeam(t.id)}
								removeLabel={`Remove from ${t.name}`}
							>
								{#snippet leading()}
									<span
										class="flex size-6 items-center justify-center rounded-full bg-chart-2/15 text-chart-2"
									>
										<Users class="size-3" />
									</span>
								{/snippet}
							</Chip>
						{/each}
					</div>
				{:else if !userTeams.isLoading}
					<p class="text-sm text-muted-foreground">Not in any team yet.</p>
				{/if}
			</Section>

			<DangerZone actions={dangerActions} />
		</Tabs.Content>

		<Tabs.Content value="access">
			<SubjectAccess
				subjectId={member.id}
				kind={SubjectKind.USER}
				name={member.name || member.email}
			/>
		</Tabs.Content>
	{/if}
</EntitySheet>
