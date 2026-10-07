<script lang="ts">
	import { principal as principalApi } from '#lib/api/principals.svelte.js';
	import { team as teamApi } from '#lib/api/team.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import { users } from '#lib/api/workspaces.svelte.js';
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
	import { atLeast } from '#lib/roles.js';
	import { Check, Crown, Info, Plus, ShieldCheck, UserCog, Users } from '@lucide/svelte';
	import { Debounced } from 'runed';
	import DangerZone, { type DangerAction } from './DangerZone.svelte';
	import EntitySheet from './EntitySheet.svelte';
	import Section from './Section.svelte';

	const sheet = useSheet();
	const query = users.get(() => sheet.id);
	const person = $derived(query.data);
	const me = user.self();

	const userTeams = teamApi.listForUser(() => sheet.id);
	let pickerOpen = $state(false);
	let search = $state('');
	const debounced = new Debounced(() => search, 250);
	const teamResults = teamApi.list(
		() => ({ query: debounced.current || undefined, limit: 20 }),
		() => pickerOpen
	);
	const teamIds = $derived(new Set((userTeams.data ?? []).map((t) => t.id)));

	const updateRole = users.updateRole();
	const setActive = users.setActive();
	const remove = users.delete();
	const transfer = users.transferOwnership();
	const addToTeam = teamApi.addMember();
	const removeFromTeam = teamApi.removeMember();
	const revokeAll = principalApi.revokeSubject();

	const isOwner = $derived(person?.role === 'owner');
	const isMe = $derived(me.data?.id === person?.id);
	const iAmOwner = $derived(me.data?.role === 'owner');
	const canManage = $derived(atLeast(me.data?.role, 'admin') && !isOwner && !isMe);

	function toggleTeam(teamId: string) {
		if (!person) return;
		const mutation = teamIds.has(teamId) ? removeFromTeam : addToTeam;
		mutation.mutate({ teamId, userId: person.id });
	}

	const dangerActions = $derived.by<DangerAction[]>(() => {
		if (!person) return [];
		const name = person.name || person.email;
		const actions: DangerAction[] = [
			{
				title: 'Revoke all access',
				description: 'Remove them from every login account. Team access stays.',
				label: 'Revoke all',
				onClick: () =>
					confirm({
						title: `Revoke all access for ${name}?`,
						description: 'Direct grants on every target are removed. Access through teams stays.',
						confirmText: 'Revoke all',
						onConfirm: () => revokeAll.mutateAsync({ subjectId: person.id, kind: SubjectKind.USER })
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
						title: `Make ${name} the owner?`,
						description:
							'They get full control, including single sign-on, billing and deleting the workspace. You become an admin, and only they can hand it back.',
						confirmText: 'Transfer ownership',
						typeToConfirm: person.email,
						onConfirm: () => transfer.mutateAsync({ newOwnerId: person.id })
					})
			});
		}
		if (canManage) {
			actions.push({
				title: person.active ? 'Deactivate account' : 'Reactivate account',
				description: person.active
					? 'They are signed out everywhere and cannot sign in. Their grants stay for when they return.'
					: 'They can sign in again with the access they had.',
				label: person.active ? 'Deactivate' : 'Reactivate',
				onClick: () =>
					person.active
						? confirm({
								title: `Deactivate ${name}?`,
								description: 'Every session ends right away. You can reactivate them later.',
								confirmText: 'Deactivate',
								onConfirm: () => setActive.mutateAsync({ userId: person.id, active: false })
							})
						: setActive.mutate({ userId: person.id, active: true })
			});
			actions.push({
				title: 'Delete account',
				description: 'Access is revoked right away. They can be invited again.',
				label: 'Delete',
				onClick: () =>
					confirm({
						title: `Delete ${name}?`,
						description: 'All their access here is revoked right away. This cannot be undone.',
						confirmText: 'Delete',
						typeToConfirm: person.email,
						onConfirm: async () => {
							await remove.mutateAsync({ userId: person.id });
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
	loading={!person}
	missing={query.isError}
	title={person?.name || person?.email || ''}
	tabs={[
		{ value: 'overview', label: 'Overview', icon: Info },
		{ value: 'access', label: 'Access', icon: ShieldCheck }
	]}
	tab={sheet.tab}
	onTabChange={(t) => (sheet.tab = t)}
	meta={{ id: person?.id, createdAt: person?.createdAt, updatedAt: person?.updatedAt }}
>
	{#snippet media()}
		<UserAvatar user={person} class="size-10" />
	{/snippet}

	{#snippet subtitle()}
		<span class="truncate">{person?.email}</span>
		{#if person && !person.active}
			<Badge variant="muted">Deactivated</Badge>
		{/if}
		{#if isOwner}
			<Badge variant="secondary"><Crown data-icon="inline-start" />Owner</Badge>
		{/if}
		{#if isMe}
			<Badge variant="outline">You</Badge>
		{/if}
	{/snippet}

	{#if person}
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
						value={person.role}
						disabled={!canManage || updateRole.isPending}
						onChange={(role) => updateRole.mutate({ userId: person.id, role })}
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
				subjectId={person.id}
				kind={SubjectKind.USER}
				name={person.name || person.email}
			/>
		</Tabs.Content>
	{/if}
</EntitySheet>
