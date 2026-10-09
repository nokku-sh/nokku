<script lang="ts">
	import { WorkspaceRole } from '#lib/gen/nokku/v1/access_pb.js';
	import StatTile from '#lib/components/blocks/StatTile.svelte';
	import { daemon } from '#lib/api/daemons.svelte.js';
	import { roles } from '#lib/api/roles.svelte.js';
	import { target } from '#lib/api/targets.svelte.js';
	import { team } from '#lib/api/team.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import { users, util, workspace } from '#lib/api/workspaces.svelte.js';
	import DangerZone from '#lib/components/sheets/DangerZone.svelte';
	import DetailList from '#lib/components/sheets/DetailList.svelte';
	import SaveStatus from '#lib/components/blocks/SaveStatus.svelte';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import * as Item from '#lib/components/ui/item/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { Textarea } from '#lib/components/ui/textarea/index.js';
	import Avatar from '#lib/components/blocks/Avatar.svelte';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import UserAvatar from '#lib/components/blocks/UserAvatar.svelte';
	import { WorkspaceSchema } from '#lib/gen/nokku/v1/workspace_pb.js';
	import { confirm, useAutoSave, useDraft } from '#lib/hooks/index.js';
	import { roleIcon, roleLabel } from '#lib/roles.js';
	import { formatTs } from '#lib/utils.js';
	import { Bot, CircleUser, Server, Users } from '@lucide/svelte';

	const ws = workspace.get();
	const me = user.self();
	const info = util.instanceInfo();
	const draft = useDraft(WorkspaceSchema, () => ws.data);
	const model = $derived(draft.current);
	const isOwner = $derived(me.data?.role === WorkspaceRole.OWNER);
	// A hosted workspace can go, a self-hosted one is the whole server.
	const deletable = $derived(isOwner && info.data?.mode === 'saas');

	const ownerQuery = users.list(() => ({ role: WorkspaceRole.OWNER, limit: 1 }));
	const owner = $derived(ownerQuery.data?.users[0]);
	const roleList = roles.list();
	const myRole = $derived(roleList.data?.find((r) => r.role === me.data?.role));
	const MyRoleIcon = $derived(roleIcon(me.data?.role || WorkspaceRole.MEMBER));

	const one = () => ({ limit: 1 });
	const counts = [
		{ label: 'Users', icon: CircleUser, href: '/access/users', query: users.list(one) },
		{ label: 'Teams', icon: Users, href: '/access/teams', query: team.list(one) },
		{ label: 'Targets', icon: Server, href: '/infrastructure/targets', query: target.list(one) },
		{ label: 'Daemons', icon: Bot, href: '/infrastructure/daemons', query: daemon.list(one) }
	];

	const update = workspace.update();
	const remove = workspace.delete();

	// Settings are left out on purpose, the backend keeps what isn't sent.
	const autoSave = useAutoSave(() =>
		update.mutateAsync({ name: model?.name, description: model?.description })
	);
	const save = () => isOwner && autoSave.save();
</script>

<PageHeader
	title="Workspace"
	description="How this workspace is named, who runs it and what's in it"
/>

{#if !model || !ws.data}
	<Skeleton class="h-40 w-full rounded-xl" />
	<Skeleton class="h-24 w-full rounded-xl" />
{:else}
	<Card.Root>
		<Card.Content class="flex flex-col gap-5 sm:flex-row">
			<Avatar id={model.id} class="size-16 shrink-0 rounded-xl" />
			<Field.Group class="flex-1 gap-4">
				<Field.Field>
					<Field.Label for="ws-name">Name</Field.Label>
					<Input
						id="ws-name"
						bind:value={model.name}
						oninput={save}
						disabled={!isOwner}
						class="text-base font-medium"
					/>
				</Field.Field>
				<Field.Field>
					<Field.Label for="ws-description">Description</Field.Label>
					<Textarea
						id="ws-description"
						bind:value={model.description}
						oninput={save}
						disabled={!isOwner}
						rows={2}
						placeholder="What this workspace is for, e.g. Production EU"
					/>
				</Field.Field>
			</Field.Group>
		</Card.Content>
		<Card.Footer class="border-t">
			<SaveStatus
				state={autoSave.saveState}
				idleText={isOwner ? 'Changes save automatically' : 'Only the owner can change this'}
			/>
		</Card.Footer>
	</Card.Root>

	<div class="grid grid-cols-2 gap-3 md:grid-cols-4">
		{#each counts as c (c.label)}
			<StatTile
				label={c.label}
				icon={c.icon}
				href={c.href}
				loading={c.query.isLoading}
				value={c.query.data?.total ?? 0}
			/>
		{/each}
	</div>

	<div class="grid gap-4 md:grid-cols-2">
		<Card.Root>
			<Card.Header>
				<Card.Title class="text-base">People</Card.Title>
				<Card.Description>Who owns the workspace and what you can do in it.</Card.Description>
			</Card.Header>
			<Card.Content class="flex flex-col gap-2">
				<Item.Root variant="muted" size="sm">
					{#snippet child({ props })}
						<a href={`/access/users?id=${owner?.id ?? ''}`} {...props}>
							<Item.Media><UserAvatar user={owner} class="size-8" /></Item.Media>
							<Item.Content>
								<Item.Title>{owner?.name || owner?.email || '…'}</Item.Title>
								<Item.Description>{owner?.email}</Item.Description>
							</Item.Content>
							<Item.Actions><Badge variant="secondary">Owner</Badge></Item.Actions>
						</a>
					{/snippet}
				</Item.Root>
				<Item.Root variant="muted" size="sm">
					<Item.Media variant="icon"><MyRoleIcon /></Item.Media>
					<Item.Content>
						<Item.Title
							>You are {roleLabel(me.data?.role || WorkspaceRole.MEMBER).toLowerCase()}</Item.Title
						>
						<Item.Description>{myRole?.description}</Item.Description>
					</Item.Content>
				</Item.Root>
			</Card.Content>
		</Card.Root>

		<Card.Root>
			<Card.Header>
				<Card.Title class="text-base">Details</Card.Title>
				<Card.Description>Handy for the CLI, the API and support.</Card.Description>
			</Card.Header>
			<Card.Content>
				<DetailList
					items={[
						{ label: 'Workspace ID', value: ws.data.id, mono: true, copy: true, wide: true },
						{ label: 'Address', value: location.origin, mono: true, copy: true, wide: true },
						{ label: 'CA pin', value: info.data?.caPin, mono: true, copy: true, wide: true },
						{ label: 'Created', value: formatTs(ws.data.createdAt) },
						{ label: 'Updated', value: formatTs(ws.data.updatedAt, 'relative') }
					]}
				/>
			</Card.Content>
		</Card.Root>
	</div>

	{#if deletable}
		<DangerZone
			actions={[
				{
					title: 'Delete workspace',
					description:
						'Removes every user, team, target and certificate. Active subscriptions are canceled.',
					label: 'Delete',
					onClick: () =>
						confirm({
							title: 'Delete workspace?',
							description:
								'This permanently deletes the workspace and all its data. Active subscriptions for it are canceled immediately. This cannot be undone.',
							typeToConfirm: ws.data?.name,
							onConfirm: () => remove.mutateAsync({})
						})
				}
			]}
		/>
	{/if}
{/if}
