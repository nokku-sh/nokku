<script lang="ts">
	import { daemon } from '$lib/api/daemons.svelte';
	import { roles } from '$lib/api/roles.svelte';
	import { target } from '$lib/api/targets.svelte';
	import { team } from '$lib/api/team.svelte';
	import { workspace } from '$lib/api/workspaces.svelte';
	import DangerZone from '$lib/components/sheets/DangerZone.svelte';
	import DetailList from '$lib/components/sheets/DetailList.svelte';
	import SaveStatus from '$lib/components/sheets/SaveStatus.svelte';
	import { Badge } from '$lib/components/ui/badge';
	import * as Card from '$lib/components/ui/card';
	import * as Field from '$lib/components/ui/field';
	import { Input } from '$lib/components/ui/input';
	import * as Item from '$lib/components/ui/item';
	import { Skeleton } from '$lib/components/ui/skeleton';
	import { Textarea } from '$lib/components/ui/textarea';
	import Avatar from '$lib/components/utils/Avatar.svelte';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import UserAvatar from '$lib/components/utils/UserAvatar.svelte';
	import { WorkspaceSchema } from '$lib/gen/nokku/v1/workspace_pb';
	import { confirm, useAutoSave, useDraft } from '$lib/hooks';
	import { atLeast, roleIcon, roleLabel } from '$lib/roles';
	import { formatTs } from '$lib/utils';
	import {
		Bot,
		ChevronRight,
		CircleUser,
		KeyRound,
		Layers2,
		ScrollText,
		Server,
		Users
	} from '@lucide/svelte';

	const ws = workspace.get();
	const draft = useDraft(WorkspaceSchema, () => ws.data);
	const model = $derived(draft.current);
	const canEdit = $derived(atLeast(ws.data?.role, 'admin'));
	const isOwner = $derived(ws.data?.role === 'owner');

	const owner = workspace.getMember(() => ws.data?.createdBy);
	const roleList = roles.list();
	const myRole = $derived(roleList.data?.find((r) => r.name === ws.data?.role));
	const MyRoleIcon = $derived(roleIcon(ws.data?.role ?? 'member'));

	const one = () => ({ limit: 1 });
	const counts = [
		{
			label: 'Members',
			icon: CircleUser,
			href: '/access/members',
			query: workspace.listMembers(one)
		},
		{ label: 'Teams', icon: Users, href: '/access/teams', query: team.list(one) },
		{ label: 'Targets', icon: Server, href: '/infrastructure/targets', query: target.list(one) },
		{ label: 'Daemons', icon: Bot, href: '/infrastructure/daemons', query: daemon.list(one) }
	];

	const more = [
		{
			title: 'Daemon defaults',
			description: 'Session policy new daemons start with.',
			icon: Bot,
			href: '/settings/daemons'
		},
		{
			title: 'Audit streaming',
			description: 'Send every event to your SIEM.',
			icon: ScrollText,
			href: '/settings/audit'
		},
		{
			title: 'Single sign-on',
			description: 'OIDC, SAML, SCIM and verified domains.',
			icon: KeyRound,
			href: '/settings/sso'
		}
	];

	const update = workspace.update();
	const remove = workspace.delete();

	// Settings are left out on purpose, the backend keeps what isn't sent.
	const autoSave = useAutoSave(() =>
		update.mutateAsync({
			workspaceId: model?.id,
			name: model?.name,
			description: model?.description
		})
	);
	const save = () => canEdit && autoSave.save();
</script>

<PageHeader
	icon={Layers2}
	title="Workspace"
	description="How this workspace is named, who runs it and what's in it."
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
						disabled={!canEdit}
						class="text-base font-medium"
					/>
				</Field.Field>
				<Field.Field>
					<Field.Label for="ws-description">Description</Field.Label>
					<Textarea
						id="ws-description"
						bind:value={model.description}
						oninput={save}
						disabled={!canEdit}
						rows={2}
						placeholder="What this workspace is for, e.g. Production EU"
					/>
				</Field.Field>
			</Field.Group>
		</Card.Content>
		<Card.Footer class="border-t">
			<SaveStatus
				state={autoSave.saveState}
				idleText={canEdit ? 'Changes save automatically' : 'Only admins can change this'}
			/>
		</Card.Footer>
	</Card.Root>

	<div class="grid grid-cols-2 gap-3 md:grid-cols-4">
		{#each counts as c (c.label)}
			<a
				href={c.href}
				class="group flex items-center gap-3 rounded-xl border bg-card p-4 transition-colors hover:bg-muted/40"
			>
				<div
					class="flex size-9 items-center justify-center rounded-lg bg-primary/10 text-primary transition-colors group-hover:bg-primary group-hover:text-primary-foreground"
				>
					<c.icon class="size-4" />
				</div>
				<div class="flex flex-col">
					{#if c.query.isLoading}
						<Skeleton class="h-6 w-8" />
					{:else}
						<span class="text-xl font-semibold tabular-nums">{c.query.data?.total ?? 0}</span>
					{/if}
					<span class="text-xs text-muted-foreground">{c.label}</span>
				</div>
			</a>
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
						<a href={`/access/members?id=${ws.data?.createdBy}`} {...props}>
							<Item.Media><UserAvatar user={owner.data} class="size-8" /></Item.Media>
							<Item.Content>
								<Item.Title>{owner.data?.name ?? '…'}</Item.Title>
								<Item.Description>{owner.data?.email}</Item.Description>
							</Item.Content>
							<Item.Actions><Badge variant="secondary">Owner</Badge></Item.Actions>
						</a>
					{/snippet}
				</Item.Root>
				<Item.Root variant="muted" size="sm">
					<Item.Media variant="icon"><MyRoleIcon /></Item.Media>
					<Item.Content>
						<Item.Title>You are {roleLabel(ws.data.role).toLowerCase()}</Item.Title>
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
						{ label: 'Created', value: formatTs(ws.data.createdAt) },
						{ label: 'Updated', value: formatTs(ws.data.updatedAt, 'relative') }
					]}
				/>
			</Card.Content>
		</Card.Root>
	</div>

	<Card.Root>
		<Card.Header>
			<Card.Title class="text-base">More settings</Card.Title>
		</Card.Header>
		<Card.Content>
			<Item.Group class="divide-y rounded-lg border">
				{#each more as link (link.href)}
					<Item.Root size="sm" class="rounded-none">
						{#snippet child({ props })}
							<a href={link.href} {...props}>
								<Item.Media variant="icon"><link.icon /></Item.Media>
								<Item.Content>
									<Item.Title>{link.title}</Item.Title>
									<Item.Description>{link.description}</Item.Description>
								</Item.Content>
								<Item.Actions><ChevronRight class="size-4 text-muted-foreground" /></Item.Actions>
							</a>
						{/snippet}
					</Item.Root>
				{/each}
			</Item.Group>
		</Card.Content>
	</Card.Root>

	{#if isOwner}
		<DangerZone
			actions={[
				{
					title: 'Delete workspace',
					description:
						'Removes every member, team, target and certificate. Active subscriptions are canceled.',
					label: 'Delete',
					onClick: () =>
						confirm({
							title: 'Delete workspace?',
							description:
								'This permanently deletes the workspace and all its data. Active subscriptions for it are canceled immediately. This cannot be undone.',
							typeToConfirm: ws.data?.name,
							onConfirm: () => remove.mutateAsync({ workspaceId: ws.data?.id })
						})
				}
			]}
		/>
	{/if}
{/if}
