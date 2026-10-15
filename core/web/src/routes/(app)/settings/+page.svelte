<script lang="ts">
	import { WorkspaceRole } from '#lib/gen/nokku/v1/access_pb.js';
	import { user } from '#lib/api/user.svelte.js';
	import { users, util, workspace } from '#lib/api/workspaces.svelte.js';
	import NokkuCaret from '#lib/assets/nokku_caret.svelte';
	import LoadError from '#lib/components/blocks/LoadError.svelte';
	import SaveStatus from '#lib/components/blocks/SaveStatus.svelte';
	import UserAvatar from '#lib/components/blocks/UserAvatar.svelte';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import DangerZone from '#lib/components/sheets/DangerZone.svelte';
	import DetailList from '#lib/components/sheets/DetailList.svelte';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import * as Item from '#lib/components/ui/item/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { Textarea } from '#lib/components/ui/textarea/index.js';
	import { DocsURL } from '#lib/config.js';
	import { WorkspaceSchema } from '#lib/gen/nokku/v1/workspace_pb.js';
	import { confirm, useAutoSave, useDraft } from '#lib/hooks/index.js';
	import { roleIcon, roleLabel, roleSlug } from '#lib/roles.js';
	import { formatTs } from '#lib/utils.js';
	import { RotateCw } from '@lucide/svelte';

	const ADMINS_SHOWN = 5;

	const ws = workspace.get();
	const baseUrl = workspace.baseUrl();
	const info = util.instanceInfo();
	const me = user.self();
	const can = user.can();
	const draft = useDraft(WorkspaceSchema, () => ws.data);
	const model = $derived(draft.current);
	const hosted = $derived(info.data?.mode === 'saas');

	// Waits for the role, so nobody fires a query their role would refuse.
	const ownerQuery = users.list(
		() => ({ role: WorkspaceRole.OWNER, limit: 1 }),
		() => can.view
	);
	const adminQuery = users.list(
		() => ({ role: WorkspaceRole.ADMIN, limit: ADMINS_SHOWN }),
		() => can.view
	);
	const people = $derived([...(ownerQuery.data?.users ?? []), ...(adminQuery.data?.users ?? [])]);
	const moreAdmins = $derived((adminQuery.data?.total ?? 0) - (adminQuery.data?.users.length ?? 0));
	const peopleFailed = $derived(ownerQuery.isError || adminQuery.isError);
	const peopleLoading = $derived(!ownerQuery.data || !adminQuery.data);
	const retryPeople = () => Promise.all([ownerQuery.refetch(), adminQuery.refetch()]);

	const MyRoleIcon = $derived(roleIcon(me.data?.role));
	const youAre = $derived.by(() => {
		const role = me.data?.role;
		if (role === WorkspaceRole.OWNER) return "You're the owner";
		const slug = roleSlug(role);
		return `You're ${/^[aeiou]/.test(slug) ? 'an' : 'a'} ${slug}`;
	});

	const update = workspace.update();
	const remove = workspace.delete();

	const nameValid = () => (model?.name.trim().length ?? 0) >= 3;
	// Settings are left out on purpose, the server keeps what isn't sent.
	const autoSave = useAutoSave(() =>
		nameValid()
			? update.mutateAsync({ name: model?.name.trim(), description: model?.description })
			: Promise.reject(new Error('name too short'))
	);
	const save = () => can.own && nameValid() && autoSave.save();
</script>

<PageHeader title="Workspace" description="Who runs this workspace and how to connect to it" />

{#if ws.isError}
	<LoadError
		title="The workspace did not load"
		description="Nothing changed, servers keep working as before."
		onRetry={() => ws.refetch()}
		class="h-[25vh] rounded-xl border-solid bg-card text-card-foreground"
	/>
{:else if !model || !ws.data || !me.data}
	<Skeleton class="h-36 w-full rounded-xl" />
	<div class="grid gap-4 md:grid-cols-2">
		<Skeleton class="h-56 w-full rounded-xl" />
		<Skeleton class="h-56 w-full rounded-xl" />
	</div>
{:else}
	<Card.Root>
		<Card.Content class="flex items-start gap-4">
			<div
				class="flex size-12 shrink-0 items-center justify-center rounded-xl bg-terminal text-brand-caret ring-1 ring-foreground/10 sm:size-14"
			>
				<NokkuCaret class="h-5 pl-0.5 sm:h-6" />
			</div>
			{#if can.own}
				<Field.Group class="min-w-0 flex-1 gap-4">
					<Field.Field data-invalid={!nameValid() || undefined}>
						<Field.Label for="ws-name">Name</Field.Label>
						<Input
							id="ws-name"
							bind:value={model.name}
							oninput={save}
							maxlength={256}
							aria-invalid={!nameValid() || undefined}
							class="text-base font-medium"
						/>
						{#if !nameValid()}
							<Field.Error>Use at least 3 characters</Field.Error>
						{/if}
					</Field.Field>
					<Field.Field>
						<Field.Label for="ws-description">Description</Field.Label>
						<Textarea
							id="ws-description"
							bind:value={model.description}
							oninput={save}
							maxlength={1000}
							rows={2}
							placeholder="What this workspace is for, e.g. Production EU"
						/>
					</Field.Field>
				</Field.Group>
			{:else}
				<div class="flex min-w-0 flex-col gap-1 self-center">
					<h2 class="text-xl font-semibold break-words">{model.name}</h2>
					<p class="text-sm break-words text-muted-foreground">
						{model.description || 'No description'}
					</p>
				</div>
			{/if}
		</Card.Content>
		{#if can.own}
			<Card.Footer class="border-t">
				<SaveStatus
					state={autoSave.saveState}
					idleText="Shows in the sidebar for everyone. Changes save automatically"
					onRetry={autoSave.retry}
				/>
			</Card.Footer>
		{/if}
	</Card.Root>

	<div class="grid gap-4 md:grid-cols-2 md:items-start">
		<Card.Root>
			<Card.Header>
				<Card.Title><h2>Who runs it</h2></Card.Title>
				<Card.Description>Ask them for access or a different role</Card.Description>
			</Card.Header>
			<Card.Content class="flex flex-col gap-3">
				{#if peopleFailed}
					<div
						class="flex items-center justify-between gap-2 rounded-lg border px-3 py-2.5 text-sm"
					>
						<span class="text-muted-foreground">The owner and admins did not load</span>
						<Button variant="ghost" size="sm" onclick={retryPeople}>
							<RotateCw data-icon="inline-start" />
							Try again
						</Button>
					</div>
				{:else if peopleLoading}
					<Skeleton class="h-28 w-full rounded-lg" />
				{:else}
					<Item.Group class="divide-y rounded-lg border">
						{#each people as person (person.id)}
							<Item.Root size="sm" class="rounded-none">
								{#snippet child({ props })}
									<a href={`/access/users?id=${person.id}`} {...props}>
										<Item.Media><UserAvatar user={person} class="size-8" /></Item.Media>
										<Item.Content class="min-w-0">
											<Item.Title class="max-w-full">
												<span class="truncate">{person.name || person.email.split('@')[0]}</span>
											</Item.Title>
											<Item.Description class="truncate">{person.email}</Item.Description>
										</Item.Content>
										<Item.Actions>
											<Badge variant="secondary">{roleLabel(person.role)}</Badge>
										</Item.Actions>
									</a>
								{/snippet}
							</Item.Root>
						{/each}
					</Item.Group>
					{#if moreAdmins > 0}
						<a
							href="/access/users?role=admin"
							class="self-start text-sm text-primary hover:underline"
						>
							{moreAdmins} more {moreAdmins === 1 ? 'admin' : 'admins'}
						</a>
					{/if}
				{/if}
				<p class="flex flex-wrap items-center gap-x-1.5 gap-y-1 text-sm text-muted-foreground">
					<MyRoleIcon class="size-4" />
					<span>{youAre}.</span>
					<a
						href={`${DocsURL}/guides/access/#roles`}
						target="_blank"
						rel="noopener"
						class="text-primary hover:underline">What each role can do</a
					>
				</p>
			</Card.Content>
		</Card.Root>

		<Card.Root>
			<Card.Header>
				<Card.Title><h2>Connect</h2></Card.Title>
				<Card.Description>
					What <code class="font-mono">nk</code>, <code class="font-mono">nokkud</code> and support
					ask for{info.data?.caPin ? '. The CA pin lets them trust this server' : ''}
				</Card.Description>
			</Card.Header>
			<Card.Content class="flex flex-col gap-3">
				<DetailList
					items={[
						{ label: 'Address', value: baseUrl.data, mono: true, copy: true, wide: true },
						{ label: 'CA pin', value: info.data?.caPin, mono: true, copy: true, wide: true },
						{ label: 'Workspace ID', value: ws.data.id, mono: true, copy: true, wide: true },
						{
							label: 'Mode',
							value: info.data?.mode && (hosted ? 'Hosted' : 'Self-hosted')
						},
						{ label: 'Created', value: formatTs(ws.data.createdAt) }
					]}
				/>
				<p class="text-sm text-muted-foreground">
					The full <code class="font-mono">nk login</code> command is under
					<a href="/profile/security" class="text-primary hover:underline">Profile, Security</a>
				</p>
			</Card.Content>
		</Card.Root>
	</div>

	{#if can.own && hosted}
		<DangerZone
			actions={[
				{
					title: 'Delete workspace',
					description:
						'Removes every user, team, target, certificate, recording and the audit log. Active subscriptions are canceled. Export the audit log first if you need a record.',
					label: 'Delete',
					onClick: () =>
						confirm({
							title: 'Delete workspace?',
							description:
								'This permanently deletes the workspace with its recordings and audit log, and cancels any active subscription. Enrolled servers keep what they last synced, so certificates already signed work until they expire. Remove nokkud from them afterwards. This cannot be undone.',
							confirmText: 'Delete workspace',
							typeToConfirm: ws.data?.name,
							onConfirm: () => remove.mutateAsync({})
						})
				}
			]}
		/>
	{:else if can.own && info.data?.mode}
		<p class="text-xs text-muted-foreground">
			On a self-hosted core the workspace is the whole server, so it can't be deleted from here.
		</p>
	{/if}
{/if}
