<script lang="ts">
	import { workspace } from '$lib/api/workspaces.svelte';
	import DeleteConfirmationModal from '$lib/components/modals/DeleteConfirmationModal.svelte';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import CopyButton from '$lib/components/ui/copy-button/copy-button.svelte';
	import * as Field from '$lib/components/ui/field';
	import { Input } from '$lib/components/ui/input';
	import * as Item from '$lib/components/ui/item';
	import { Spinner } from '$lib/components/ui/spinner';
	import { Textarea } from '$lib/components/ui/textarea';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import { type Workspace } from '$lib/gen/nokku/v1/workspace_pb';
	import { formatTs } from '$lib/utils';
	import { CalendarIcon, ClockIcon, Hash, Layers2, Save, User } from '@lucide/svelte';

	let ws = $derived(workspace.get());
	let members = $derived(workspace.listMembers());
	let owner = $derived(members.data?.members.find((m) => m.id === ws.data?.createdBy));

	let wsData = $state({} as Workspace);
	$effect(() => {
		if (ws.data) wsData = { ...ws.data };
	});

	const update = workspace.update();
	const deleteWorkspace = workspace.delete();
	let deleteOpen = $state(false);
</script>

<DeleteConfirmationModal
	bind:open={deleteOpen}
	title="Delete Workspace"
	description="This will permanently delete your workspace and all associated data. Active subscriptions tied to this workspace will be immediately canceled. This action cannot be undone."
	itemName={ws.data?.name}
	requireConfirmation={true}
	onConfirm={() => deleteWorkspace.mutate({ workspaceId: ws.data?.id })}
/>

<PageHeader
	icon={Layers2}
	title="General Settings"
	description="Manage your workspace's basic information and preferences."
/>

{#if ws.data}
	<Card.Root class="overflow-hidden rounded-xl border shadow-sm">
		<Card.Header>
			<Card.Title class="flex items-center gap-2 text-base">
				<Layers2 size={18} />
				Workspace Profile
			</Card.Title>
			<Card.Description>Update your workspace name and description.</Card.Description>
		</Card.Header>
		<Card.Content class="space-y-6">
			<Field.Field>
				<Field.Label for="name">Name</Field.Label>
				<Field.Content>
					<Input
						id="name"
						bind:value={wsData.name}
						placeholder="Enter workspace name"
						disabled={update.isPending}
						required
					/>
				</Field.Content>
			</Field.Field>

			<Field.Field>
				<Field.Label for="description">Description</Field.Label>
				<Field.Content>
					<Textarea
						id="description"
						bind:value={wsData.description}
						placeholder="Describe your workspace (optional)"
						rows={4}
						disabled={update.isPending}
					/>
				</Field.Content>
			</Field.Field>
		</Card.Content>

		<Card.Footer class="flex justify-end">
			<Button
				variant="default"
				size="sm"
				onclick={() => update.mutate({ ...wsData })}
				disabled={update.isPending}
				class="w-full sm:w-auto"
			>
				<Save class={update.isPending ? 'hidden' : ''} />
				<Spinner class={update.isPending ? '' : 'hidden'} />
				Save
			</Button>
		</Card.Footer>
	</Card.Root>

	<Card.Root class="overflow-hidden rounded-xl border shadow-sm">
		<Card.Header>
			<Card.Title class="text-base font-semibold">Details</Card.Title>
		</Card.Header>
		<Card.Content class="grid gap-4 sm:grid-cols-2">
			<Item.Root variant="outline" size="sm">
				<Item.Media>
					<Hash class="text-muted-foreground" />
				</Item.Media>
				<Item.Content class="overflow-hidden">
					<Item.Title>Workspace ID</Item.Title>
					<Item.Description class="truncate font-mono">
						<CopyButton text={ws.data.id} icon={false} class="p-0 hover:bg-transparent">
							<span class="font-mono text-sm font-light">{ws.data.id}</span>
						</CopyButton>
					</Item.Description>
				</Item.Content>
			</Item.Root>

			<Item.Root variant="outline" size="sm">
				<Item.Media>
					<User class="text-muted-foreground" />
				</Item.Media>
				<Item.Content class="overflow-hidden">
					<Item.Title>Owner</Item.Title>
					<Item.Description class="truncate font-mono">
						<CopyButton text={owner?.email || ''} icon={false} class="p-0 hover:bg-transparent">
							<span class="font-mono text-sm font-light">{owner?.email}</span>
						</CopyButton>
					</Item.Description>
				</Item.Content>
			</Item.Root>

			<Item.Root variant="outline" size="sm">
				<Item.Media>
					<CalendarIcon class="text-muted-foreground" />
				</Item.Media>
				<Item.Content class="overflow-hidden">
					<Item.Title>Created</Item.Title>
					<Item.Description class="truncate font-mono">
						{formatTs(ws.data.createdAt)}
					</Item.Description>
				</Item.Content>
			</Item.Root>

			<Item.Root variant="outline" size="sm">
				<Item.Media>
					<ClockIcon class="text-muted-foreground" />
				</Item.Media>
				<Item.Content class="overflow-hidden">
					<Item.Title>Last Updated</Item.Title>
					<Item.Description class="truncate font-mono">
						{formatTs(ws.data.updatedAt, 'relative')}
					</Item.Description>
				</Item.Content>
			</Item.Root>
		</Card.Content>
	</Card.Root>

	<Card.Root class="border border-destructive/20">
		<Card.Header>
			<Card.Title class="font-medium text-destructive">Delete this workspace</Card.Title>
			<Card.Description>
				Once you delete a workspace, there is no going back. All data including members, teams, and
				certificates will be permanently removed. Any active subscription attached to this workspace
				will also be canceled.</Card.Description
			>
		</Card.Header>

		<Card.Footer class="flex justify-between border-t border-destructive/20 bg-destructive/5">
			<p class="text-sm font-medium text-destructive">Proceed with caution.</p>
			<Button
				variant="destructive"
				size="sm"
				onclick={() => (deleteOpen = true)}
				class="w-full sm:w-auto"
			>
				Delete Workspace
			</Button>
		</Card.Footer>
	</Card.Root>
{/if}
