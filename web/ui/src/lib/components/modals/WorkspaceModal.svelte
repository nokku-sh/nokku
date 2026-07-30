<script lang="ts">
	import { workspace } from '$lib/api/workspaces.svelte';
	import FormModal from '$lib/components/modals/FormModal.svelte';
	import * as Field from '$lib/components/ui/field';
	import { Input } from '$lib/components/ui/input';
	import type { Workspace } from '$lib/gen/nokku/v1/workspace_pb';
	import Textarea from '$lib/components/ui/textarea/textarea.svelte';

	interface Props {
		data?: Workspace;
		open?: boolean;
	}
	let { data = $bindable({} as Workspace), open = $bindable(false) }: Props = $props();

	const createMutation = workspace.create();
	const updateMutation = workspace.update();
	let isLoading = $derived(createMutation.isPending || updateMutation.isPending);

	async function onSubmit() {
		if (data.id) {
			updateMutation.mutate({ ...data, workspaceId: data.id });
		} else {
			createMutation.mutate({ ...data });
		}
		open = false;
	}
</script>

<FormModal
	bind:open
	title="{data?.id ? 'Edit' : 'Create'} Workspace"
	description="Configure your workspace"
	submitLabel={data.id ? 'Update' : 'Create'}
	{onSubmit}
	{isLoading}
>
	<Field.Field>
		<Field.Label for="workspace-name">Name</Field.Label>
		<Field.Content>
			<Input id="workspace-name" bind:value={data.name} placeholder="My Workspace" required />
		</Field.Content>
	</Field.Field>

	<Field.Field>
		<Field.Label for="workspace-description">Description</Field.Label>
		<Field.Content>
			<Textarea
				id="workspace-description"
				bind:value={data.description}
				placeholder="My workspace description"
			/>
		</Field.Content>
	</Field.Field>
</FormModal>
