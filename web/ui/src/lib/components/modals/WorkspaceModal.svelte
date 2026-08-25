<script lang="ts">
	import { Layers2 } from '@lucide/svelte';
	import { workspace } from '$lib/api/workspaces.svelte';
	import * as Field from '$lib/components/ui/field';
	import { Input } from '$lib/components/ui/input';
	import { Textarea } from '$lib/components/ui/textarea';
	import type { Workspace } from '$lib/gen/nokku/v1/workspace_pb';
	import { useAutoSave } from '$lib/hooks';
	import FormModal from './FormModal.svelte';

	interface Props {
		draft: Workspace;
		open?: boolean;
	}
	let { draft: model, open = $bindable(false) }: Props = $props();

	const isEdit = $derived(!!model.id);

	const createMutation = workspace.create();
	const updateMutation = workspace.update();
	const isLoading = $derived(createMutation.isPending);

	const autoSave = useAutoSave(() => updateMutation.mutateAsync({ ...model }));
	function save() {
		if (isEdit) autoSave.save();
	}

	function onSubmit() {
		createMutation.mutate({ ...model });
		open = false;
	}
</script>

<FormModal
	bind:open
	title={isEdit ? 'Edit Workspace' : 'Create Workspace'}
	description={isEdit
		? 'Changes save automatically.'
		: 'Workspaces isolate targets, members, and certificates.'}
	icon={isEdit ? undefined : Layers2}
	onSubmit={isEdit ? undefined : onSubmit}
	{isLoading}
	saveState={autoSave.saveState}
>
	<Field.Field>
		<Field.Label for="workspace-name">Name</Field.Label>
		<Field.Content>
			<Input
				id="workspace-name"
				bind:value={model.name}
				placeholder="Production"
				required
				oninput={save}
			/>
		</Field.Content>
	</Field.Field>

	<Field.Field>
		<Field.Label for="workspace-description">Description</Field.Label>
		<Field.Content>
			<Textarea
				id="workspace-description"
				bind:value={model.description}
				placeholder="What this workspace is for"
				oninput={save}
			/>
		</Field.Content>
	</Field.Field>
</FormModal>
