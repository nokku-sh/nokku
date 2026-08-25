<script lang="ts">
	import { Settings2, Users } from '@lucide/svelte';
	import { team } from '$lib/api/team.svelte';
	import * as Field from '$lib/components/ui/field';
	import { Input } from '$lib/components/ui/input';
	import * as Tabs from '$lib/components/ui/tabs';
	import { Textarea } from '$lib/components/ui/textarea';
	import type { Team } from '$lib/gen/nokku/v1/team_pb';
	import { useAutoSave } from '$lib/hooks';
	import FormModal from './FormModal.svelte';
	import MetaInfo from './MetaInfo.svelte';
	import ModalTabs from './ModalTabs.svelte';
	import TeamMembersField from './TeamMembersField.svelte';

	interface Props {
		draft: Team;
		open?: boolean;
	}
	let { draft: model, open = $bindable(false) }: Props = $props();

	const isEdit = $derived(!!model.id);

	const createMutation = team.create();
	const updateMutation = team.update();
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
	title={isEdit ? model.name : 'Create Team'}
	description={isEdit
		? 'Changes save automatically.'
		: 'Teams group members for easier access assignment.'}
	onSubmit={isEdit ? undefined : onSubmit}
	{isLoading}
	saveState={autoSave.saveState}
>
	<ModalTabs
		tabs={isEdit
			? [
					{ value: 'general', label: 'General', icon: Settings2 },
					{ value: 'members', label: 'Members', icon: Users }
				]
			: [{ value: 'general', label: 'General', icon: Settings2 }]}
	>
		<Tabs.Content value="general" class="space-y-4">
			<Field.Field>
				<Field.Label for="team-name">Name</Field.Label>
				<Field.Content>
					<Input
						id="team-name"
						bind:value={model.name}
						placeholder="Platform Team"
						required
						oninput={save}
					/>
				</Field.Content>
			</Field.Field>

			<Field.Field>
				<Field.Label for="team-description">Description</Field.Label>
				<Field.Content>
					<Textarea
						id="team-description"
						bind:value={model.description}
						placeholder="Owns production infrastructure access"
						oninput={save}
					/>
				</Field.Content>
			</Field.Field>

			{#if isEdit}
				<MetaInfo createdAt={model.createdAt} updatedAt={model.updatedAt} />
			{/if}
		</Tabs.Content>

		{#if isEdit}
			<Tabs.Content value="members" class="space-y-4">
				<TeamMembersField data={model} />
			</Tabs.Content>
		{/if}
	</ModalTabs>
</FormModal>
