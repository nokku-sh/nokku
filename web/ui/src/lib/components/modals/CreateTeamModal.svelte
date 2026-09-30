<script lang="ts">
	import { create } from '@bufbuild/protobuf';
	import { Users } from '@lucide/svelte';
	import { team as teamApi } from '$lib/api/team.svelte';
	import * as Field from '$lib/components/ui/field';
	import { Input } from '$lib/components/ui/input';
	import { Textarea } from '$lib/components/ui/textarea';
	import { TeamSchema } from '$lib/gen/nokku/v1/team_pb';
	import { useSheet } from '$lib/hooks';
	import FormModal from '$lib/components/blocks/FormModal.svelte';

	let { open = $bindable(false) }: { open?: boolean } = $props();

	const sheet = useSheet();
	const createTeam = teamApi.create();
	let model = $state(create(TeamSchema));

	async function onSubmit() {
		const res = await createTeam.mutateAsync({ ...model });
		model = create(TeamSchema);
		if (res.team) sheet.show(res.team.id, 'members');
	}
</script>

<FormModal
	bind:open
	title="Create a team"
	description="Group people and grant them access together."
	icon={Users}
	submitLabel="Create team"
	{onSubmit}
>
	<Field.Field>
		<Field.Label for="new-team-name">Name</Field.Label>
		<Input id="new-team-name" bind:value={model.name} placeholder="Platform" required />
	</Field.Field>
	<Field.Field>
		<Field.Label for="new-team-description">Description</Field.Label>
		<Textarea
			id="new-team-description"
			bind:value={model.description}
			placeholder="Owns production infrastructure"
		/>
	</Field.Field>
</FormModal>
