<script lang="ts">
	import { Server } from '@lucide/svelte';
	import { target as targetApi } from '#lib/api/targets.svelte.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { TagsInput } from '#lib/components/ui/tags-input/index.js';
	import { Textarea } from '#lib/components/ui/textarea/index.js';
	import { TargetSchema } from '#lib/gen/nokku/v1/target_pb.js';
	import { newDraft, useSheet } from '#lib/hooks/index.js';
	import FormModal from '#lib/components/blocks/FormModal.svelte';

	let { open = $bindable(false) }: { open?: boolean } = $props();

	const sheet = useSheet();
	const tagFilters = targetApi.filters();
	const createTarget = targetApi.create();

	let model = $state(newDraft(TargetSchema));

	async function onSubmit() {
		const res = await createTarget.mutateAsync({ ...model });
		model = newDraft(TargetSchema);
		if (res.target) await sheet.show(res.target.id, 'access');
	}
</script>

<FormModal
	bind:open
	title="Add a target"
	description="A server people log in to. Accounts and access are set up right after."
	icon={Server}
	submitLabel="Add target"
	{onSubmit}
>
	<Field.Field>
		<Field.Label for="new-target-name">Name</Field.Label>
		<Input id="new-target-name" bind:value={model.name} placeholder="web-prod-1" required />
		<Field.Description>Used in ssh user@name. Letters, digits, - and _.</Field.Description>
	</Field.Field>

	<Field.Field>
		<Field.Label for="new-target-description">Description</Field.Label>
		<Textarea
			id="new-target-description"
			bind:value={model.description}
			placeholder="Production web server, Frankfurt"
		/>
	</Field.Field>

	<Field.Field>
		<Field.Label for="new-target-tags">Tags</Field.Label>
		<TagsInput
			id="new-target-tags"
			bind:value={model.tags}
			suggestions={tagFilters.data?.tags}
			placeholder="linux, production"
		/>
	</Field.Field>
</FormModal>
