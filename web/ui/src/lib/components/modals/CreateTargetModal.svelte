<script lang="ts">
	import { create } from '@bufbuild/protobuf';
	import { Server } from '@lucide/svelte';
	import { ca } from '#lib/api/certificates.svelte.js';
	import { target as targetApi } from '#lib/api/targets.svelte.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { TagsInput } from '#lib/components/ui/tags-input/index.js';
	import * as Select from '#lib/components/ui/select/index.js';
	import { Textarea } from '#lib/components/ui/textarea/index.js';
	import { AuthorityType } from '#lib/gen/nokku/v1/certificates_pb.js';
	import { TargetSchema } from '#lib/gen/nokku/v1/target_pb.js';
	import { useSheet } from '#lib/hooks/index.js';
	import FormModal from '#lib/components/blocks/FormModal.svelte';

	let { open = $bindable(false) }: { open?: boolean } = $props();

	const sheet = useSheet();
	// A server only takes an SSH CA, and each kind has its own default.
	const cas = ca.list();
	const sshCAs = $derived((cas.data ?? []).filter((c) => c.authorityType === AuthorityType.SSH));
	const tagFilters = targetApi.filters();
	const createTarget = targetApi.create();

	let model = $state(create(TargetSchema));
	const caId = $derived(model.caId || sshCAs.find((c) => c.isDefault)?.id || '');

	async function onSubmit() {
		const res = await createTarget.mutateAsync({ ...model, caId });
		model = create(TargetSchema);
		if (res.target) sheet.show(res.target.id, 'access');
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
		<Field.Label for="new-target-ca">Certificate authority</Field.Label>
		<Select.Root type="single" value={caId} onValueChange={(v) => (model.caId = v)}>
			<Select.Trigger id="new-target-ca" class="w-full">
				{sshCAs.find((c) => c.id === caId)?.name ?? 'Choose a CA'}
			</Select.Trigger>
			<Select.Content>
				<Select.Group>
					{#each sshCAs as c (c.id)}
						<Select.Item value={c.id}>{c.name}</Select.Item>
					{/each}
				</Select.Group>
			</Select.Content>
		</Select.Root>
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
