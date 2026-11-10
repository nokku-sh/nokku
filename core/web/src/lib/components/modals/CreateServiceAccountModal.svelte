<script lang="ts">
	import { WorkspaceRole } from '#lib/gen/nokku/v1/access_pb.js';
	import { Bot } from '@lucide/svelte';
	import { serviceAccount as saApi } from '#lib/api/service_account.svelte.js';
	import RolePicker from '#lib/components/access/RolePicker.svelte';
	import { SERVICE_ACCOUNT_MAX_ROLE } from '#lib/roles.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Textarea } from '#lib/components/ui/textarea/index.js';
	import { ServiceAccountSchema } from '#lib/gen/nokku/v1/service_account_pb.js';
	import { newDraft, useSheet } from '#lib/hooks/index.js';
	import FormModal from '#lib/components/blocks/FormModal.svelte';

	let { open = $bindable(false) }: { open?: boolean } = $props();

	const sheet = useSheet();
	const createSA = saApi.create();

	let model = $state(newDraft(ServiceAccountSchema, { role: WorkspaceRole.VIEWER }));

	// No key here. A CI job needs none, and a script gets one from the sheet.
	async function onSubmit() {
		const res = await createSA.mutateAsync({ ...model });
		model = newDraft(ServiceAccountSchema, { role: WorkspaceRole.VIEWER });
		await sheet.show(res.serviceAccount?.id ?? '', 'ci');
	}
</script>

<FormModal
	bind:open
	title="Create a service account"
	description="An API identity for CI, Ansible and other automation. How it signs in comes next."
	icon={Bot}
	submitLabel="Create"
	{onSubmit}
>
	<Field.Field>
		<Field.Label for="new-sa-name">Name</Field.Label>
		<Input id="new-sa-name" bind:value={model.name} placeholder="github-deploy" required />
	</Field.Field>

	<Field.Field>
		<Field.Label for="new-sa-description">What it's for</Field.Label>
		<Textarea
			id="new-sa-description"
			bind:value={model.description}
			placeholder="Deploys from the main branch"
			rows={2}
		/>
	</Field.Field>

	<Field.Set>
		<Field.Legend variant="label">Workspace role</Field.Legend>
		<RolePicker
			value={model.role}
			max={SERVICE_ACCOUNT_MAX_ROLE}
			machine
			onChange={(role) => (model.role = role)}
		/>
	</Field.Set>
</FormModal>
