<script lang="ts">
	import FormModal from '#lib/components/blocks/FormModal.svelte';
	import { ca as caApi } from '#lib/api/certificates.svelte.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Switch } from '#lib/components/ui/switch/index.js';
	import { Textarea } from '#lib/components/ui/textarea/index.js';
	import { CertificateAuthoritySchema } from '#lib/gen/nokku/v1/certificates_pb.js';
	import { newDraft, useSheet } from '#lib/hooks/index.js';
	import { Shield } from '@lucide/svelte';

	let { open = $bindable(false) }: { open?: boolean } = $props();

	const sheet = useSheet();
	const createCA = caApi.create();

	// The keys and the lifetimes are the server's, so the two never drift.
	// A draft leaves what it is not given undefined, so every field the form reads is named.
	const blank = () =>
		newDraft(CertificateAuthoritySchema, {
			name: '',
			description: '',
			isDefault: false
		});
	let model = $state(blank());

	function reset() {
		model = blank();
	}

	async function onSubmit() {
		const res = await createCA.mutateAsync({ ...model });
		reset();
		if (res.certificateAuthority) await sheet.show(res.certificateAuthority.id);
	}
</script>

<FormModal
	bind:open
	title="Create a certificate authority"
	description="Its two Ed25519 keys, one for logins and one for servers, are made on the server and never leave it. Lifetimes start from the defaults, change them on the CA afterwards."
	icon={Shield}
	classModal="sm:max-w-lg"
	onOpenChange={(v) => !v && reset()}
	submitLabel="Create CA"
	submitDisabled={!model.name.trim()}
	{onSubmit}
>
	<Field.Field>
		<Field.Label for="new-ca-name">Name</Field.Label>
		<Input id="new-ca-name" bind:value={model.name} placeholder="production-ssh" required />
	</Field.Field>
	<Field.Field>
		<Field.Label for="new-ca-description">Description</Field.Label>
		<Textarea
			id="new-ca-description"
			bind:value={model.description}
			placeholder="Signs production SSH logins"
			rows={2}
		/>
	</Field.Field>
	<Field.Field orientation="horizontal">
		<Field.Content>
			<Field.Label for="new-ca-default">Make it the default</Field.Label>
			<Field.Description>New targets use it unless you pick another CA.</Field.Description>
		</Field.Content>
		<Switch id="new-ca-default" bind:checked={model.isDefault} />
	</Field.Field>
</FormModal>
