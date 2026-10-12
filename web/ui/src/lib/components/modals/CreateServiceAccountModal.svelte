<script lang="ts">
	import { WorkspaceRole } from '#lib/gen/nokku/v1/access_pb.js';
	import SecretReveal from '#lib/components/blocks/SecretReveal.svelte';
	import { Bot, KeyRound } from '@lucide/svelte';
	import { serviceAccount as saApi } from '#lib/api/service_account.svelte.js';
	import RolePicker from '#lib/components/access/RolePicker.svelte';
	import { SERVICE_ACCOUNT_MAX_ROLE } from '#lib/roles.js';
	import * as Alert from '#lib/components/ext/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Dialog from '#lib/components/ui/dialog/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Textarea } from '#lib/components/ui/textarea/index.js';
	import { ServiceAccountSchema } from '#lib/gen/nokku/v1/service_account_pb.js';
	import { newDraft, useSheet } from '#lib/hooks/index.js';
	import FormModal from '#lib/components/blocks/FormModal.svelte';
	import TokenExpiryField, { TokenExpiry } from './TokenExpiryField.svelte';

	let { open = $bindable(false) }: { open?: boolean } = $props();

	const sheet = useSheet();
	const createSA = saApi.create();
	const createToken = saApi.tokens.create();
	const expiry = new TokenExpiry();

	let model = $state(newDraft(ServiceAccountSchema, { role: WorkspaceRole.VIEWER }));
	let tokenLabel = $state('');

	let token = $state('');
	let createdId = $state('');

	// Two calls. If the token fails the account exists, so the sheet opens on its tokens and the toast says why.
	async function onSubmit() {
		const res = await createSA.mutateAsync({ ...model });
		const id = res.serviceAccount?.id ?? '';
		try {
			const tok = await createToken.mutateAsync({
				serviceAccountId: id,
				label: tokenLabel.trim(),
				expiresAt: expiry.timestamp
			});
			token = tok.secret;
			createdId = id;
		} catch {
			await sheet.show(id, 'tokens');
		}
		model = newDraft(ServiceAccountSchema, { role: WorkspaceRole.VIEWER });
		tokenLabel = '';
		expiry.preset = '90';
	}

	function finish() {
		const id = createdId;
		token = '';
		createdId = '';
		if (id) sheet.show(id, 'access');
	}
</script>

<FormModal
	bind:open
	title="Create a service account"
	description="An API identity for CI, Ansible and other automation."
	icon={Bot}
	submitLabel="Create and show token"
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
			onChange={(role) => (model.role = role)}
		/>
	</Field.Set>

	<Field.Field>
		<Field.Label for="new-sa-token-label">First token</Field.Label>
		<Input
			id="new-sa-token-label"
			bind:value={tokenLabel}
			placeholder="github-actions"
			maxlength={100}
		/>
		<Field.Description>Where it will live. More tokens can be added later.</Field.Description>
	</Field.Field>

	<TokenExpiryField {expiry} />
</FormModal>

<Dialog.Root open={!!token} onOpenChange={(v) => !v && finish()}>
	<Dialog.Content class="sm:max-w-lg">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2">
				<KeyRound class="size-4" />
				Copy the token now
			</Dialog.Title>
			<Dialog.Description>Store it in your CI secrets.</Dialog.Description>
		</Dialog.Header>
		<SecretReveal
			values={[{ value: token }, { label: 'As an env var', value: `export NK_TOKEN=${token}` }]}
		/>
		<Alert.Root variant="info">
			<KeyRound />
			<Alert.Description>
				Next, grant it a login account on the targets it deploys to.
			</Alert.Description>
		</Alert.Root>
		<Dialog.Footer>
			<Button onclick={finish}>I saved it, set up access</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
