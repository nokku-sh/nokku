<script lang="ts">
	import { WorkspaceRole } from '#lib/gen/nokku/v1/access_pb.js';
	import { httpFetch } from '#lib/api/client.js';
	import { credentials } from '#lib/api/credential.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import DangerZone from '#lib/components/sheets/DangerZone.svelte';
	import FormModal from '#lib/components/blocks/FormModal.svelte';
	import SaveStatus from '#lib/components/blocks/SaveStatus.svelte';
	import * as Alert from '#lib/components/ext/alert/index.js';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import * as ImageCropper from '#lib/components/ui/image-cropper/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import * as InputGroup from '#lib/components/ui/input-group/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import { UserSchema } from '#lib/gen/nokku/v1/account_pb.js';
	import { confirm, useAutoSave, useDraft } from '#lib/hooks/index.js';
	import { roleIcon, roleLabel } from '#lib/roles.js';
	import { formatTs } from '#lib/utils.js';
	import { ArrowRight, Mail, MailQuestionMarkIcon, Trash } from '@lucide/svelte';
	import { toast } from 'svelte-sonner';

	const me = user.self();
	const draft = useDraft(UserSchema, () => me.data);
	const model = $derived(draft.current);
	const RoleIcon = $derived(roleIcon(me.data?.role || WorkspaceRole.MEMBER));

	const updateProfile = user.updateProfile();
	const deleteAccount = user.deleteAccount();
	const requestEmailChange = user.requestEmailChange();
	const creds = credentials.all();
	// An identity provider owns the address of the accounts it signs in.
	const managed = $derived((creds.data ?? []).some((c) => c.type === 'oidc' || c.type === 'scim'));
	const isOwner = $derived(me.data?.role === WorkspaceRole.OWNER);

	let emailOpen = $state(false);
	let newEmail = $state('');

	async function submitEmailChange() {
		await requestEmailChange.mutateAsync({ newEmail });
		toast.success('Check your new inbox', {
			description: 'The address changes once you click the link we sent there.'
		});
		newEmail = '';
	}

	const autoSave = useAutoSave(() => updateProfile.mutateAsync({ name: model?.name }));

	function askDelete() {
		void confirm({
			title: 'Delete your account?',
			description:
				'This deletes your account and every grant you have here. This cannot be undone.',
			typeToConfirm: me.data?.email,
			onConfirm: () => deleteAccount.mutateAsync({})
		});
	}
</script>

<PageHeader title="Profile" description="Who you are in this workspace">
	<Button href="/profile/security" variant="link">
		Security
		<ArrowRight />
	</Button>
</PageHeader>

{#if !model}
	<Skeleton class="h-48 w-full rounded-xl" />
{:else}
	<Card.Root>
		<Card.Content class="flex flex-col gap-6 sm:flex-row">
			<ImageCropper.Root
				bind:src={() => model.picture ?? '', (v) => (model.picture = v)}
				onCropped={async (file) => {
					try {
						const form = new FormData();
						form.append('picture', file);
						const res = await httpFetch('/upload/avatar', { method: 'POST', body: form });
						// The upload only stores the file, UpdateAccount attaches it.
						const { url } = await res.json();
						await updateProfile.mutateAsync({ picture: url });
						toast.success('Avatar updated');
					} catch {
						// httpFetch already toasted the error.
					}
				}}
				onUnsupportedFile={(file) => toast.error(`Unsupported file type: ${file.type}`)}
			>
				<div class="relative self-center sm:self-start">
					<ImageCropper.UploadTrigger>
						<ImageCropper.Preview class="size-24" />
					</ImageCropper.UploadTrigger>
					{#if model.picture}
						<Button
							class="absolute -right-2 -bottom-2 rounded-full"
							variant="outline"
							size="icon-sm"
							aria-label="Remove avatar"
							onclick={() => {
								model.picture = '';
								updateProfile.mutate({ picture: '' });
							}}
						>
							<Trash />
						</Button>
					{/if}
				</div>
				<ImageCropper.Dialog>
					<ImageCropper.Cropper />
					<ImageCropper.Controls>
						<ImageCropper.Crop />
						<ImageCropper.Cancel />
					</ImageCropper.Controls>
				</ImageCropper.Dialog>
			</ImageCropper.Root>

			<Field.Group class="flex-1 gap-4">
				<Field.Field>
					<Field.Label for="profile-name">Name</Field.Label>
					<Input
						id="profile-name"
						bind:value={model.name}
						placeholder="Ada Lovelace"
						oninput={() => autoSave.save()}
					/>
					<Field.Description>Shown to your teammates and in the audit log.</Field.Description>
				</Field.Field>
				<Field.Field>
					<Field.Label for="profile-email">Email</Field.Label>
					<InputGroup.Root>
						<InputGroup.Addon><Mail /></InputGroup.Addon>
						<InputGroup.Input id="profile-email" value={model.email} readonly />
						{#if !managed}
							<InputGroup.Addon align="inline-end">
								<InputGroup.Button onclick={() => (emailOpen = true)}>Change</InputGroup.Button>
							</InputGroup.Addon>
						{/if}
					</InputGroup.Root>
					<Field.Description>
						{managed
							? 'Your identity provider owns this address. Change it there.'
							: 'Your sign-in email. A change needs a click in the new inbox.'}
					</Field.Description>
				</Field.Field>
				{#if model.pendingEmail}
					<Alert.Root>
						<MailQuestionMarkIcon />
						<Alert.Title>Waiting for {model.pendingEmail}</Alert.Title>
						<Alert.Description>
							Click the link we sent there to finish the change. Until then you sign in with your
							current address.
						</Alert.Description>
					</Alert.Root>
				{/if}
			</Field.Group>
		</Card.Content>
		<Card.Footer class="flex justify-between gap-3 border-t">
			<SaveStatus state={autoSave.saveState} idleText="Changes save automatically" />
			<span class="flex items-center gap-2 text-xs text-muted-foreground">
				<Badge variant="secondary">
					<RoleIcon data-icon="inline-start" />
					{roleLabel(me.data?.role || WorkspaceRole.MEMBER)}
				</Badge>
				since {formatTs(me.data?.createdAt, 'short')}
			</span>
		</Card.Footer>
	</Card.Root>

	<FormModal
		bind:open={emailOpen}
		title="Change your email address"
		description="We send a link to the new address. Your current address gets a notice and can cancel the change."
		icon={Mail}
		submitLabel="Send the link"
		submitDisabled={!newEmail}
		onSubmit={submitEmailChange}
	>
		<Field.Field>
			<Field.Label for="new-email">New email</Field.Label>
			<Input
				id="new-email"
				type="email"
				autocomplete="email"
				bind:value={newEmail}
				placeholder="you@company.com"
				required
			/>
		</Field.Field>
	</FormModal>

	<DangerZone
		actions={[
			{
				title: 'Delete account',
				description: isOwner
					? 'The owner cannot leave. Transfer ownership to someone else first.'
					: 'Removes you from this workspace for good.',
				label: 'Delete',
				disabled: isOwner,
				onClick: askDelete
			}
		]}
	/>
{/if}
