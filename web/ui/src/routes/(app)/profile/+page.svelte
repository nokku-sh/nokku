<script lang="ts">
	import { goto } from '$app/navigation';
	import { auth } from '$lib/api/auth.svelte';
	import { httpFetch } from '$lib/api/client';
	import { user } from '$lib/api/user.svelte';
	import { workspace } from '$lib/api/workspaces.svelte';
	import DangerZone from '$lib/components/sheets/DangerZone.svelte';
	import SaveStatus from '$lib/components/sheets/SaveStatus.svelte';
	import * as Alert from '$lib/components/ui/alert';
	import { Badge } from '$lib/components/ui/badge';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import * as Field from '$lib/components/ui/field';
	import * as ImageCropper from '$lib/components/ui/image-cropper';
	import { Input } from '$lib/components/ui/input';
	import * as InputGroup from '$lib/components/ui/input-group';
	import * as Item from '$lib/components/ui/item';
	import { Skeleton } from '$lib/components/ui/skeleton';
	import { Spinner } from '$lib/components/ui/spinner';
	import Avatar from '$lib/components/utils/Avatar.svelte';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import { UserSchema } from '$lib/gen/nokku/v1/account_pb';
	import { confirm, useAutoSave, useDraft } from '$lib/hooks';
	import { roleLabel } from '$lib/roles';
	import { workspaceID } from '$lib/store.svelte';
	import { formatTs } from '$lib/utils';
	import { BadgeCheck, Mail, Send, ShieldCheck, Trash2, TriangleAlert, User } from '@lucide/svelte';
	import { toast } from 'svelte-sonner';

	const me = user.self();
	const draft = useDraft(UserSchema, () => me.data);
	const model = $derived(draft.current);

	const updateProfile = user.updateProfile();
	const resendVerification = auth.resendVerification();
	const deleteAccount = user.deleteAccount();
	const workspaces = workspace.list();

	const autoSave = useAutoSave(() => updateProfile.mutateAsync({ name: model?.name }));

	const owned = $derived(
		(workspaces.data ?? []).filter((w) => w.createdBy === me.data?.id).map((w) => w.name)
	);

	function askDelete() {
		void confirm({
			title: 'Delete your account?',
			description: owned.length
				? `This deletes your account and the workspaces you own: ${owned.join(', ')}. A workspace other people still use can't go with it, transfer its ownership first. Active subscriptions are canceled. This cannot be undone.`
				: 'This deletes your account and removes you from every workspace. This cannot be undone.',
			typeToConfirm: me.data?.email,
			onConfirm: () => deleteAccount.mutateAsync({})
		});
	}

	function switchTo(id: string) {
		workspaceID.current = id;
		void goto('/');
	}
</script>

<PageHeader title="Profile" description="Who you are across Nokku." icon={User} />

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
							<Trash2 />
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
						{#if model.emailVerified}
							<InputGroup.Addon align="inline-end">
								<BadgeCheck class="text-success" />
								<span class="text-xs text-success">Verified</span>
							</InputGroup.Addon>
						{/if}
					</InputGroup.Root>
					<Field.Description>Your sign-in email. It can't be changed here.</Field.Description>
				</Field.Field>
				{#if !model.emailVerified}
					<Alert.Root variant="warning">
						<TriangleAlert />
						<Alert.Title>Your email isn't verified</Alert.Title>
						<Alert.Description>Password resets and notices need a verified email.</Alert.Description
						>
						<Alert.Action>
							<Button
								size="sm"
								variant="outline"
								onclick={() => resendVerification.mutate({ email: model.email })}
								disabled={resendVerification.isPending || resendVerification.isSuccess}
							>
								{#if resendVerification.isPending}
									<Spinner data-icon="inline-start" />
								{:else if !resendVerification.isSuccess}
									<Send data-icon="inline-start" />
								{/if}
								{resendVerification.isSuccess ? 'Email sent' : 'Resend'}
							</Button>
						</Alert.Action>
					</Alert.Root>
				{/if}
			</Field.Group>
		</Card.Content>
		<Card.Footer class="flex justify-between gap-3 border-t">
			<SaveStatus state={autoSave.saveState} idleText="Changes save automatically" />
			<span class="text-xs text-muted-foreground">
				Member since {formatTs(me.data?.createdAt, 'short')}
			</span>
		</Card.Footer>
	</Card.Root>

	<Card.Root>
		<Card.Header>
			<Card.Title class="text-base">Your workspaces</Card.Title>
			<Card.Description>Where you're a member, and your role in each.</Card.Description>
			<Card.Action>
				<Button size="sm" variant="ghost" href="/profile/security">
					<ShieldCheck data-icon="inline-start" />
					Security
				</Button>
			</Card.Action>
		</Card.Header>
		<Card.Content>
			{#if workspaces.isLoading}
				<Skeleton class="h-16 w-full" />
			{:else if workspaces.data?.length}
				<Item.Group class="divide-y rounded-lg border">
					{#each workspaces.data as w (w.id)}
						{@const current = w.id === workspaceID.current}
						<Item.Root size="sm" class="rounded-none">
							<Item.Media><Avatar id={w.id} class="size-8 rounded-lg" /></Item.Media>
							<Item.Content>
								<Item.Title class="flex items-center gap-2">
									{w.name}
									{#if current}<Badge variant="success">Current</Badge>{/if}
								</Item.Title>
								{#if w.description}
									<Item.Description>{w.description}</Item.Description>
								{/if}
							</Item.Content>
							<Item.Actions>
								<Badge variant="secondary">{roleLabel(w.role)}</Badge>
								{#if !current}
									<Button size="sm" variant="ghost" onclick={() => switchTo(w.id)}>Switch</Button>
								{/if}
							</Item.Actions>
						</Item.Root>
					{/each}
				</Item.Group>
			{:else}
				<p class="text-sm text-muted-foreground">You're not in a workspace yet.</p>
			{/if}
		</Card.Content>
	</Card.Root>

	<DangerZone
		actions={[
			{
				title: 'Delete account',
				description: owned.length
					? `Also deletes the workspaces you own (${owned.length}).`
					: 'Removes you from every workspace.',
				label: 'Delete',
				onClick: askDelete
			}
		]}
	/>
{/if}
