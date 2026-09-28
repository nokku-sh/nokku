<script lang="ts">
	import { auth } from '$lib/api/auth.svelte';
	import { httpFetch } from '$lib/api/client';
	import { user, type LinkedAccount } from '$lib/api/user.svelte';
	import { GitHubIcon, GoogleIcon, OIDCIcon, SAMLIcon } from '$lib/assets';
	import DeleteConfirmationModal from '$lib/components/modals/DeleteConfirmationModal.svelte';
	import Badge from '$lib/components/ui/badge/badge.svelte';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import * as Empty from '$lib/components/ui/empty';
	import * as Field from '$lib/components/ui/field';
	import * as ImageCropper from '$lib/components/ui/image-cropper';
	import { Input } from '$lib/components/ui/input';
	import * as Item from '$lib/components/ui/item';
	import Spinner from '$lib/components/ui/spinner/spinner.svelte';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import { UserSchema } from '$lib/gen/nokku/v1/account_pb';
	import { create } from '@bufbuild/protobuf';
	import {
		BadgeCheck,
		Link,
		Save,
		Send,
		Trash2,
		TriangleAlert,
		Unlink,
		User
	} from '@lucide/svelte';
	import { toast } from 'svelte-sonner';

	const userData = $derived.by(() => user.self());
	let currentUser = $state(create(UserSchema));

	$effect(() => {
		if (userData.data) currentUser = create(UserSchema, userData.data);
	});

	const updateProfile = user.updateProfile();
	const resendVerification = auth.resendVerification();

	const linkedAccounts = $derived.by(() => user.listLinkedAccounts());
	const unlink = user.unlinkAccount();

	let unlinkProvider = $state('');
	let unlinkOpen = $state(false);

	function providerName(account: LinkedAccount): string {
		switch (account.provider) {
			case 'github':
				return 'GitHub';
			case 'google':
				return 'Google';
			default:
				return account.protocol === 'saml' ? 'SAML' : 'OIDC';
		}
	}

	function providerIcon(account: LinkedAccount) {
		switch (account.provider) {
			case 'github':
				return GitHubIcon;
			case 'google':
				return GoogleIcon;
			default:
				return account.protocol === 'saml' ? SAMLIcon : OIDCIcon;
		}
	}

	function linkAccount(provider: string) {
		const endpoint = provider === 'github' ? '/oauth/login' : '/oidc/login';
		const query =
			provider === 'github' ? 'provider=github&link=true' : `provider=${provider}&link=true`;
		window.location.href = `${endpoint}?${query}`;
	}
</script>

<PageHeader
	title="Profile"
	description="Manage your account information and personal details."
	icon={User}
/>

<div class="flex flex-col gap-6 md:flex-row">
	<div
		class="flex min-w-75 flex-col items-center justify-center rounded-xl border bg-card/30 py-6 text-card-foreground shadow-sm"
	>
		<div class="flex flex-col items-center gap-6 text-center">
			<ImageCropper.Root
				bind:src={currentUser.picture}
				onCropped={async (file) => {
					try {
						const formData = new FormData();
						formData.append('picture', file);
						const res = await httpFetch('/upload/avatar', {
							method: 'POST',
							body: formData
						});
						// The upload only stores the file, UpdateAccount attaches it.
						const { url } = await res.json();
						updateProfile.mutate({ ...currentUser, picture: url });
						toast.success('Avatar uploaded successfully!');
					} catch {}
				}}
				onUnsupportedFile={(file) => {
					toast.error(`Unsupported file type: ${file.type}`);
				}}
			>
				<div class="relative">
					<ImageCropper.UploadTrigger>
						<ImageCropper.Preview class="size-24" />
					</ImageCropper.UploadTrigger>
					<Button
						class="absolute -right-2 -bottom-3 rounded-full"
						variant="outline"
						size="icon"
						onclick={() => updateProfile.mutate({ ...currentUser, picture: '' })}
					>
						<Trash2 class="text-destructive" />
					</Button>
				</div>
				<ImageCropper.Dialog>
					<ImageCropper.Cropper />
					<ImageCropper.Controls>
						<ImageCropper.Crop />
						<ImageCropper.Cancel />
					</ImageCropper.Controls>
				</ImageCropper.Dialog>
			</ImageCropper.Root>

			<div class="space-y-1">
				<h3 class="text-xl font-bold">{currentUser?.name || 'Operator'}</h3>
				<p class="text-sm text-muted-foreground">
					{currentUser?.email || 'email@example.com'}
					{#if currentUser?.emailVerified}
						<BadgeCheck size={16} class="inline text-emerald-600" />
					{/if}
				</p>
			</div>
		</div>
	</div>

	<Card.Root class="w-full">
		<Card.Content class="space-y-4">
			<Field.Field>
				<Field.Label for="description">Full Name</Field.Label>
				<Field.Content>
					<Input
						id="name"
						type="text"
						bind:value={currentUser.name}
						placeholder="Enter your full name"
					/>
					<Field.Description>Optional, used for billing and communication.</Field.Description>
				</Field.Content>
			</Field.Field>

			<Field.Field>
				<Field.Label for="description">Email</Field.Label>
				<Field.Content class="flex items-center gap-2">
					<Input
						id="email"
						type="email"
						bind:value={currentUser.email}
						required
						placeholder="Enter your email"
					/>
				</Field.Content>
			</Field.Field>

			{#if !currentUser?.emailVerified}
				<div class="rounded-lg border border-orange-500/20 bg-orange-500/5 p-4">
					<div class="flex items-center gap-1 text-sm text-orange-600 dark:text-orange-400">
						<TriangleAlert size={16} />
						<div class="flex w-full items-center justify-between">
							<span class="font-medium">Your email address is not verified!</span>
							<Button
								size="sm"
								variant="outline"
								onclick={() => resendVerification.mutate({ email: currentUser.email })}
								disabled={resendVerification.isPending || resendVerification.isSuccess}
							>
								<Spinner class={resendVerification.isPending ? '' : 'hidden'} />
								{#if resendVerification.isSuccess}
									Email Sent!
								{:else}
									<Send size={12} /> Resend Verification
								{/if}
							</Button>
						</div>
					</div>
				</div>
			{/if}
		</Card.Content>

		<Card.Footer class="flex justify-end">
			<Button
				variant="default"
				size="sm"
				onclick={() => updateProfile.mutate(currentUser)}
				disabled={updateProfile.isPending}
				class="w-full sm:w-auto"
			>
				<Save class={updateProfile.isPending ? 'hidden' : ''} />
				<Spinner class={updateProfile.isPending ? '' : 'hidden'} />
				Save
			</Button>
		</Card.Footer>
	</Card.Root>
</div>

<Card.Root>
	<Card.Header>
		<Card.Title class="flex items-center gap-2 text-lg">
			<Link class="size-5 text-muted-foreground" />
			Connected Accounts
		</Card.Title>
		<Card.Description>Link your GitHub or Google account for easy sign-in.</Card.Description>
	</Card.Header>

	<Card.Content>
		{#if linkedAccounts.isSuccess && linkedAccounts.data.length > 0}
			<Item.Group class="border-border bg-transparent">
				{#each linkedAccounts.data as account (account.provider + ':' + account.providerId)}
					{@const Icon = providerIcon(account)}
					<Item.Root variant="muted">
						<Item.Media variant="icon"><Icon /></Item.Media>
						<Item.Content>
							<Item.Title>{providerName(account)}</Item.Title>
							<Item.Description>Connected</Item.Description>
						</Item.Content>
						<Item.Actions>
							{#if account.provider === 'github' || account.provider === 'google'}
								<Button
									variant="ghost"
									size="sm"
									onclick={() => {
										unlinkProvider = account.provider;
										unlinkOpen = true;
									}}
								>
									<Unlink class="size-4" />
								</Button>
							{:else}
								<Badge variant="default">managed</Badge>
							{/if}
						</Item.Actions>
					</Item.Root>
				{/each}
			</Item.Group>
		{:else if linkedAccounts.isSuccess}
			<Empty.Root class="bg-muted/50">
				<Empty.Title>No accounts linked</Empty.Title>
				<Empty.Description>
					Link a GitHub or Google account to sign in without a password.
				</Empty.Description>
			</Empty.Root>
		{:else if linkedAccounts.isError}
			<Empty.Root class="bg-muted/50">
				<Empty.Title>Could not load linked accounts</Empty.Title>
				<Empty.Description>Try reloading the page.</Empty.Description>
			</Empty.Root>
		{/if}
	</Card.Content>

	<Card.Footer class="flex items-center justify-between">
		<p class="text-sm text-muted-foreground">You can link one account per provider.</p>
		<div class="flex gap-2">
			{#if linkedAccounts.isSuccess}
				<Button
					size="sm"
					variant="outline"
					onclick={() => linkAccount('google')}
					disabled={linkedAccounts.data.filter((a) => a.provider === 'google').length > 0}
				>
					<GoogleIcon class="size-4" />
					Link Google
				</Button>
				<Button
					size="sm"
					variant="outline"
					onclick={() => linkAccount('github')}
					disabled={linkedAccounts.data.filter((a) => a.provider === 'github').length > 0}
				>
					<GitHubIcon class="size-4" />
					Link GitHub
				</Button>
			{/if}
		</div>
	</Card.Footer>
</Card.Root>

<DeleteConfirmationModal
	bind:open={unlinkOpen}
	title="Unlink Account"
	description="This will remove the connected account. You can link it again later."
	onConfirm={() => {
		unlink.mutate({ provider: unlinkProvider });
	}}
/>
