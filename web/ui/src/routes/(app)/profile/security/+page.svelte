<script lang="ts">
	import { backupCode, passkey, password } from '$lib/api/credential.svelte';
	import { registerPasskey } from '$lib/api/passkey';
	import { user } from '$lib/api/user.svelte';
	import DeleteConfirmationModal from '$lib/components/modals/DeleteConfirmationModal.svelte';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import * as Empty from '$lib/components/ui/empty';
	import * as Field from '$lib/components/ui/field';
	import * as Rename from '$lib/components/ui/rename';
	import { InputGroupVariants } from '$lib/components/ui/input-group';
	import * as Item from '$lib/components/ui/item';
	import { Progress } from '$lib/components/ui/progress';
	import { Spinner } from '$lib/components/ui/spinner';
	import { Switch } from '$lib/components/ui/switch';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import { formatTs } from '$lib/utils';
	import {
		Binary,
		Clock,
		CopyIcon,
		DownloadIcon,
		Globe,
		IdCard,
		KeyRound,
		LoaderCircle,
		Lock,
		MailX,
		MonitorSmartphone,
		ShieldIcon,
		Terminal,
		Trash2,
		TriangleAlert
	} from '@lucide/svelte';
	import { toast } from 'svelte-sonner';
	import Label from '$lib/components/ui/label/label.svelte';
	import CopyButton from '$lib/components/ui/copy-button/copy-button.svelte';

	const currentUser = $derived(user.self());
	const deleteAccount = user.deleteAccount();
	const changePassword = password.update();
	const deletePassword = password.delete();

	const passkeys = $derived(passkey.list());
	const updatePasskey = passkey.update();
	const deletePasskey = passkey.delete();

	const backupCodes = $derived(backupCode.list());
	const createBackupCodes = backupCode.create();
	const deleteBackupCodes = backupCode.delete();

	const listDevices = $derived(user.listUserDevices());
	const deleteDevice = user.deleteUserDevice();

	const setEmailRecovery = user.setEmailRecovery();

	const enableEmailRecovery = $derived(currentUser.data?.enableEmailRecovery ?? true);

	let editingPasskeyId = $state<string | null>(null);
	let deletePasskeyId = $state('');
	let deletePasskeyOpen = $state(false);
	let deletePasswordOpen = $state(false);
	let deleteAccountOpen = $state(false);
	let deleteBackupCodesOpen = $state(false);
	let deleteDeviceOpen = $state(false);
	let deleteDeviceId = $state('');

	let currentPassword = $state('');
	let newPassword = $state('');
	let confirmPassword = $state('');
	let isRegisteringPasskey = $state(false); // Added dedicated loading state

	const getPasswordStrength = (password: string) => {
		if (password.length === 0) return { score: -1, text: '', color: 'default' };
		if (password.length < 8) return { score: 0, text: 'Too short', color: 'destructive' };
		if (password.length < 12) return { score: 1, text: 'Weak', color: 'destructive' };
		if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(password))
			return { score: 2, text: 'Fair', color: 'secondary' };
		return { score: 3, text: 'Strong', color: 'default' };
	};

	let passwordsMatch = $derived(newPassword === confirmPassword);
	let passwordStrength = $derived(getPasswordStrength(newPassword));

	const handleRegisterPasskey = async () => {
		try {
			if (!window.PublicKeyCredential) {
				toast.error('Passkeys not supported', {
					description: 'Your browser does not support passkeys. Please use a modern browser.'
				});
				return;
			}
			isRegisteringPasskey = true;
			await registerPasskey();
			toast.success('Passkey added', {
				description: 'Your passkey has been successfully registered.'
			});
			passkeys.refetch();
		} catch (error) {
			if (error instanceof DOMException) {
				if (error.name === 'NotAllowedError') {
					toast.error('Registration cancelled', {
						description: 'Passkey registration was cancelled or timed out.'
					});
				} else if (error.name === 'InvalidStateError') {
					toast.error('Passkey already exists', {
						description: 'This authenticator is already registered.'
					});
				} else {
					toast.error('Registration failed', { description: error.message });
				}
			} else {
				toast.error('Registration failed', {
					description: 'Failed to register passkey. Please try again.'
				});
			}
		} finally {
			isRegisteringPasskey = false;
		}
	};

	const handleDeletePassword = async () => {
		if (!currentPassword.trim()) {
			toast.error('Please enter your current password');
			return;
		}
		deletePassword.mutate({ currentPassword });
		deletePasswordOpen = false;
		currentPassword = '';
	};

	const handlePasswordUpdate = async (event: Event) => {
		event.preventDefault();
		if (!passwordsMatch) {
			toast.error('Passwords do not match');
			return;
		}
		if (passwordStrength.score < 2) {
			toast.error('Password is too weak');
			return;
		}
		changePassword.mutate({ currentPassword, newPassword });
		currentPassword = '';
		newPassword = '';
		confirmPassword = '';
	};

	const handleDownloadBackupCodes = (codes: string[]) => {
		if (!codes) return;
		const codesList = codes.join('\n');
		const content = `Nokku Backup Codes\nGenerated: ${new Date().toLocaleString()}\n\nKeep these codes in a safe place. Each code can only be used once.\n\n${codesList}\n\nThese codes can be used to access your account if you lose your passkey or password.`;
		const blob = new Blob([content], { type: 'text/plain' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = `nokku-backup-codes-${new Date().toISOString().split('T')[0]}.txt`;
		a.click();
		URL.revokeObjectURL(url);
		toast.success('Backup codes downloaded');
	};

	const handleCopyBackupCodes = async (codes: string[]) => {
		if (!codes) return;
		await navigator.clipboard.writeText(codes.join('\n'));
		toast.success('Backup codes copied to clipboard');
	};
</script>

<PageHeader
	title="Security"
	description="Manage your authentication methods, connected devices, and account recovery options."
	icon={ShieldIcon}
/>

<DeleteConfirmationModal
	bind:open={deletePasskeyOpen}
	title="Delete Passkey"
	description="This will remove your passkey permanently. Make sure you have other ways to access your account."
	onConfirm={() => deletePasskey.mutate({ id: deletePasskeyId })}
/>
<DeleteConfirmationModal
	bind:open={deletePasswordOpen}
	title="Delete Password"
	description="This will remove your password permanently. You will only be able to sign in using your passkeys. Make sure your passkeys are working before deleting your password. You won't be able to recover it."
	itemName="Enter your current password"
	bind:confirmationText={currentPassword}
	requireTyping={true}
	onConfirm={handleDeletePassword}
/>
<DeleteConfirmationModal
	bind:open={deleteBackupCodesOpen}
	title="Delete Backup Codes"
	description="This will invalidate all existing backup codes, making it impossible to use them to recover your account."
	onConfirm={() => deleteBackupCodes.mutate({})}
/>
<DeleteConfirmationModal
	bind:open={deleteDeviceOpen}
	title="Revoke Device Access"
	description="This will immediately revoke this CLI device's authorization. Any active terminal sessions will be terminated."
	onConfirm={() => deleteDevice.mutate({ id: deleteDeviceId })}
/>
<DeleteConfirmationModal
	bind:open={deleteAccountOpen}
	title="Delete Account"
	description="This will permanently delete your account, your workspaces, and all associated infrastructure data. Any active subscriptions will be canceled immediately. This action cannot be undone."
	itemName={currentUser.data?.email}
	requireConfirmation={true}
	onConfirm={() => deleteAccount.mutate({})}
/>

<!-- Passkeys Panel -->
<Card.Root>
	<Card.Header>
		<Card.Title class="flex items-center gap-2 text-lg">
			<KeyRound class="size-5 text-muted-foreground" />
			Passkeys
		</Card.Title>
		<Card.Description>
			Log in securely and quickly using your device's biometrics (Touch ID, Face ID) or a hardware
			security key. No password required.
		</Card.Description>
	</Card.Header>
	<Card.Content>
		{#if passkeys.isSuccess && passkeys.data.length > 0}
			<Item.Group class="border-border bg-transparent">
				{#each passkeys.data || [] as pk (pk.id)}
					<Item.Root variant="muted">
						<Item.Media variant="icon">
							<KeyRound />
						</Item.Media>
						<Item.Content>
							<Rename.Root
								this="span"
								value={pk.name}
								validate={(value) => value.trim().length > 0}
								onSave={(value) => {
									updatePasskey.mutate({ id: pk.id, name: value.trim() });
									passkeys.refetch();
								}}
							/>
							<Item.Description>Added {formatTs(pk.createdAt)}</Item.Description>
						</Item.Content>
						<Item.Actions>
							<Button
								variant="ghost"
								size="sm"
								disabled={editingPasskeyId === pk.id}
								onclick={() => {
									deletePasskeyId = pk.id;
									deletePasskeyOpen = true;
								}}
								class="shrink-0 text-muted-foreground hover:bg-destructive/10 hover:text-destructive"
							>
								<Trash2 />
							</Button>
						</Item.Actions>
					</Item.Root>
				{/each}
			</Item.Group>
		{:else}
			<Empty.Root class="bg-muted/50">
				<Empty.Header>
					<Empty.Media variant="icon">
						<KeyRound />
					</Empty.Media>
					<Empty.Title>No passkeys configured</Empty.Title>
					<Empty.Description>Add a passkey for secure, passwordless login.</Empty.Description>
				</Empty.Header>
			</Empty.Root>
		{/if}
	</Card.Content>

	<Card.Footer class="flex items-center justify-between">
		<p class="text-sm text-muted-foreground">Passkeys are the most secure way to sign in.</p>
		<Button size="sm" onclick={handleRegisterPasskey} disabled={isRegisteringPasskey}>
			{#if isRegisteringPasskey}
				<LoaderCircle class="animate-spin" /> Adding...
			{:else}
				Add Passkey
			{/if}
		</Button>
	</Card.Footer>
</Card.Root>

<!-- Password Panel -->
<Card.Root>
	<Card.Header>
		<Card.Title class="flex items-center gap-2 text-lg">
			<Lock class="size-5 text-muted-foreground" />
			Password
		</Card.Title>
		<Card.Description>
			Protect your account with a strong, unique password. If you add a passkey, you can remove your
			password entirely for enhanced security.
		</Card.Description>
	</Card.Header>
	<Card.Content class="space-y-4">
		<Field.Field>
			<Field.Label for="currentPassword">Current Password</Field.Label>
			<Field.Content>
				<InputGroupVariants
					variant="password"
					bind:value={currentPassword}
					placeholder="Enter your current password"
					inputProps={{ id: 'currentPassword', autocomplete: 'new-password' }}
				/>
			</Field.Content>
		</Field.Field>

		<Field.Field>
			<Field.Label for="newPassword">New Password</Field.Label>
			<Field.Content>
				<InputGroupVariants
					variant="password"
					bind:value={newPassword}
					placeholder="Enter your new password"
					inputProps={{ id: 'new-pw', autocomplete: 'new-password' }}
				/>
				{#if newPassword && passwordStrength.score !== -1}
					<div class="mt-2 space-y-1.5">
						<div class="flex items-center justify-between">
							<span class="text-[10px] tracking-wider text-muted-foreground uppercase">
								Strength
							</span>
							<span
								class="text-[10px] font-medium"
								class:text-destructive={passwordStrength.score < 2}
								class:text-success={passwordStrength.score >= 2}>{passwordStrength.text}</span
							>
						</div>
						<Progress value={(passwordStrength.score + 1) * 25} class="h-1" />
					</div>
				{/if}
			</Field.Content>
		</Field.Field>

		<Field.Field>
			<Field.Label for="confirmPassword">Confirm New Password</Field.Label>
			<Field.Content>
				<InputGroupVariants
					variant="password"
					bind:value={confirmPassword}
					placeholder="Confirm your new password"
					inputProps={{ id: 'confirm-pw', autocomplete: 'new-password' }}
					class={confirmPassword && !passwordsMatch
						? 'border-destructive focus-within:ring-destructive/20'
						: ''}
				/>
				{#if confirmPassword && !passwordsMatch}
					<p class="mt-1.5 text-xs text-destructive">Passwords do not match</p>
				{/if}
			</Field.Content>
		</Field.Field>
	</Card.Content>

	<Card.Footer class="flex items-center justify-between">
		<p class="text-sm text-muted-foreground">Ensure your new password is secure.</p>
		<div class="flex gap-3">
			<Button
				variant="outline"
				size="sm"
				class="border-orange-500/30 text-orange-600 hover:bg-orange-500/10"
				disabled={!passkeys.isSuccess || passkeys.data.length === 0}
				onclick={() => (deletePasswordOpen = true)}
			>
				Remove Password
			</Button>
			<Button
				size="sm"
				onclick={handlePasswordUpdate}
				disabled={changePassword.isPending ||
					!passwordsMatch ||
					passwordStrength.score < 2 ||
					!currentPassword}
			>
				{#if changePassword.isPending}
					<LoaderCircle class="animate-spin" /> Updating...
				{:else}
					Update Password
				{/if}
			</Button>
		</div>
	</Card.Footer>
</Card.Root>

<!-- Backup Codes Panel -->
<Card.Root>
	<Card.Header>
		<Card.Title class="flex items-center gap-2 text-lg">
			<Binary class="size-5 text-muted-foreground" />
			Account Recovery Codes
		</Card.Title>
		<Card.Description>
			Emergency one-time codes. Use these to access your account if you lose your phone or security
			key. Store them somewhere safe, like a password manager.
		</Card.Description>
	</Card.Header>
	<Card.Content>
		{#if createBackupCodes.isSuccess}
			<div class="grid grid-cols-2 gap-3 sm:grid-cols-4">
				{#each createBackupCodes.data.codes || [] as code (code)}
					<div
						class="rounded-md border bg-muted/30 px-3 py-2.5 text-center font-mono text-sm font-medium tracking-widest select-all"
					>
						{code}
					</div>
				{/each}
			</div>
			<div class="mt-4 rounded-lg border border-amber-500/20 bg-amber-500/5 p-4">
				<div class="flex items-center gap-2 text-amber-600 dark:text-amber-400">
					<TriangleAlert size={16} />
					<p class="text-sm">
						Keep these safe. They will not be shown again. Each code works only once.
					</p>
				</div>
			</div>
		{:else}
			<Empty.Root class="bg-muted/50">
				<Empty.Header>
					<Empty.Media variant="icon">
						<Binary />
					</Empty.Media>
					<Empty.Title>
						{#if backupCodes.isSuccess && backupCodes.data.length > 0}
							{backupCodes.data.length} codes remaining
						{:else}
							No backup codes generated
						{/if}
					</Empty.Title>
					<Empty.Description>
						{#if backupCodes.isSuccess && backupCodes.data.length > 0}
							You have active backup codes. If you lost them, regenerate a new set immediately to
							invalidate the old ones.
						{:else}
							Generate backup codes to ensure you never lose access to your account.
						{/if}
					</Empty.Description>
				</Empty.Header>
				<Empty.Content>
					{#if backupCodes.isSuccess && backupCodes.data.length > 0}
						<Button variant="destructive" size="sm" onclick={() => (deleteBackupCodesOpen = true)}>
							Delete Backup Codes
						</Button>
					{/if}
				</Empty.Content>
			</Empty.Root>
		{/if}
	</Card.Content>

	<Card.Footer class="flex items-center justify-between">
		<p class="text-sm text-muted-foreground">Store your codes in a secure password manager.</p>
		<div class="flex items-center gap-2">
			{#if createBackupCodes.isSuccess}
				<Button
					variant="outline"
					size="sm"
					onclick={() => handleCopyBackupCodes(createBackupCodes.data.codes)}
				>
					<CopyIcon size={14} class="mr-1.5" /> Copy All
				</Button>
				<Button
					variant="default"
					size="sm"
					onclick={() => handleDownloadBackupCodes(createBackupCodes.data.codes)}
				>
					<DownloadIcon size={14} class="mr-1.5" /> Download
				</Button>
			{:else if backupCodes.isSuccess && backupCodes.data.length > 0}
				<Button variant="default" size="sm" onclick={createBackupCodes.mutate}>
					{#if createBackupCodes.isPending}
						<LoaderCircle size={14} class="mr-2 animate-spin" /> Generating...
					{:else}
						Regenerate Codes
					{/if}
				</Button>
			{:else}
				<Button variant="default" size="sm" onclick={createBackupCodes.mutate}>
					{#if createBackupCodes.isPending}
						<LoaderCircle size={14} class="animate-spin" /> Generating...
					{:else}
						Generate Backup Codes
					{/if}
				</Button>
			{/if}
		</div>
	</Card.Footer>
</Card.Root>

<!-- Connected Devices Panel -->
<Card.Root>
	<Card.Header>
		<Card.Title class="flex items-center gap-2 text-lg">
			<MonitorSmartphone class="size-5 text-muted-foreground" />
			Connected Devices
		</Card.Title>
		<Card.Description>
			Manage laptops, workstations currently authorized to access your account.
		</Card.Description>
	</Card.Header>

	<Card.Content>
		{#if listDevices.isLoading}
			<div class="flex items-center justify-center py-6 text-muted-foreground">
				<Spinner class="mr-2 size-4" /> Loading devices...
			</div>
		{:else if listDevices.isError}
			<div class="flex items-center justify-center py-6 text-destructive">
				Failed to load devices.
			</div>
		{:else if !listDevices.data || listDevices.data.length === 0}
			<Empty.Root class="bg-muted/50">
				<Empty.Header>
					<Empty.Media variant="icon">
						<Terminal />
					</Empty.Media>
					<Empty.Title>No connected devices</Empty.Title>
					<Empty.Description>
						No browsers or CLI applications are connected to your account yet.
					</Empty.Description>
				</Empty.Header>
			</Empty.Root>
		{:else}
			<Item.Group class="border-border bg-transparent">
				{#each listDevices.data as device (device.id)}
					<Item.Root variant="muted">
						<Item.Media variant="icon">
							{#if device.kind === 'web'}
								<Globe />
							{:else}
								<Terminal />
							{/if}
						</Item.Media>
						<Item.Content>
							<Item.Title>
								{device.name}
								<CopyButton text={device.id} icon={false} class="p-0 hover:bg-transparent">
									<CopyIcon size={12} class="text-muted-foreground" title="Device ID" />
								</CopyButton>
							</Item.Title>
							<Item.Description>
								<div class="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
									<span class="flex items-center gap-1">
										<MonitorSmartphone size={12} />
										{device.kind === 'web' ? 'Browser' : 'CLI'}
									</span>
									{#if device.lastUsedAt}
										<span class="flex items-center gap-1">
											<Clock size={12} />
											Last active: {formatTs(device.lastUsedAt, 'relative')}
										</span>
									{/if}
								</div>
							</Item.Description>
						</Item.Content>
						<Item.Actions>
							<Button
								variant="ghost"
								size="sm"
								disabled={deleteDevice.isPending}
								onclick={() => {
									deleteDeviceId = device.id;
									deleteDeviceOpen = true;
								}}
								class="shrink-0 text-muted-foreground hover:bg-destructive/10 hover:text-destructive"
							>
								{#if deleteDevice.variables?.id === device.id && deleteDevice.isPending}
									<LoaderCircle class="size-4 animate-spin" />
								{:else}
									<Trash2 class="size-4" />
								{/if}
							</Button>
						</Item.Actions>
					</Item.Root>
				{/each}
			</Item.Group>
		{/if}
	</Card.Content>
</Card.Root>

<!-- Email Recovery Panel -->
<Card.Root class="border border-chart-2/20">
	<Card.Header>
		<Card.Title class="flex items-center gap-2 text-lg text-chart-2">
			<MailX class="size-5" />
			Email Recovery
		</Card.Title>
		<Card.Description>
			When enabled, you can reset your password and verify your email via email. Disable this for
			stricter security. You will only be able to log in using your passkeys, password, backup
			codes, or linked OAuth accounts. If you lose access to all of them, your account is
			permanently unrecoverable!
		</Card.Description>
	</Card.Header>

	<Card.Footer class="flex justify-between border-t border-chart-2/20 bg-chart-2/5">
		<div class="space-y-0.5">
			<Label for="email-recovery" class="text-chart-2">Enable email recovery</Label>
			<p class="text-sm text-muted-foreground">Allow password reset and verification emails</p>
		</div>
		<Switch
			id="email-recovery"
			checked={enableEmailRecovery}
			disabled={setEmailRecovery.isPending}
			onCheckedChange={() => setEmailRecovery.mutate({ enable: !enableEmailRecovery })}
		/>
	</Card.Footer>
</Card.Root>

<!-- Danger Zone Panel -->
<Card.Root class="border border-destructive/20">
	<Card.Header>
		<Card.Title class="font-medium text-destructive">Delete Account</Card.Title>
		<Card.Description>
			Permanently delete your account, workspaces, and all associated infrastructure data. This
			action is irreversible and cannot be undone.
		</Card.Description>
	</Card.Header>

	<Card.Footer class="flex justify-between border-t border-destructive/20 bg-destructive/5">
		<p class="text-sm font-medium text-destructive">Proceed with caution.</p>
		<Button
			variant="destructive"
			size="sm"
			onclick={() => (deleteAccountOpen = true)}
			class="w-full sm:w-auto"
		>
			Delete Account
		</Button>
	</Card.Footer>
</Card.Root>
