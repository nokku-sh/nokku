<script lang="ts">
	import { describeAgent } from '$lib/agent';
	import { backupCode, credentials, passkey, password } from '$lib/api/credential.svelte';
	import { registerPasskey } from '$lib/api/passkey';
	import { session, sessionKindLabel, sessionMethodLabel } from '$lib/api/session.svelte';
	import { user, type LinkedAccount } from '$lib/api/user.svelte';
	import { GitHubIcon, GoogleIcon, OIDCIcon, SAMLIcon } from '$lib/assets';
	import Section from '$lib/components/sheets/Section.svelte';
	import * as Alert from '$lib/components/ui/alert';
	import { Badge } from '$lib/components/ui/badge';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import * as Collapsible from '$lib/components/ui/collapsible';
	import * as Field from '$lib/components/ui/field';
	import { InputGroupVariants } from '$lib/components/ui/input-group';
	import * as Item from '$lib/components/ui/item';
	import { Progress } from '$lib/components/ui/progress';
	import { Rename } from '$lib/components/ui/rename';
	import { Skeleton } from '$lib/components/ui/skeleton';
	import { Spinner } from '$lib/components/ui/spinner';
	import { Switch } from '$lib/components/ui/switch';
	import * as Tooltip from '$lib/components/ui/tooltip';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import { AuditOutcome } from '$lib/gen/nokku/v1/util_pb';
	import { formatTs } from '$lib/utils';
	import type { Timestamp } from '@bufbuild/protobuf/wkt';
	import {
		Binary,
		Check,
		CircleAlert,
		Copy,
		Download,
		KeyRound,
		Link,
		Lock,
		LogIn,
		LogOut,
		Mail,
		Monitor,
		MonitorSmartphone,
		Plus,
		ShieldCheck,
		Smartphone,
		Terminal,
		Trash2,
		Unlink
	} from '@lucide/svelte';
	import { toast } from 'svelte-sonner';
	import { confirm } from '$lib/hooks';

	const me = user.self();
	const all = credentials.all();
	const passkeys = passkey.list();
	const renamePasskey = passkey.rename();
	const deletePasskey = passkey.delete();
	const linked = user.listLinkedAccounts();
	const unlink = user.unlinkAccount();
	const changePassword = password.update();
	const deletePassword = password.delete();
	const codes = backupCode.list();
	const createCodes = backupCode.create();
	const deleteCodes = backupCode.delete();
	const sessions = session.list();
	const revokeSession = session.revoke();
	const revokeOthers = session.revokeOthers();
	const setEmailRecovery = user.setEmailRecovery();
	const recentSignIns = user.activity(() => ({
		enabled: !!me.data?.id,
		limit: 5,
		filter: { actions: ['Login', 'LoginDenied'], outcome: AuditOutcome.UNSPECIFIED }
	}));

	const passwordCredential = $derived((all.data ?? []).find((c) => c.type === 'password'));
	const hasPassword = $derived(!!passwordCredential);

	const usage = (added?: Timestamp, used?: Timestamp) =>
		`Added ${formatTs(added, 'relative', 'a while ago')} · ${used ? `last used ${formatTs(used, 'relative')}` : 'not used yet'}`;
	const passkeyCount = $derived(passkeys.data?.length ?? 0);
	const codeCount = $derived(codes.data?.length ?? 0);
	// Every way in, used to stop the last one from being removed.
	const methodCount = $derived(passkeyCount + (hasPassword ? 1 : 0) + (linked.data?.length ?? 0));
	const otherSessions = $derived((sessions.data ?? []).filter((s) => !s.current));
	const emailRecovery = $derived(!me.data?.disablePasswordReset);

	const checks = $derived([
		{
			done: passkeyCount > 0,
			label: 'Add a passkey',
			doneLabel: `${passkeyCount} ${passkeyCount === 1 ? 'passkey' : 'passkeys'}`,
			hint: 'Phishing proof, and faster than a password.',
			href: '#sign-in'
		},
		{
			done: codeCount > 0,
			label: 'Create backup codes',
			doneLabel: `${codeCount} backup codes left`,
			hint: 'Your way back in if you lose every device.',
			href: '#recovery'
		},
		{
			done: !!me.data?.emailVerified,
			label: 'Verify your email',
			doneLabel: 'Email verified',
			hint: 'Needed for password resets and important notices.',
			href: '/profile'
		}
	]);
	const doneCount = $derived(checks.filter((c) => c.done).length);
	const status = $derived(
		doneCount === checks.length
			? { label: 'Strong', variant: 'success' as const }
			: doneCount === checks.length - 1
				? { label: 'Good', variant: 'info' as const }
				: { label: 'Needs attention', variant: 'warning' as const }
	);

	let adding = $state(false);
	async function addPasskey() {
		if (!window.PublicKeyCredential) {
			toast.error('Passkeys not supported', { description: 'Try a current browser.' });
			return;
		}
		adding = true;
		try {
			await registerPasskey();
			toast.success('Passkey added');
			await passkeys.refetch();
		} catch (error) {
			const cancelled = error instanceof DOMException && error.name === 'NotAllowedError';
			const exists = error instanceof DOMException && error.name === 'InvalidStateError';
			toast.error(
				cancelled ? 'Cancelled' : exists ? 'This key is already added' : 'Adding failed',
				{ description: cancelled ? 'The passkey prompt was closed or timed out.' : undefined }
			);
		} finally {
			adding = false;
		}
	}

	let passwordOpen = $state(false);
	let current = $state('');
	let next = $state('');
	let repeat = $state('');
	const strength = $derived.by(() => {
		if (!next) return undefined;
		if (next.length < 8) return { score: 0, text: 'Too short' };
		if (next.length < 12) return { score: 1, text: 'Weak' };
		if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(next)) return { score: 2, text: 'Fair' };
		return { score: 3, text: 'Strong' };
	});
	const canChange = $derived(!!current && next === repeat && (strength?.score ?? 0) >= 2);

	async function submitPassword(e: SubmitEvent) {
		e.preventDefault();
		if (!canChange) return;
		await changePassword.mutateAsync({ currentPassword: current, newPassword: next });
		toast.success('Password changed');
		current = next = repeat = '';
		passwordOpen = false;
	}

	function providerName(a: LinkedAccount) {
		if (a.provider === 'github') return 'GitHub';
		if (a.provider === 'google') return 'Google';
		return a.protocol === 'saml' ? 'SAML' : 'OIDC';
	}
	function providerIcon(a: LinkedAccount) {
		if (a.provider === 'github') return GitHubIcon;
		if (a.provider === 'google') return GoogleIcon;
		return a.protocol === 'saml' ? SAMLIcon : OIDCIcon;
	}
	const linkable = [
		{
			provider: 'google',
			label: 'Google',
			icon: GoogleIcon,
			href: '/oidc/login?provider=google&link=true'
		},
		{
			provider: 'github',
			label: 'GitHub',
			icon: GitHubIcon,
			href: '/oauth/login?provider=github&link=true'
		}
	];

	function download(list: string[]) {
		const content = `Nokku backup codes\nCreated ${new Date().toLocaleString()}\n\nEach code works once.\n\n${list.join('\n')}\n`;
		const url = URL.createObjectURL(new Blob([content], { type: 'text/plain' }));
		const a = document.createElement('a');
		a.href = url;
		a.download = `nokku-backup-codes-${new Date().toISOString().slice(0, 10)}.txt`;
		a.click();
		URL.revokeObjectURL(url);
	}

	const kindIcon = (kind: string) =>
		kind === 'cli' ? Terminal : kind === 'web_device' ? Smartphone : Monitor;
</script>

{#snippet lastWayIn(disabled: boolean)}
	{#if disabled}
		<Tooltip.Content>Your only way in, add another method first.</Tooltip.Content>
	{/if}
{/snippet}

<PageHeader
	title="Security"
	description="How you sign in, how you get back in, and where you are signed in."
	icon={ShieldCheck}
/>

<Card.Root>
	<Card.Header>
		<Card.Title class="flex items-center gap-2 text-base">
			Security checkup
			<Badge variant={status.variant}>{status.label}</Badge>
		</Card.Title>
		<Card.Description>{doneCount} of {checks.length} done.</Card.Description>
		<Card.Action>
			<Progress value={(doneCount / checks.length) * 100} class="h-1.5 w-28" />
		</Card.Action>
	</Card.Header>
	<Card.Content class="grid gap-2 sm:grid-cols-3">
		{#each checks as c (c.label)}
			<a
				href={c.href}
				class={[
					'flex items-start gap-2.5 rounded-lg border p-3 transition-colors hover:bg-muted/40',
					!c.done && 'border-warning/40 bg-warning/5'
				]}
			>
				{#if c.done}
					<Check class="mt-0.5 size-4 shrink-0 text-success" />
				{:else}
					<CircleAlert class="mt-0.5 size-4 shrink-0 text-warning" />
				{/if}
				<span class="flex flex-col">
					<span class="text-sm font-medium">{c.done ? c.doneLabel : c.label}</span>
					<span class="text-xs text-muted-foreground">{c.hint}</span>
				</span>
			</a>
		{/each}
	</Card.Content>
</Card.Root>

<Card.Root id="sign-in">
	<Card.Header>
		<Card.Title class="text-base">Ways to sign in</Card.Title>
		<Card.Description>Keep at least two, so losing one device never locks you out.</Card.Description
		>
	</Card.Header>
	<Card.Content class="flex flex-col divide-y">
		<Section title="Passkeys" icon={KeyRound} count={passkeyCount}>
			{#snippet action()}
				<Button size="sm" variant="ghost" onclick={addPasskey} disabled={adding}>
					{#if adding}<Spinner data-icon="inline-start" />{:else}<Plus
							data-icon="inline-start"
						/>{/if}
					Add passkey
				</Button>
			{/snippet}
			{#if passkeys.isLoading}
				<Skeleton class="h-12 w-full" />
			{:else if passkeyCount}
				<Item.Group class="divide-y rounded-lg border">
					{#each passkeys.data ?? [] as pk (pk.id)}
						<Item.Root size="sm" class="rounded-none">
							<Item.Media variant="icon"><KeyRound /></Item.Media>
							<Item.Content>
								<Item.Title>
									<Rename
										this="span"
										value={pk.name || 'Passkey'}
										class="rounded-sm hover:bg-muted"
										onSave={(name) => renamePasskey.mutate({ id: pk.id, name })}
										validate={(v) => v.trim().length > 0}
									/>
								</Item.Title>
								<Item.Description>{usage(pk.createdAt, pk.lastUsedAt)}</Item.Description>
							</Item.Content>
							<Item.Actions>
								<Tooltip.Root>
									<Tooltip.Trigger>
										{#snippet child({ props })}
											<span {...props}>
												<Button
													variant="ghost"
													size="icon-sm"
													aria-label={`Remove ${pk.name || 'passkey'}`}
													disabled={methodCount <= 1}
													onclick={() =>
														confirm({
															title: `Remove ${pk.name || 'this passkey'}?`,
															description: 'You can no longer sign in with it.',
															confirmText: 'Remove',
															onConfirm: () => deletePasskey.mutateAsync({ id: pk.id })
														})}
												>
													<Trash2 />
												</Button>
											</span>
										{/snippet}
									</Tooltip.Trigger>
									{@render lastWayIn(methodCount <= 1)}
								</Tooltip.Root>
							</Item.Actions>
						</Item.Root>
					{/each}
				</Item.Group>
			{:else}
				<p class="text-sm text-muted-foreground">
					No passkey yet. Use Touch ID, Windows Hello or a security key instead of a password.
				</p>
			{/if}
		</Section>

		<Section title="Password" icon={Lock}>
			<Collapsible.Root bind:open={passwordOpen}>
				<div class="flex items-center justify-between gap-3">
					<p class="text-sm text-muted-foreground">
						{passwordCredential
							? usage(passwordCredential.createdAt, passwordCredential.lastUsedAt)
							: 'No password set.'}
					</p>
					{#if hasPassword}
						<div class="flex gap-1">
							<Collapsible.Trigger>
								{#snippet child({ props })}
									<Button {...props} size="sm" variant="ghost">
										{passwordOpen ? 'Cancel' : 'Change'}
									</Button>
								{/snippet}
							</Collapsible.Trigger>
							<Button
								size="sm"
								variant="ghost"
								disabled={passkeyCount === 0}
								title={passkeyCount === 0 ? 'Add a passkey first' : undefined}
								onclick={() =>
									confirm({
										title: 'Remove your password?',
										description:
											'You will sign in with passkeys only. Make sure they work first, a removed password cannot be recovered.',
										input: { label: 'Current password', type: 'password' },
										confirmText: 'Remove',
										onConfirm: (currentPassword) => deletePassword.mutateAsync({ currentPassword })
									})}
							>
								Remove
							</Button>
						</div>
					{/if}
				</div>
				<Collapsible.Content>
					<form class="mt-3 flex flex-col gap-3 rounded-lg border p-3" onsubmit={submitPassword}>
						<Field.Field>
							<Field.Label for="current-password">Current password</Field.Label>
							<InputGroupVariants
								variant="password"
								bind:value={current}
								inputProps={{ id: 'current-password', autocomplete: 'current-password' }}
							/>
						</Field.Field>
						<div class="grid gap-3 sm:grid-cols-2">
							<Field.Field>
								<Field.Label for="new-password">New password</Field.Label>
								<InputGroupVariants
									variant="password"
									bind:value={next}
									inputProps={{ id: 'new-password', autocomplete: 'new-password' }}
								/>
								{#if strength}
									<div class="flex items-center gap-2">
										<Progress value={(strength.score + 1) * 25} class="h-1 flex-1" />
										<span
											class={['text-xs', strength.score < 2 ? 'text-destructive' : 'text-success']}
										>
											{strength.text}
										</span>
									</div>
								{/if}
							</Field.Field>
							<Field.Field data-invalid={!!repeat && repeat !== next}>
								<Field.Label for="repeat-password">Repeat it</Field.Label>
								<InputGroupVariants
									variant="password"
									bind:value={repeat}
									inputProps={{
										id: 'repeat-password',
										autocomplete: 'new-password',
										'aria-invalid': !!repeat && repeat !== next
									}}
								/>
								{#if repeat && repeat !== next}
									<Field.Description class="text-destructive">Doesn't match.</Field.Description>
								{/if}
							</Field.Field>
						</div>
						<Button
							type="submit"
							size="sm"
							class="self-end"
							disabled={!canChange || changePassword.isPending}
						>
							{#if changePassword.isPending}<Spinner data-icon="inline-start" />{/if}
							Change password
						</Button>
					</form>
				</Collapsible.Content>
			</Collapsible.Root>
		</Section>

		<Section title="Connected accounts" icon={Link} count={linked.data?.length}>
			{#snippet action()}
				{#each linkable.filter((l) => !linked.data?.some((a) => a.provider === l.provider)) as l (l.provider)}
					<Button size="sm" variant="ghost" href={l.href}>
						<l.icon data-icon="inline-start" />
						Link {l.label}
					</Button>
				{/each}
			{/snippet}
			{#if linked.data?.length}
				<Item.Group class="divide-y rounded-lg border">
					{#each linked.data as a (a.provider + a.providerId)}
						{@const Icon = providerIcon(a)}
						{@const managed = a.provider !== 'github' && a.provider !== 'google'}
						<Item.Root size="sm" class="rounded-none">
							<Item.Media variant="icon"><Icon /></Item.Media>
							<Item.Content>
								<Item.Title>{providerName(a)}</Item.Title>
								<Item.Description>
									{usage(a.createdAt, a.lastUsedAt)}
									{#if managed}· managed by your organization's SSO{/if}
								</Item.Description>
							</Item.Content>
							<Item.Actions>
								{#if managed}
									<Badge variant="outline">SSO</Badge>
								{:else}
									<Tooltip.Root>
										<Tooltip.Trigger>
											{#snippet child({ props })}
												<span {...props}>
													<Button
														variant="ghost"
														size="icon-sm"
														aria-label={`Unlink ${providerName(a)}`}
														disabled={methodCount <= 1}
														onclick={() =>
															confirm({
																title: `Unlink ${providerName(a)}?`,
																description: 'You can link it again later.',
																confirmText: 'Unlink',
																onConfirm: () => unlink.mutateAsync({ provider: a.provider })
															})}
													>
														<Unlink />
													</Button>
												</span>
											{/snippet}
										</Tooltip.Trigger>
										{@render lastWayIn(methodCount <= 1)}
									</Tooltip.Root>
								{/if}
							</Item.Actions>
						</Item.Root>
					{/each}
				</Item.Group>
			{:else if !linked.isLoading}
				<p class="text-sm text-muted-foreground">
					Link GitHub or Google to sign in with one click.
				</p>
			{/if}
		</Section>
	</Card.Content>
</Card.Root>

<Card.Root id="recovery">
	<Card.Header>
		<Card.Title class="text-base">Recovery</Card.Title>
		<Card.Description>Your way back in when every device is gone.</Card.Description>
	</Card.Header>
	<Card.Content class="flex flex-col divide-y">
		<Section title="Backup codes" icon={Binary}>
			{#snippet action()}
				<Button
					size="sm"
					variant="ghost"
					disabled={createCodes.isPending}
					onclick={() =>
						codeCount
							? confirm({
									title: 'Create new backup codes?',
									description: 'Your current codes stop working right away.',
									confirmText: 'Create new codes',
									destructive: false,
									onConfirm: () => createCodes.mutateAsync()
								})
							: createCodes.mutate()}
				>
					{#if createCodes.isPending}<Spinner data-icon="inline-start" />{/if}
					{codeCount ? 'Regenerate' : 'Create codes'}
				</Button>
			{/snippet}
			{#if createCodes.isSuccess}
				<Alert.Root variant="warning">
					<Binary />
					<Alert.Title>Save these now, they are shown once</Alert.Title>
					<Alert.Description
						>Each code works one time. Keep them in your password manager.</Alert.Description
					>
				</Alert.Root>
				<div class="grid grid-cols-2 gap-2 sm:grid-cols-4">
					{#each createCodes.data.codes as code (code)}
						<code
							class="rounded-md border bg-muted/40 px-2 py-2 text-center font-mono text-sm tracking-widest select-all"
						>
							{code}
						</code>
					{/each}
				</div>
				<div class="flex gap-2">
					<Button
						size="sm"
						variant="outline"
						onclick={async () => {
							await navigator.clipboard.writeText(createCodes.data.codes.join('\n'));
							toast.success('Codes copied');
						}}
					>
						<Copy data-icon="inline-start" /> Copy
					</Button>
					<Button size="sm" variant="outline" onclick={() => download(createCodes.data.codes)}>
						<Download data-icon="inline-start" /> Download
					</Button>
					<Button size="sm" variant="ghost" onclick={() => createCodes.reset()}>I saved them</Button
					>
				</div>
			{:else}
				<div class="flex items-center justify-between gap-3">
					<p class="text-sm text-muted-foreground">
						{codeCount
							? `${codeCount} codes left. Regenerate if you lost them.`
							: 'No backup codes yet.'}
					</p>
					{#if codeCount}
						<Button
							size="sm"
							variant="ghost"
							onclick={() =>
								confirm({
									title: 'Delete backup codes?',
									description: 'They stop working and can no longer recover your account.',
									onConfirm: () => deleteCodes.mutateAsync({})
								})}
						>
							Delete
						</Button>
					{/if}
				</div>
			{/if}
		</Section>

		<Section title="Email recovery" icon={Mail}>
			<Field.Field orientation="horizontal">
				<Field.Content>
					<Field.Label for="email-recovery">Allow password resets by email</Field.Label>
					<Field.Description>
						Turn it off for stricter security. Then only your passkeys, password, backup codes and
						connected accounts get you in, and losing all of them locks you out for good.
					</Field.Description>
				</Field.Content>
				<Switch
					id="email-recovery"
					checked={emailRecovery}
					disabled={setEmailRecovery.isPending}
					onCheckedChange={(on) =>
						on
							? setEmailRecovery.mutate({ enable: true })
							: confirm({
									title: 'Turn off email recovery?',
									description:
										'Nobody, including support, can reset your password by email anymore. Make sure you have backup codes.',
									confirmText: 'Turn off',
									onConfirm: () => setEmailRecovery.mutateAsync({ enable: false })
								})}
				/>
			</Field.Field>
		</Section>
	</Card.Content>
</Card.Root>

<Card.Root>
	<Card.Header>
		<Card.Title class="text-base">Where you're signed in</Card.Title>
		<Card.Description>Browsers, the nk CLI and remembered devices.</Card.Description>
		{#if otherSessions.length}
			<Card.Action>
				<Button
					size="sm"
					variant="outline"
					disabled={revokeOthers.isPending}
					onclick={() =>
						confirm({
							title: 'Sign out everywhere else?',
							description: `Signs out ${otherSessions.length} ${otherSessions.length === 1 ? 'device' : 'devices'}. You stay signed in here.`,
							confirmText: 'Sign out',
							onConfirm: () => revokeOthers.mutateAsync({ ids: otherSessions.map((s) => s.id) })
						})}
				>
					<LogOut data-icon="inline-start" />
					Sign out everywhere else
				</Button>
			</Card.Action>
		{/if}
	</Card.Header>
	<Card.Content>
		{#if sessions.isLoading}
			<Skeleton class="h-24 w-full" />
		{:else}
			<Item.Group class="divide-y rounded-lg border">
				{#each sessions.data ?? [] as s (s.id)}
					{@const Icon = kindIcon(s.kind)}
					<Item.Root size="sm" class="rounded-none">
						<Item.Media variant="icon"><Icon /></Item.Media>
						<Item.Content>
							<Item.Title class="flex items-center gap-2">
								{s.userAgent ? describeAgent(s.userAgent) : sessionKindLabel(s.kind)}
								{#if s.current}<Badge variant="success">This device</Badge>{/if}
							</Item.Title>
							<Item.Description>
								{sessionKindLabel(s.kind)} · {sessionMethodLabel(s.method)}{s.ip
									? ` · ${s.ip}`
									: ''}
								· active {formatTs(s.lastSeenAt, 'relative', 'unknown')}
							</Item.Description>
						</Item.Content>
						<Item.Actions>
							{#if !s.current}
								<Button
									size="sm"
									variant="ghost"
									disabled={revokeSession.isPending}
									onclick={() => revokeSession.mutate({ id: s.id })}
								>
									Sign out
								</Button>
							{/if}
						</Item.Actions>
					</Item.Root>
				{/each}
			</Item.Group>
		{/if}
	</Card.Content>
</Card.Root>

<Card.Root>
	<Card.Header>
		<Card.Title class="text-base">Recent sign-ins</Card.Title>
		<Card.Description>The last five attempts on your account.</Card.Description>
		<Card.Action>
			<Button size="sm" variant="ghost" href="/profile/activity?view=signins">View all</Button>
		</Card.Action>
	</Card.Header>
	<Card.Content>
		{#if recentSignIns.isLoading}
			<Skeleton class="h-24 w-full" />
		{:else if recentSignIns.data?.logs.length}
			<Item.Group class="divide-y rounded-lg border">
				{#each recentSignIns.data.logs as e (e.id)}
					{@const denied = !e.ok}
					<Item.Root size="sm" class="rounded-none">
						<Item.Media variant="icon" class={denied ? 'text-destructive' : undefined}>
							{#if denied}<CircleAlert />{:else}<LogIn />{/if}
						</Item.Media>
						<Item.Content>
							<Item.Title class="flex items-center gap-2">
								{denied ? 'Sign-in denied' : 'Signed in'}
								{#if typeof e.details?.['method'] === 'string'}
									<Badge variant="secondary"
										>{sessionMethodLabel(e.details['method'] as string)}</Badge
									>
								{/if}
							</Item.Title>
							<Item.Description>
								{describeAgent(e.userAgent)}{e.ip ? ` · ${e.ip}` : ''}
							</Item.Description>
						</Item.Content>
						<Item.Actions class="text-xs text-muted-foreground">
							{formatTs(e.timestamp, 'relative')}
						</Item.Actions>
					</Item.Root>
				{/each}
			</Item.Group>
		{:else}
			<p class="flex items-center gap-2 text-sm text-muted-foreground">
				<MonitorSmartphone class="size-4" /> No sign-ins recorded yet.
			</p>
		{/if}
	</Card.Content>
</Card.Root>
