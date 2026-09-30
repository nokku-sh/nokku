<script lang="ts">
	import { credentials, passkey, password } from '$lib/api/credential.svelte';
	import { registerPasskey } from '$lib/api/passkey';
	import { user, type LinkedAccount } from '$lib/api/user.svelte';
	import { GitHubIcon, GoogleIcon, OIDCIcon, SAMLIcon } from '$lib/assets';
	import Section from '$lib/components/sheets/Section.svelte';
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
	import * as Tooltip from '$lib/components/ui/tooltip';
	import { formatTs } from '$lib/utils';
	import type { Timestamp } from '@bufbuild/protobuf/wkt';
	import { KeyRound, Link, Lock, Plus, Trash2, Unlink } from '@lucide/svelte';
	import { toast } from 'svelte-sonner';
	import { confirm } from '$lib/hooks';

	const all = credentials.all();

	const passkeys = passkey.list();

	const renamePasskey = passkey.rename();

	const deletePasskey = passkey.delete();

	const linked = user.listLinkedAccounts();

	const unlink = user.unlinkAccount();

	const changePassword = password.update();

	const deletePassword = password.delete();

	const passwordCredential = $derived((all.data ?? []).find((c) => c.type === 'password'));

	const hasPassword = $derived(!!passwordCredential);

	const usage = (added?: Timestamp, used?: Timestamp) =>
		`Added ${formatTs(added, 'relative', 'a while ago')} · ${used ? `last used ${formatTs(used, 'relative')}` : 'not used yet'}`;

	const passkeyCount = $derived(passkeys.data?.length ?? 0);

	// Every way in, used to stop the last one from being removed.
	const methodCount = $derived(passkeyCount + (hasPassword ? 1 : 0) + (linked.data?.length ?? 0));

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
</script>

{#snippet lastWayIn(disabled: boolean)}
	{#if disabled}
		<Tooltip.Content>Your only way in, add another method first.</Tooltip.Content>
	{/if}
{/snippet}

<Card.Root id="sign-in">
	<Card.Header>
		<Card.Title>Ways to sign in</Card.Title>
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
