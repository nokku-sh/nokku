<script lang="ts">
	import { auth } from '#lib/api/auth.svelte.js';
	import { credentials } from '#lib/api/credential.svelte.js';
	import { registerPasskey } from '#lib/api/passkey.js';
	import { OIDCIcon } from '#lib/assets/index.js';
	import Section from '#lib/components/sheets/Section.svelte';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Item from '#lib/components/ui/item/index.js';
	import { Rename } from '#lib/components/ui/rename/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import * as Tooltip from '#lib/components/ui/tooltip/index.js';
	import type { AccountCredential } from '#lib/gen/nokku/v1/account_pb.js';
	import { formatTs } from '#lib/utils.js';
	import type { Timestamp } from '@bufbuild/protobuf/wkt';
	import { KeyRound, Link, Mail, Plus, Trash2, Unlink } from '@lucide/svelte';
	import { toast } from 'svelte-sonner';
	import { confirm } from '#lib/hooks/index.js';

	const all = credentials.all();
	const remove = credentials.remove();
	const rename = credentials.rename();
	const options = auth.options();

	const passkeys = $derived((all.data ?? []).filter((c) => c.type === 'passkey'));
	const linked = $derived((all.data ?? []).filter((c) => c.type === 'oidc'));
	const scim = $derived((all.data ?? []).some((c) => c.type === 'scim'));

	// With email links on, a lost passkey is not a lockout. Otherwise the last
	// method stays.
	const magicLink = $derived(options.data?.magicLink ?? false);
	const lastWay = $derived(!magicLink && passkeys.length + linked.length <= 1);

	const usage = (added?: Timestamp, used?: Timestamp) =>
		`Added ${formatTs(added, 'relative', 'a while ago')} · ${used ? `last used ${formatTs(used, 'relative')}` : 'not used yet'}`;

	const providerName = (c: AccountCredential) =>
		options.data?.providers.find((p) => p.providerId === c.provider)?.name || c.provider;

	// Providers of this workspace the account has not signed in through yet.
	const linkable = $derived(
		(options.data?.providers ?? []).filter((p) => !linked.some((c) => c.provider === p.providerId))
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
			await all.refetch();
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
</script>

{#snippet lastWayIn(disabled: boolean)}
	{#if disabled}
		<Tooltip.Content>Your only way in, add another method first.</Tooltip.Content>
	{/if}
{/snippet}

<Card.Root id="sign-in">
	<Card.Header>
		<Card.Title>Ways to sign in</Card.Title>
		<Card.Description>
			{magicLink
				? 'A link to your email always works. Passkeys are faster and phishing proof.'
				: 'Keep at least two, so losing one device never locks you out.'}
		</Card.Description>
	</Card.Header>
	<Card.Content class="flex flex-col divide-y">
		<Section title="Passkeys" icon={KeyRound} count={passkeys.length}>
			{#snippet action()}
				<Button size="sm" variant="ghost" onclick={addPasskey} disabled={adding}>
					{#if adding}<Spinner data-icon="inline-start" />{:else}<Plus
							data-icon="inline-start"
						/>{/if}
					Add passkey
				</Button>
			{/snippet}
			{#if all.isLoading}
				<Skeleton class="h-12 w-full" />
			{:else if passkeys.length}
				<Item.Group class="divide-y rounded-lg border">
					{#each passkeys as pk (pk.id)}
						<Item.Root size="sm" class="rounded-none">
							<Item.Media variant="icon"><KeyRound /></Item.Media>
							<Item.Content>
								<Item.Title>
									<Rename
										this="span"
										value={pk.label || 'Passkey'}
										class="rounded-sm hover:bg-muted"
										onSave={(label) => rename.mutate({ id: pk.id, label })}
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
													aria-label={`Remove ${pk.label || 'passkey'}`}
													disabled={lastWay}
													onclick={() =>
														confirm({
															title: `Remove ${pk.label || 'this passkey'}?`,
															description: 'You can no longer sign in with it.',
															confirmText: 'Remove',
															onConfirm: () => remove.mutateAsync({ id: pk.id })
														})}
												>
													<Trash2 />
												</Button>
											</span>
										{/snippet}
									</Tooltip.Trigger>
									{@render lastWayIn(lastWay)}
								</Tooltip.Root>
							</Item.Actions>
						</Item.Root>
					{/each}
				</Item.Group>
			{:else}
				<p class="text-sm text-muted-foreground">
					No passkey yet. Use Touch ID, Windows Hello or a security key and skip the email link.
				</p>
			{/if}
		</Section>

		{#if magicLink}
			<Section title="Email link" icon={Mail}>
				<p class="text-sm text-muted-foreground">
					A sign-in link can always be sent to your address. Keep that inbox safe.
				</p>
			</Section>
		{/if}

		{#if linked.length || linkable.length || scim}
			<Section title="Single sign-on" icon={Link} count={linked.length}>
				{#snippet action()}
					{#each linkable as p (p.providerId)}
						<Button
							size="sm"
							variant="ghost"
							href={`/oidc/login?provider=${encodeURIComponent(p.providerId)}&link=true`}
							data-sveltekit-reload
						>
							<OIDCIcon data-icon="inline-start" />
							Link {p.name || p.providerId}
						</Button>
					{/each}
				{/snippet}
				{#if linked.length}
					<Item.Group class="divide-y rounded-lg border">
						{#each linked as a (a.id)}
							<Item.Root size="sm" class="rounded-none">
								<Item.Media variant="icon"><OIDCIcon /></Item.Media>
								<Item.Content>
									<Item.Title>{providerName(a)}</Item.Title>
									<Item.Description>{usage(a.createdAt, a.lastUsedAt)}</Item.Description>
								</Item.Content>
								<Item.Actions>
									<Tooltip.Root>
										<Tooltip.Trigger>
											{#snippet child({ props })}
												<span {...props}>
													<Button
														variant="ghost"
														size="icon-sm"
														aria-label={`Unlink ${providerName(a)}`}
														disabled={lastWay}
														onclick={() =>
															confirm({
																title: `Unlink ${providerName(a)}?`,
																description: 'You can link it again by signing in through it.',
																confirmText: 'Unlink',
																onConfirm: () => remove.mutateAsync({ id: a.id })
															})}
													>
														<Unlink />
													</Button>
												</span>
											{/snippet}
										</Tooltip.Trigger>
										{@render lastWayIn(lastWay)}
									</Tooltip.Root>
								</Item.Actions>
							</Item.Root>
						{/each}
					</Item.Group>
				{:else if scim}
					<p class="flex items-center gap-2 text-sm text-muted-foreground">
						<Badge variant="outline">SCIM</Badge> Your account is managed by your identity provider.
					</p>
				{:else}
					<p class="text-sm text-muted-foreground">
						Sign in through your identity provider once and it shows up here.
					</p>
				{/if}
			</Section>
		{/if}
	</Card.Content>
</Card.Root>
