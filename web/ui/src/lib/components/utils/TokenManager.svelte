<script lang="ts">
	import type { Snippet } from 'svelte';
	import { token } from '$lib/api/tokens.svelte';
	import { roles as rolesApi } from '$lib/api/roles.svelte';
	import { assignableRoles, roleLabel } from '$lib/roles';
	import { TokenKind } from '$lib/gen/nokku/v1/token_pb';
	import { Badge } from '$lib/components/ui/badge';
	import { Button } from '$lib/components/ui/button';
	import * as Field from '$lib/components/ui/field';
	import { Input } from '$lib/components/ui/input';
	import * as Item from '$lib/components/ui/item';
	import * as Select from '$lib/components/ui/select';
	import { Separator } from '$lib/components/ui/separator';
	import { Spinner } from '$lib/components/ui/spinner';
	import { Switch } from '$lib/components/ui/switch';
	import { formatTs } from '$lib/utils';
	import { KeyRound, Trash2 } from '@lucide/svelte';

	interface Props {
		kind: TokenKind;
		/** Renders what to do with a freshly created token. */
		reveal: Snippet<[string]>;
	}
	let { kind, reveal }: Props = $props();

	const expiries = [
		{ value: '3600', label: '1 hour' },
		{ value: '86400', label: '1 day' },
		{ value: '604800', label: '7 days' },
		{ value: '2592000', label: '30 days' },
		{ value: 'never', label: 'Never' }
	];

	const tokens = $derived(token.list(kind));
	const create = token.create();
	const remove = token.remove();
	const rolesQuery = $derived(rolesApi.list());
	const roleOptions = $derived(assignableRoles(rolesQuery.data ?? [], 'users'));

	let label = $state('');
	let expiry = $state('86400');
	let maxUses = $state('');
	let autoApprove = $state(false);
	let role = $state('viewer');

	function submit() {
		create.mutate({
			kind,
			label,
			ttl: expiry === 'never' ? undefined : { seconds: BigInt(expiry) },
			maxUses: maxUses ? Number(maxUses) : undefined,
			autoApprove: kind === TokenKind.ENROLL ? autoApprove : undefined,
			roleName: kind === TokenKind.INVITE ? role : undefined
		});
	}

	function done() {
		create.reset();
		label = '';
		maxUses = '';
	}
</script>

{#if create.isSuccess}
	<div class="space-y-3">
		{@render reveal(create.data.secret)}
		<p class="text-xs text-muted-foreground">
			This is the only time the token is shown. Revoke it below if it leaks.
		</p>
		<Button size="sm" variant="secondary" onclick={done}>Done</Button>
	</div>
{:else}
	<form
		class="space-y-3"
		onsubmit={(e) => {
			e.preventDefault();
			submit();
		}}
	>
		<Field.Field>
			<Field.Label for="token-label">Label</Field.Label>
			<Input id="token-label" placeholder="prod fleet" maxlength={100} bind:value={label} />
		</Field.Field>
		<div class="grid grid-cols-2 gap-3">
			<Field.Field>
				<Field.Label for="token-expiry">Expires after</Field.Label>
				<Select.Root type="single" bind:value={expiry}>
					<Select.Trigger id="token-expiry" class="w-full">
						{expiries.find((e) => e.value === expiry)?.label}
					</Select.Trigger>
					<Select.Content>
						{#each expiries as e (e.value)}
							<Select.Item value={e.value}>{e.label}</Select.Item>
						{/each}
					</Select.Content>
				</Select.Root>
			</Field.Field>
			<Field.Field>
				<Field.Label for="token-uses">Max uses</Field.Label>
				<Input id="token-uses" type="number" min="1" placeholder="Unlimited" bind:value={maxUses} />
			</Field.Field>
		</div>
		{#if kind === TokenKind.ENROLL}
			<Item.Root variant="outline" size="sm">
				<Item.Content>
					<Item.Title>Approve automatically</Item.Title>
					<Item.Description>Daemons join without review.</Item.Description>
				</Item.Content>
				<Item.Actions>
					<Switch bind:checked={autoApprove} aria-label="Approve automatically" />
				</Item.Actions>
			</Item.Root>
		{:else}
			<Field.Field>
				<Field.Label for="token-role">Role</Field.Label>
				<Select.Root type="single" bind:value={role}>
					<Select.Trigger id="token-role" class="w-full">{roleLabel(role)}</Select.Trigger>
					<Select.Content>
						{#each roleOptions as r (r.name)}
							<Select.Item value={r.name}>{roleLabel(r.name)}</Select.Item>
						{/each}
					</Select.Content>
				</Select.Root>
			</Field.Field>
		{/if}
		<Button type="submit" size="sm" disabled={create.isPending}>
			{#if create.isPending}
				<Spinner />
			{:else}
				<KeyRound size={14} />
			{/if}
			Create token
		</Button>
	</form>
{/if}

<Separator />

{#if tokens.isPending}
	<div class="flex justify-center py-4"><Spinner /></div>
{:else if !tokens.data?.tokens.length}
	<p class="text-sm text-muted-foreground">No active tokens.</p>
{:else}
	<div class="space-y-2">
		{#each tokens.data.tokens as t (t.id)}
			<Item.Root variant="outline" size="sm">
				<Item.Content>
					<Item.Title>
						{t.label || 'Untitled'}
						{#if t.autoApprove}<Badge variant="secondary">auto-approve</Badge>{/if}
						{#if t.roleName}<Badge variant="secondary">{roleLabel(t.roleName)}</Badge>{/if}
					</Item.Title>
					<Item.Description>
						{t.uses}{t.maxUses ? ` / ${t.maxUses}` : ''} uses · expires
						{formatTs(t.expiresAt, 'relative', 'never')}
						{#if t.lastUsedAt}· last used {formatTs(t.lastUsedAt, 'relative')}{/if}
					</Item.Description>
				</Item.Content>
				<Item.Actions>
					<Button
						variant="ghost"
						size="icon"
						aria-label="Revoke token"
						disabled={remove.isPending}
						onclick={() => remove.mutate({ id: t.id })}
					>
						<Trash2 size={14} />
					</Button>
				</Item.Actions>
			</Item.Root>
		{/each}
	</div>
{/if}
