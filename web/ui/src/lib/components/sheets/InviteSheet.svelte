<script lang="ts">
	import { WorkspaceRole } from '#lib/gen/nokku/v1/access_pb.js';
	import { workspace } from '#lib/api/workspaces.svelte.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import CopyText from '#lib/components/blocks/CopyText.svelte';
	import { TokenKind } from '#lib/gen/nokku/v1/token_pb.js';
	import { roleLabel } from '#lib/roles.js';
	import { formatTs } from '#lib/utils.js';
	import { Link, Mail, UserPlus } from '@lucide/svelte';
	import TokenSheet from './TokenSheet.svelte';

	let { open = $bindable(false) }: { open?: boolean } = $props();

	const ws = workspace.get();

	const inviteUrl = (secret: string) => `${location.origin}/invite?token=${secret}`;

	function mailto(secret: string, role?: WorkspaceRole) {
		const name = ws.data?.name ?? 'our workspace';
		const subject = `Join ${name} on Nokku`;
		const body = `You're invited to ${name} on Nokku${role ? ` as ${roleLabel(role).toLowerCase()}` : ''}.\n\nJoin here: ${inviteUrl(secret)}`;
		return `mailto:?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
	}
</script>

<TokenSheet
	bind:open
	kind={TokenKind.INVITE}
	title="Invite people"
	description="Anyone with the link creates an account with its role until it expires or runs out."
	icon={UserPlus}
	labelPlaceholder="Platform team onboarding"
>
	{#snippet reveal(secret, t)}
		<div class="flex flex-col gap-2 rounded-lg border bg-muted/40 p-3">
			<span class="flex items-center gap-1.5 text-xs text-muted-foreground">
				<Link class="size-3" />
				Invite link
			</span>
			<CopyText value={inviteUrl(secret)} mono class="text-sm" />
			<span class="text-xs text-muted-foreground">
				Joins as {roleLabel(t?.role || WorkspaceRole.MEMBER).toLowerCase()}
				{#if t?.maxUses}· {t.maxUses === 1 ? 'one person' : `up to ${t.maxUses} people`}{/if}
				· {t?.expiresAt ? `expires ${formatTs(t.expiresAt, 'relative')}` : 'never expires'}
			</span>
		</div>
		<Button variant="outline" size="sm" class="self-start" href={mailto(secret, t?.role)}>
			<Mail data-icon="inline-start" />
			Send by email
		</Button>
	{/snippet}
</TokenSheet>
