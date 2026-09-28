<script lang="ts">
	import { roleLabel } from '$lib/roles';
	import { goto } from '$app/navigation';
	import { Button } from '$lib/components/ui/button';
	import * as Dialog from '$lib/components/ui/dialog';
	import { Badge } from '$lib/components/ui/badge';
	import { PartyPopper, CircleX, LoaderCircle, Users, Clock } from '@lucide/svelte';
	import { invite } from '$lib/api/workspaces.svelte';
	import { inviteToken } from '$lib/store.svelte';
	import { formatTs, toDate } from '$lib/utils';

	const invitation = $derived(invite.get());
	const claimInvitation = invite.claim();
	let open = $derived(!!inviteToken.current);

	let expired = $derived.by(() => {
		if (invitation.isSuccess && invitation.data !== undefined) return false;
		return toDate(invitation.data?.expiresAt) < new Date();
	});

	$effect(() => {
		if (!open) clearTokens();
	});

	function handleAccept() {
		claimInvitation.mutate({ token: inviteToken.current });
		clearTokens();
	}

	function clearTokens() {
		// Remove token and redirect to home
		inviteToken.current = '';
		goto('/');
	}
</script>

<Dialog.Root bind:open onOpenChange={(open) => !open && clearTokens()}>
	<Dialog.Content class="max-w-sm">
		{#if invitation.isPending}
			<div class="flex flex-col items-center justify-center gap-4 py-8">
				<LoaderCircle class="h-8 w-8 animate-spin text-muted-foreground" />
				<p class="text-sm text-muted-foreground">Verifying invitation…</p>
			</div>
		{:else if invitation.isError || expired}
			<Dialog.Header class="items-center text-center">
				<div
					class="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-destructive/10"
				>
					<CircleX class="h-6 w-6 text-destructive" />
				</div>
				<Dialog.Title>Invitation Unavailable</Dialog.Title>
				<Dialog.Description>
					This invitation link is expired or invalid. Please ask the workspace owner for a new one.
				</Dialog.Description>
			</Dialog.Header>
			<div class="flex justify-center pt-2">
				<Button variant="outline" onclick={clearTokens}>Go Home</Button>
			</div>
		{:else if invitation.isSuccess}
			<Dialog.Header class="items-center text-center">
				<div class="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
					<PartyPopper class="h-6 w-6 text-primary" />
				</div>
				<Dialog.Title>You're Invited!</Dialog.Title>
				<Dialog.Description>You've been invited to join a workspace</Dialog.Description>
			</Dialog.Header>

			<div class="rounded-lg bg-muted/50 p-4">
				<div class="flex items-center gap-3">
					<div class="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
						<Users class="h-5 w-5 text-primary" />
					</div>
					<div class="flex-1">
						<p class="font-semibold">{invitation.data.workspaceName}</p>
						{#if invitation.data.workspaceDescription}
							<p class="text-xs text-muted-foreground">
								{invitation.data.workspaceDescription}
							</p>
						{/if}
					</div>
					<Badge variant="default">{roleLabel(invitation.data.roleName || 'member')}</Badge>
				</div>
			</div>

			{#if invitation.data.expiresAt}
				<div class="flex items-center justify-center gap-1.5 text-xs text-muted-foreground">
					<Clock class="h-3 w-3" />
					Expires {formatTs(invitation.data.expiresAt, 'relative')}
				</div>
			{/if}

			<div class="flex gap-3 pt-2">
				<Button variant="outline" class="flex-1" onclick={clearTokens}>Decline</Button>
				<Button class="flex-1" onclick={handleAccept} disabled={claimInvitation.isPending}>
					{#if claimInvitation.isPending}
						<LoaderCircle class="h-4 w-4 animate-spin" />
					{/if}
					Join Workspace
				</Button>
			</div>
		{/if}
	</Dialog.Content>
</Dialog.Root>
