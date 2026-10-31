<script lang="ts">
	import { WorkspaceRole } from '#lib/gen/nokku/v1/access_pb.js';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { invite } from '#lib/api/workspaces.svelte.js';
	import AuthCard from '#lib/components/blocks/AuthCard.svelte';
	import LegalConsent from '#lib/components/blocks/LegalConsent.svelte';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import { roleLabel } from '#lib/roles.js';
	import { formatTs } from '#lib/utils.js';
	import { CircleX, LogIn, PartyPopper, UserPlus } from '@lucide/svelte';

	const token = page.url.searchParams.get('token') ?? '';
	const invitation = invite.get(token);
	const accept = invite.accept();

	let name = $state('');

	// Only the button spends the invite. A mail scanner that opens the link must not.
	function join(e: SubmitEvent) {
		e.preventDefault();
		// A new account has only this session, so it lands where it can add a passkey.
		accept.mutate(
			{ token, name: name.trim() },
			{ onSuccess: () => void goto('/profile/security') }
		);
	}
</script>

{#if accept.isPending || accept.isSuccess}
	<AuthCard title="Creating your account" description="One moment" icon={UserPlus}>
		<Spinner class="size-6 self-center text-primary" />
	</AuthCard>
{:else if !token || invitation.isError}
	<AuthCard
		title="Invitation unavailable"
		description="This link is expired, used or invalid. Ask whoever invited you for a new one."
		icon={CircleX}
		tone="destructive"
	>
		<Button href="/login" variant="outline">
			<LogIn data-icon="inline-start" />
			Sign in instead
		</Button>
	</AuthCard>
{:else if invitation.isLoading}
	<AuthCard title="Checking your invitation" description="One moment">
		<Skeleton class="h-10 w-full" />
		<Skeleton class="h-10 w-full" />
	</AuthCard>
{:else}
	<AuthCard
		title={`Join ${invitation.data?.workspaceName || 'the workspace'}`}
		description={`You were invited as ${invitation.data?.email}`}
		icon={PartyPopper}
		wide
	>
		<div class="flex items-center justify-center gap-2 text-xs text-muted-foreground">
			<Badge variant="secondary">{roleLabel(invitation.data?.role || WorkspaceRole.MEMBER)}</Badge>
			{#if invitation.data?.expiresAt}
				<span>Expires {formatTs(invitation.data.expiresAt, 'relative')}</span>
			{/if}
		</div>

		<form class="flex flex-col gap-4" onsubmit={join}>
			<Field.Field>
				<Field.Label for="name">Full name</Field.Label>
				<Input
					id="name"
					autocomplete="name"
					bind:value={name}
					placeholder="Ada Lovelace"
					required
				/>
				<Field.Description>
					How your team and the audit log know you. You can add a passkey right after.
				</Field.Description>
			</Field.Field>

			<Button type="submit" disabled={!name.trim()}>
				<UserPlus data-icon="inline-start" />
				Join
			</Button>
		</form>

		<LegalConsent lead="By joining," />

		{#snippet footer()}
			Already have an account? <a href="/login" class="font-medium text-primary hover:underline"
				>Sign in</a
			>
		{/snippet}
	</AuthCard>
{/if}
