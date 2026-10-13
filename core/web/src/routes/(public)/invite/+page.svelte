<script lang="ts">
	import { WorkspaceRole } from '#lib/gen/nokku/v1/access_pb.js';
	import { page } from '$app/state';
	import { auth } from '#lib/api/auth.svelte.js';
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
	import { CircleX, LogIn, Mail, MailCheck, PartyPopper } from '@lucide/svelte';

	const token = page.url.searchParams.get('token') ?? '';
	const invitation = invite.get(token);
	const options = auth.options();
	const accept = invite.accept();

	let name = $state('');
	let email = $state('');

	const valid = $derived(!!name.trim() && email.includes('@'));

	// The account is made by a mailed link. Without mail or under required SSO there is none, so the form is left out.
	const blocked = $derived.by(() => {
		if (!options.data || options.data.magicLink) return undefined;
		if (!options.data.emailConfigured) {
			return {
				title: 'Invitations are off',
				description:
					'This server sends no email, so it cannot create your account. Ask whoever invited you to set up email.'
			};
		}
		return {
			title: 'Sign in with your provider',
			description:
				'This workspace requires single sign-on, so an invitation cannot create an account. Sign in with its identity provider instead.'
		};
	});

	function byEmail(e: SubmitEvent) {
		e.preventDefault();
		accept.mutate({ token, name: name.trim(), email: email.trim() });
	}
</script>

{#if !token || invitation.isError}
	<AuthCard
		title="Invitation unavailable"
		description="This link is expired, used up or invalid. Ask whoever invited you for a new one."
		icon={CircleX}
		tone="destructive"
	>
		<Button href="/login" variant="outline">
			<LogIn data-icon="inline-start" />
			Sign in instead
		</Button>
	</AuthCard>
{:else if invitation.isLoading || options.isLoading}
	<AuthCard title="Checking your invitation" description="One moment">
		<Skeleton class="h-10 w-full" />
		<Skeleton class="h-10 w-full" />
	</AuthCard>
{:else if blocked}
	<AuthCard
		title={blocked.title}
		description={blocked.description}
		icon={CircleX}
		tone="destructive"
	>
		<Button href="/login" variant="outline">
			<LogIn data-icon="inline-start" />
			Go to sign in
		</Button>
	</AuthCard>
{:else if accept.isSuccess}
	<AuthCard
		title="Check your email"
		description={`A link to finish creating your account is on its way to ${email}. It works for 15 minutes and may land in spam.`}
		icon={MailCheck}
		tone="success"
	/>
{:else}
	<AuthCard
		title={`Join ${invitation.data?.workspaceName || 'the workspace'}`}
		description="You were invited, this creates your account"
		icon={PartyPopper}
		wide
	>
		<div class="flex items-center justify-center gap-2 text-xs text-muted-foreground">
			<Badge variant="secondary">{roleLabel(invitation.data?.role || WorkspaceRole.MEMBER)}</Badge>
			{#if invitation.data?.expiresAt}
				<span>Expires {formatTs(invitation.data.expiresAt, 'relative')}</span>
			{/if}
		</div>

		<form class="flex flex-col gap-4" onsubmit={byEmail}>
			<Field.Group class="gap-4">
				<Field.Field>
					<Field.Label for="name">Full name</Field.Label>
					<Input
						id="name"
						autocomplete="name"
						bind:value={name}
						placeholder="Ada Lovelace"
						required
					/>
				</Field.Field>
				<Field.Field>
					<Field.Label for="email">Email</Field.Label>
					<Input
						id="email"
						type="email"
						autocomplete="email"
						bind:value={email}
						placeholder="you@company.com"
						required
					/>
					<Field.Description>
						How your team and the audit log know you. We mail a link that creates your account, and
						you can add a passkey right after.
					</Field.Description>
				</Field.Field>
			</Field.Group>

			<Button type="submit" disabled={!valid || accept.isPending}>
				{#if accept.isPending}<Spinner data-icon="inline-start" />{:else}<Mail
						data-icon="inline-start"
					/>{/if}
				Email me a link
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
