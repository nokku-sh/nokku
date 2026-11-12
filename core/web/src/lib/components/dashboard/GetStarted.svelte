<script lang="ts">
	import { auth, whenFresh } from '#lib/api/auth.svelte.js';
	import { session } from '#lib/api/session.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import EnrollSheet from '#lib/components/sheets/EnrollSheet.svelte';
	import InviteSheet from '#lib/components/sheets/InviteSheet.svelte';
	import CodeSnippet from '#lib/components/blocks/CodeSnippet.svelte';
	import CopyCommand from '#lib/components/blocks/CopyCommand.svelte';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Item from '#lib/components/ui/item/index.js';
	import * as Tabs from '#lib/components/ui/tabs/index.js';
	import { setupDismissed } from '#lib/store.svelte.js';
	import { nkLoginCommand } from '#lib/utils.js';
	import { Check, Rocket, UserPlus } from '@lucide/svelte';
	import NkLogin from './NkLogin.svelte';

	interface Props {
		workspace: string;
		/** A target or a daemon exists. Until then the card is the whole dashboard. */
		connected: boolean;
		users: number;
	}

	let { workspace, connected, users }: Props = $props();

	const can = user.can();
	const options = auth.options();
	// A CLI session is what nk login leaves behind.
	const sessions = session.list();
	const signedIn = $derived((sessions.data ?? []).some((s) => s.kind === 'cli'));
	const canInvite = $derived(can.admin && !!options.data?.passkey);

	const steps = $derived([
		{ id: 'workspace', title: 'Your workspace is ready', done: true, body: undefined },
		{ id: 'server', title: 'Connect a server', done: connected, body: server },
		{ id: 'terminal', title: 'Sign in from your terminal', done: signedIn, body: terminal },
		{ id: 'team', title: 'Bring your team', done: users > 1, body: team }
	]);
	const left = $derived(steps.filter((s) => !s.done).length);
	const next = $derived(steps.find((s) => !s.done));
	const show = $derived(!connected || (left > 0 && !sessions.isLoading && !setupDismissed.current));

	// With a server connected the dashboard has real things to show, so setup shrinks to its next step.
	let expanded = $state(false);

	let enrollOpen = $state(false);
	let inviteOpen = $state(false);
	const invite = () => whenFresh(() => (inviteOpen = true));
</script>

<EnrollSheet bind:open={enrollOpen} />
<InviteSheet bind:open={inviteOpen} />

{#snippet server()}
	<p class="text-sm text-muted-foreground">
		The daemon is the easy path: it keeps the server in sync and lets you open shells from here. No
		agent allowed? Push the config over plain SSH instead.
	</p>
	<Tabs.Root value="daemon" class="gap-3">
		<Tabs.List>
			<Tabs.Trigger value="daemon">With nokkud</Tabs.Trigger>
			<Tabs.Trigger value="sync">Without a daemon</Tabs.Trigger>
		</Tabs.List>
		<Tabs.Content value="daemon" class="flex flex-col gap-3">
			<ol class="flex list-inside list-decimal flex-col gap-1 text-sm text-muted-foreground">
				<li>Create an enrollment token.</li>
				<li>Install nokkud on the server and run the command below. It asks for the token.</li>
			</ol>
			<CodeSnippet code="sudo nokkud enroll" language="bash" />
			{#if can.admin}
				<Button class="self-start" onclick={() => whenFresh(() => (enrollOpen = true))}>
					<Rocket data-icon="inline-start" />
					Create enrollment token
				</Button>
			{:else}
				<p class="text-sm text-muted-foreground">An admin creates the token for you.</p>
			{/if}
		</Tabs.Content>
		<Tabs.Content value="sync" class="flex flex-col gap-3">
			<p class="text-sm text-muted-foreground">
				From your machine, with root SSH to the server. Once is enough, access changes need no new
				sync.
			</p>
			<CodeSnippet code="nk sync root@your-server" language="bash" />
		</Tabs.Content>
	</Tabs.Root>
{/snippet}

{#snippet terminal()}
	<NkLogin />
{/snippet}

{#snippet team()}
	<p class="text-sm text-muted-foreground">
		Grant access per server account, to people or whole teams.
	</p>
	{#if canInvite}
		<Button variant="outline" class="self-start" onclick={invite}>
			<UserPlus data-icon="inline-start" />
			Invite people
		</Button>
	{:else if can.admin && options.data?.emailConfigured === false}
		<p class="text-sm text-muted-foreground">
			Invitations are mailed, and this server sends no email yet. Set it up, or let people in
			through an identity provider.
		</p>
	{/if}
{/snippet}

{#if show && connected && !expanded && next}
	<Item.Root variant="outline" class="bg-card">
		<Item.Media>
			<Badge variant="success" class="font-mono">{steps.length - left} of {steps.length}</Badge>
		</Item.Media>
		<Item.Content>
			<Item.Title>Next setup step: {next.title.toLowerCase()}</Item.Title>
		</Item.Content>
		<Item.Actions class="flex-wrap">
			{#if next.id === 'terminal'}
				<CopyCommand command={nkLoginCommand()} />
			{:else if next.id === 'team' && canInvite}
				<Button variant="outline" size="sm" onclick={invite}>
					<UserPlus data-icon="inline-start" />
					Invite people
				</Button>
			{/if}
			<Button variant="ghost" size="sm" onclick={() => (expanded = true)}>All steps</Button>
			<Button variant="ghost" size="sm" onclick={() => (setupDismissed.current = true)}>
				Dismiss
			</Button>
		</Item.Actions>
	</Item.Root>
{:else if show}
	<Card.Root>
		<Card.Header>
			<Card.Title>
				<h2 class="text-xl font-semibold tracking-tight">
					{connected ? 'Finish setting up' : 'Connect your first server'}
				</h2>
			</Card.Title>
			<Card.Description>
				{#if connected}
					{left} of {steps.length} steps left.
				{:else}
					Four steps, most of them one command. {workspace} already has its CA, so every login is a short-lived
					certificate from day one.
				{/if}
			</Card.Description>
			{#if connected}
				<Card.Action>
					<Button variant="ghost" size="sm" onclick={() => (expanded = false)}>Show less</Button>
					<Button variant="ghost" size="sm" onclick={() => (setupDismissed.current = true)}>
						Dismiss
					</Button>
				</Card.Action>
			{/if}
		</Card.Header>
		<Card.Content>
			<!-- Done steps fold to their title, so the card shrinks as the setup goes on. -->
			<ol class="flex flex-col gap-6">
				{#each steps as step, i (step.id)}
					<li class="grid grid-cols-[2rem_1fr] gap-4">
						<span
							class={[
								'flex size-8 items-center justify-center rounded-full border font-mono text-sm',
								step.done ? 'border-success bg-success text-success-foreground' : 'bg-background'
							]}
						>
							{#if step.done}<Check class="size-4" aria-hidden="true" />{:else}{i + 1}{/if}
						</span>
						<div class="flex min-w-0 flex-col gap-3 pb-2">
							<h3 class={['pt-1 font-medium', step.done && 'text-muted-foreground line-through']}>
								{#if step.done}<span class="sr-only">Done:</span>{/if}
								{step.title}
							</h3>
							{#if !step.done}{@render step.body?.()}{/if}
						</div>
					</li>
				{/each}
			</ol>
		</Card.Content>
	</Card.Root>
{/if}
