<script lang="ts">
	import { auth } from '#lib/api/auth.svelte.js';
	import { session } from '#lib/api/session.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import { util } from '#lib/api/workspaces.svelte.js';
	import EnrollSheet from '#lib/components/sheets/EnrollSheet.svelte';
	import InviteSheet from '#lib/components/sheets/InviteSheet.svelte';
	import CodeSnippet from '#lib/components/blocks/CodeSnippet.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Tabs from '#lib/components/ui/tabs/index.js';
	import { DocsURL } from '#lib/config.js';
	import { setupDismissed } from '#lib/store.svelte.js';
	import { nkLoginCommand } from '#lib/utils.js';
	import { Check, Rocket, UserPlus } from '@lucide/svelte';
	import type { Snippet } from 'svelte';

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

	const info = util.instanceInfo();
	const login = $derived(nkLoginCommand(info.data?.caPin));

	const done = $derived([true, connected, signedIn, users > 1]);
	const left = $derived(done.filter((d) => !d).length);
	const show = $derived(!connected || (left > 0 && !sessions.isLoading && !setupDismissed.current));

	let enrollOpen = $state(false);
	let inviteOpen = $state(false);
</script>

<EnrollSheet bind:open={enrollOpen} />
<InviteSheet bind:open={inviteOpen} />

<!-- Done steps fold to their title, so the card shrinks as the setup goes on. -->
{#snippet step(n: number, title: string, body?: Snippet)}
	{@const ok = done[n - 1]}
	<li class="grid grid-cols-[2rem_1fr] gap-4">
		<span
			class={[
				'flex size-8 items-center justify-center rounded-full border font-mono text-sm',
				ok ? 'border-success bg-success text-success-foreground' : 'bg-background'
			]}
		>
			{#if ok}<Check class="size-4" />{:else}{n}{/if}
		</span>
		<div class="flex min-w-0 flex-col gap-3 pb-2">
			<h3 class={['pt-1 font-medium', ok && 'text-muted-foreground line-through']}>{title}</h3>
			{#if !ok}{@render body?.()}{/if}
		</div>
	</li>
{/snippet}

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
				<Button class="self-start" onclick={() => (enrollOpen = true)}>
					<Rocket data-icon="inline-start" />
					Create enrollment token
				</Button>
			{:else}
				<p class="text-sm text-muted-foreground">An admin creates the token for you.</p>
			{/if}
		</Tabs.Content>
		<Tabs.Content value="sync" class="flex flex-col gap-3">
			<p class="text-sm text-muted-foreground">
				From your machine, with root SSH to the server. Run it again when access changes.
			</p>
			<CodeSnippet code="nk sync root@your-server" language="bash" />
		</Tabs.Content>
	</Tabs.Root>
{/snippet}

{#snippet terminal()}
	<p class="text-sm text-muted-foreground">
		Sign the CLI in once. After that plain <code class="font-mono">ssh</code> just works.
	</p>
	<CodeSnippet code={login} language="bash" />
	<a href={DocsURL} target="_blank" rel="noopener" class="text-sm text-primary hover:underline">
		Install nk
	</a>
{/snippet}

{#snippet team()}
	<p class="text-sm text-muted-foreground">
		Grant access per server account, to people or whole teams.
	</p>
	{#if can.admin && options.data?.magicLink}
		<Button variant="outline" class="self-start" onclick={() => (inviteOpen = true)}>
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

{#if show}
	<Card.Root>
		<Card.Header>
			<span class="spec-label">Getting started</span>
			<Card.Title class="text-2xl font-semibold tracking-tight">
				{connected ? 'Finish setting up' : 'Connect your first server'}
			</Card.Title>
			<Card.Description>
				{#if connected}
					{left} of 4 steps left.
				{:else}
					Four steps, most of them one command. {workspace} already has a default CA, so every login is
					a short-lived certificate from day one.
				{/if}
			</Card.Description>
			{#if connected}
				<Card.Action>
					<Button variant="ghost" size="sm" onclick={() => (setupDismissed.current = true)}>
						Dismiss
					</Button>
				</Card.Action>
			{/if}
		</Card.Header>
		<Card.Content>
			<ol class="flex flex-col gap-6">
				{@render step(1, 'Your workspace is ready')}
				{@render step(2, 'Connect a server', server)}
				{@render step(3, 'Sign in from your terminal', terminal)}
				{@render step(4, 'Bring your team', team)}
			</ol>
		</Card.Content>
	</Card.Root>
{/if}
