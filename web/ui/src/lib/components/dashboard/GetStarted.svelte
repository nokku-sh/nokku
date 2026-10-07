<script lang="ts">
	import EnrollSheet from '#lib/components/sheets/EnrollSheet.svelte';
	import InviteSheet from '#lib/components/sheets/InviteSheet.svelte';
	import CodeSnippet from '#lib/components/blocks/CodeSnippet.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Tabs from '#lib/components/ui/tabs/index.js';
	import { DocsURL } from '#lib/config.js';
	import { Check, Rocket, UserPlus } from '@lucide/svelte';
	import type { Snippet } from 'svelte';

	interface Props {
		workspace: string;
		users: number;
		canEdit: boolean;
	}

	let { workspace, users, canEdit }: Props = $props();

	let enrollOpen = $state(false);
	let inviteOpen = $state(false);
</script>

<EnrollSheet bind:open={enrollOpen} />
<InviteSheet bind:open={inviteOpen} />

{#snippet step(n: number, done: boolean, title: string, body: Snippet)}
	<li class="grid grid-cols-[2rem_1fr] gap-4">
		<span
			class={[
				'flex size-8 items-center justify-center rounded-full border font-mono text-sm',
				done ? 'border-success bg-success text-success-foreground' : 'bg-background'
			]}
		>
			{#if done}<Check class="size-4" />{:else}{n}{/if}
		</span>
		<div class="flex min-w-0 flex-col gap-3 pb-2">
			<h3 class={['font-medium', done && 'text-muted-foreground line-through']}>{title}</h3>
			{@render body()}
		</div>
	</li>
{/snippet}

{#snippet created()}
	<p class="text-sm text-muted-foreground">
		{workspace} comes with a default CA, so every login is a short-lived certificate from day one.
	</p>
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
			{#if canEdit}
				<Button class="self-start" onclick={() => (enrollOpen = true)}>
					<Rocket data-icon="inline-start" />
					Create enrollment token
				</Button>
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
	<CodeSnippet code="nk login" language="bash" />
	<a href={DocsURL} target="_blank" rel="noopener" class="text-sm text-primary hover:underline">
		Install nk
	</a>
{/snippet}

{#snippet team()}
	<p class="text-sm text-muted-foreground">
		Grant access per server account, to people or whole teams.
	</p>
	{#if canEdit}
		<Button variant="outline" class="self-start" onclick={() => (inviteOpen = true)}>
			<UserPlus data-icon="inline-start" />
			Invite people
		</Button>
	{/if}
{/snippet}

<Card.Root>
	<Card.Header>
		<span class="spec-label">Getting started</span>
		<Card.Title class="text-2xl font-semibold tracking-tight">Connect your first server</Card.Title>
		<Card.Description>Four steps, most of them one command.</Card.Description>
	</Card.Header>
	<Card.Content>
		<ol class="flex flex-col gap-6">
			{@render step(1, true, 'Your workspace is ready', created)}
			{@render step(2, false, 'Connect a server', server)}
			{@render step(3, false, 'Sign in from your terminal', terminal)}
			{@render step(4, users > 1, 'Bring your team', team)}
		</ol>
	</Card.Content>
</Card.Root>
