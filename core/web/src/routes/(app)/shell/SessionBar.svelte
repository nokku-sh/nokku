<script lang="ts">
	import { useConnect, useServers } from '#lib/api/connect.svelte.js';
	import { getSessions } from '#lib/api/terminal.svelte.js';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { activeSessionID } from '#lib/store.svelte.js';
	import { formatTs, toDate } from '#lib/utils.js';
	import { Clock, Copy } from '@lucide/svelte';

	const SOON_MS = 3_600_000;

	const servers = useServers();
	const connect = useConnect();

	const session = $derived(getSessions().get(activeSessionID.current));
	const server = $derived(
		session
			? servers.list.find(
					(t) => t.daemonId === session.daemonID && t.usernames.includes(session.username)
				)
			: undefined
	);
	// Unset when the access is for good.
	const ends = $derived(session && server?.usernameExpiresAt[session.username]);
	const soon = $derived(!!ends && toDate(ends).getTime() - Date.now() < SOON_MS);
</script>

{#if session}
	<div
		class="flex flex-wrap items-center gap-x-4 gap-y-1 border-t px-3 py-1.5 text-xs text-muted-foreground"
	>
		<span class="font-mono text-foreground">{session.username}@{session.daemonName}</span>
		{#if server && servers.records(server)}
			<Badge variant="destructive" title="This server keeps an encrypted recording of the session">
				REC
			</Badge>
		{/if}
		<span>Runs through Nokku, which sees this screen</span>
		{#if ends}
			<span class={['flex items-center gap-1', soon && 'font-medium text-warning']}>
				<Clock class="size-3" />
				Your access ends {formatTs(ends, 'withTime')}, {formatTs(ends, 'relative')}
			</span>
		{/if}
		{#if server}
			<Button
				variant="ghost"
				size="xs"
				class="ml-auto"
				onclick={() => connect.copy(server, session.username)}
			>
				<Copy data-icon="inline-start" />
				Copy the ssh line
			</Button>
		{/if}
	</div>
{/if}
