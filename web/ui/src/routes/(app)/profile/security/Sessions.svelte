<script lang="ts">
	import { describeAgent } from '#lib/agent.js';
	import { session, sessionKindLabel, sessionMethodLabel } from '#lib/api/session.svelte.js';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Item from '#lib/components/ui/item/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { formatTs } from '#lib/utils.js';
	import { LogOut, Monitor, Smartphone, Terminal } from '@lucide/svelte';
	import { confirm } from '#lib/hooks/index.js';

	const sessions = session.list();

	const revokeSession = session.revoke();

	const revokeOthers = session.revokeOthers();

	const otherSessions = $derived((sessions.data ?? []).filter((s) => !s.current));

	const kindIcon = (kind: string) =>
		kind === 'cli' ? Terminal : kind === 'device' ? Smartphone : Monitor;
</script>

<Card.Root>
	<Card.Header>
		<Card.Title>Where you're signed in</Card.Title>
		<Card.Description>Browsers, the nk CLI and remembered devices.</Card.Description>
		{#if otherSessions.length}
			<Card.Action>
				<Button
					size="sm"
					variant="outline"
					disabled={revokeOthers.isPending}
					onclick={() =>
						confirm({
							title: 'Sign out everywhere else?',
							description: `Signs out ${otherSessions.length} ${otherSessions.length === 1 ? 'device' : 'devices'}. You stay signed in here.`,
							confirmText: 'Sign out',
							onConfirm: () => revokeOthers.mutateAsync({ ids: otherSessions.map((s) => s.id) })
						})}
				>
					<LogOut data-icon="inline-start" />
					Sign out everywhere else
				</Button>
			</Card.Action>
		{/if}
	</Card.Header>
	<Card.Content>
		{#if sessions.isLoading}
			<Skeleton class="h-24 w-full" />
		{:else}
			<Item.Group class="divide-y rounded-lg border">
				{#each sessions.data ?? [] as s (s.id)}
					{@const Icon = kindIcon(s.kind)}
					<Item.Root size="sm" class="rounded-none">
						<Item.Media variant="icon"><Icon /></Item.Media>
						<Item.Content>
							<Item.Title class="flex items-center gap-2">
								{s.userAgent ? describeAgent(s.userAgent) : sessionKindLabel(s.kind)}
								{#if s.current}<Badge variant="success">This device</Badge>{/if}
							</Item.Title>
							<Item.Description>
								{sessionKindLabel(s.kind)} · {sessionMethodLabel(s.method)}{s.ip
									? ` · ${s.ip}`
									: ''}
								· active {formatTs(s.lastSeenAt, 'relative', 'unknown')}
							</Item.Description>
						</Item.Content>
						<Item.Actions>
							{#if !s.current}
								<Button
									size="sm"
									variant="ghost"
									onclick={() =>
										confirm({
											title: 'Sign out this device?',
											description: 'It has to sign in again to get back in.',
											confirmText: 'Sign out',
											onConfirm: () => revokeSession.mutateAsync({ id: s.id })
										})}
								>
									Sign out
								</Button>
							{/if}
						</Item.Actions>
					</Item.Root>
				{/each}
			</Item.Group>
		{/if}
	</Card.Content>
</Card.Root>
