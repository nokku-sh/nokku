<script lang="ts">
	import { goto } from '$app/navigation';
	import { daemon as daemonApi } from '$lib/api/daemons.svelte';
	import { target } from '$lib/api/targets.svelte';
	import { user } from '$lib/api/user.svelte';
	import StatusDot from '$lib/components/blocks/StatusDot.svelte';
	import { Badge } from '$lib/components/ui/badge';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import * as Empty from '$lib/components/ui/empty';
	import * as InputGroup from '$lib/components/ui/input-group';
	import * as Kbd from '$lib/components/ui/kbd';
	import { Skeleton } from '$lib/components/ui/skeleton';
	import * as Tooltip from '$lib/components/ui/tooltip';
	import type { Target } from '$lib/gen/nokku/v1/target_pb';
	import { recentTargets } from '$lib/store.svelte';
	import { Search, Server } from '@lucide/svelte';
	import { toast } from 'svelte-sonner';

	let { showAll = false }: { showAll?: boolean } = $props();

	const LIMIT = 9;

	const me = user.self();
	const access = target.access(() => me.data?.id);
	const createSession = daemonApi.createSession();

	let query = $state('');
	let input = $state<HTMLInputElement | null>(null);

	const online = $derived(
		new Set((access.data?.daemons ?? []).filter((d) => d.online).map((d) => d.id))
	);
	const canShell = (t: Target) => !!t.daemonId && online.has(t.daemonId);
	const accounts = (t: Target) => [...new Set((t.principals ?? []).map((p) => p.username))];

	// Recent first, then reachable, then by name.
	const servers = $derived.by(() => {
		const q = query.trim().toLowerCase();
		const recent = recentTargets.current;
		const rank = (t: Target) => {
			const i = recent.indexOf(t.id);
			return i < 0 ? recent.length : i;
		};
		return (access.data?.targets ?? [])
			.filter(
				(t) =>
					!q ||
					t.name.toLowerCase().includes(q) ||
					t.metadata?.hostname?.toLowerCase().includes(q) ||
					accounts(t).some((a) => a.toLowerCase().includes(q))
			)
			.sort(
				(a, b) =>
					rank(a) - rank(b) ||
					Number(canShell(b)) - Number(canShell(a)) ||
					a.name.localeCompare(b.name)
			);
	});
	const visible = $derived(query ? servers : servers.slice(0, LIMIT));

	function remember(id: string) {
		recentTargets.current = [id, ...recentTargets.current.filter((r) => r !== id)].slice(0, 6);
	}

	async function connect(t: Target, username: string) {
		remember(t.id);
		if (canShell(t)) {
			await createSession.mutateAsync({ daemonId: t.daemonId, username });
			await goto('/sessions');
			return;
		}
		await navigator.clipboard.writeText(`ssh ${username}@${t.name}`);
		toast.success('SSH command copied', { description: 'Run nk login first on a new machine.' });
	}

	function onkeydown(e: KeyboardEvent) {
		const typing =
			e.target instanceof HTMLElement &&
			(e.target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName));
		if (e.key === '/' && !typing && !e.metaKey && !e.ctrlKey) {
			e.preventDefault();
			input?.focus();
		}
	}
</script>

<svelte:window {onkeydown} />

<Card.Root class="gap-3">
	<Card.Header>
		<Card.Title>Your servers</Card.Title>
		<Card.Description>Click an account to open a shell, or copy its ssh command.</Card.Description>
		<Card.Action>
			<InputGroup.Root class="w-44 sm:w-56">
				<InputGroup.Input
					bind:ref={input}
					bind:value={query}
					placeholder="Filter"
					aria-label="Filter servers"
				/>
				<InputGroup.Addon><Search /></InputGroup.Addon>
				<InputGroup.Addon align="inline-end"><Kbd.Root>/</Kbd.Root></InputGroup.Addon>
			</InputGroup.Root>
		</Card.Action>
	</Card.Header>
	<Card.Content>
		{#if access.isLoading || me.isLoading}
			<div class="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
				{#each { length: 6 }, i (i)}<Skeleton class="h-24 w-full" />{/each}
			</div>
		{:else if !servers.length}
			<Empty.Root class="border border-dashed">
				<Empty.Header>
					<Empty.Media variant="icon"><Server /></Empty.Media>
					<Empty.Title>{query ? 'No server matches' : 'No servers for you yet'}</Empty.Title>
					<Empty.Description>
						{query ? 'Try a name, host or account.' : 'An admin grants you an account on a target.'}
					</Empty.Description>
				</Empty.Header>
			</Empty.Root>
		{:else}
			<div class="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
				{#each visible as t (t.id)}
					{@const shell = canShell(t)}
					<div
						class="flex min-w-0 flex-col gap-2 rounded-lg border p-3 transition-colors hover:bg-muted/40"
					>
						<div class="flex min-w-0 items-center gap-2">
							<StatusDot tone={shell ? 'success' : 'muted'} live={shell} />
							<span class="truncate font-medium">{t.name}</span>
							{#if !t.daemonId}<Badge variant="muted" class="ml-auto">nk sync</Badge>{/if}
						</div>
						<span class="truncate font-mono text-xs text-muted-foreground">
							{t.metadata?.hostname || t.endpoints[0] || 'no address yet'}
						</span>
						<div class="flex flex-wrap gap-1">
							{#each accounts(t) as username (username)}
								<Tooltip.Root>
									<Tooltip.Trigger>
										{#snippet child({ props })}
											<Button
												{...props}
												size="xs"
												variant="secondary"
												class="font-mono"
												disabled={createSession.isPending}
												onclick={() => connect(t, username)}
											>
												{username}
											</Button>
										{/snippet}
									</Tooltip.Trigger>
									<Tooltip.Content>
										{shell ? 'Open a shell in the browser' : `Copy ssh ${username}@${t.name}`}
									</Tooltip.Content>
								</Tooltip.Root>
							{/each}
						</div>
					</div>
				{/each}
			</div>
			{#if !query && servers.length > LIMIT}
				<p class="mt-3 text-xs text-muted-foreground">
					{servers.length - LIMIT} more, filter to find them{#if showAll}, or
						<a href="/infrastructure/targets" class="text-primary hover:underline"
							>see all targets</a
						>{/if}.
				</p>
			{/if}
		{/if}
	</Card.Content>
</Card.Root>
