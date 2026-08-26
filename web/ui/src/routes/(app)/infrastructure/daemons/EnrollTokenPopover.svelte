<script lang="ts">
	import { queryClient } from '$lib/api/client';
	import { daemon } from '$lib/api/daemons.svelte';
	import { workspace } from '$lib/api/workspaces.svelte';
	import * as Popover from '$lib/components/ui/popover';
	import { Button } from '$lib/components/ui/button';
	import InputGroupVariants from '$lib/components/ui/input-group/input-group-variants.svelte';
	import { Spinner } from '$lib/components/ui/spinner';
	import { formatTs, toDate } from '$lib/utils';
	import { WorkspaceService } from '$lib/gen/nokku/v1/workspace_pb';
	import { Clock, KeyRound, RefreshCw, Trash2 } from '@lucide/svelte';

	const ws = $derived(workspace.get());
	const refresh = daemon.refreshToken();
	const revoke = daemon.revokeToken();

	// Token mutations belong to the daemon service, so the global mutation
	// cache never touches workspace queries. Invalidate manually to keep
	// enrollExpiresAt accurate for the "active token" hint below.
	function invalidateWorkspace() {
		void queryClient.invalidateQueries({
			queryKey: ['connect-query', WorkspaceService.typeName]
		});
	}

	const hasActiveToken = $derived(
		!!ws.data?.enrollExpiresAt && toDate(ws.data.enrollExpiresAt) > new Date()
	);

	const curlCommand = $derived(
		`curl -fsSL https://get.nokku.sh/nokkud | TOKEN=${refresh.data?.token} sh`
	);
	const cliCommand = $derived(`nokkud --enroll ${refresh.data?.token}`);

	function generate() {
		refresh.mutate({}, { onSuccess: invalidateWorkspace });
	}

	function revokeCurrent() {
		revoke.mutate(
			{},
			{
				onSuccess: () => {
					refresh.reset();
					invalidateWorkspace();
				}
			}
		);
	}
</script>

{#snippet actionButtons()}
	<Button variant="outline" size="sm" onclick={generate} disabled={refresh.isPending}>
		{#if refresh.isPending}
			<Spinner />
		{:else}
			<RefreshCw size={14} />
		{/if}
		Rotate
	</Button>
	<Button variant="destructive" size="sm" onclick={revokeCurrent} disabled={revoke.isPending}>
		{#if revoke.isPending}
			<Spinner />
		{:else}
			<Trash2 size={14} />
		{/if}
		Revoke
	</Button>
{/snippet}

<Popover.Root>
	<Popover.Trigger>
		{#snippet child({ props })}
			<Button {...props} variant="outline">
				<KeyRound size={16} />
				Enroll daemons
			</Button>
		{/snippet}
	</Popover.Trigger>

	<Popover.Content align="end" class="w-104 space-y-4">
		<Popover.Header>
			<Popover.Title class="text-base">Daemon enrollment</Popover.Title>
			<Popover.Description>
				Tokens let new nokkud installs join this workspace. They expire after 24 hours.
			</Popover.Description>
		</Popover.Header>

		{#if ws.isPending}
			<div class="flex justify-center py-6">
				<Spinner />
			</div>
		{:else if refresh.isSuccess}
			<div class="space-y-3">
				<div class="space-y-1.5">
					<p class="text-xs font-medium text-muted-foreground">Quick install</p>
					<InputGroupVariants variant="code-area" value={curlCommand} truncate={80} readonly />
				</div>
				<div class="space-y-1.5">
					<p class="text-xs font-medium text-muted-foreground">Already installed?</p>
					<InputGroupVariants variant="copy-input" value={cliCommand} readonly />
				</div>
				<div class="flex items-center justify-between">
					<p class="text-xs text-muted-foreground">
						Expires {formatTs(refresh.data?.expiresAt, 'relative')}
					</p>
					<div class="flex gap-2">
						{@render actionButtons()}
					</div>
				</div>
			</div>
		{:else if hasActiveToken}
			<div class="space-y-3">
				<div
					class="flex items-center gap-2 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-200"
				>
					<Clock size={14} class="shrink-0" />
					<span>
						A token is active until {formatTs(ws.data?.enrollExpiresAt, 'relative')}. Rotate it to
						view or replace the value.
					</span>
				</div>
				<div class="flex gap-2">
					{@render actionButtons()}
				</div>
			</div>
		{:else}
			<div class="space-y-3">
				<p class="text-sm text-muted-foreground">
					No active enrollment token. Generate one to deploy your first daemon.
				</p>
				<Button size="sm" onclick={generate} disabled={refresh.isPending}>
					{#if refresh.isPending}
						<Spinner />
					{:else}
						<KeyRound size={14} />
					{/if}
					Generate token
				</Button>
			</div>
		{/if}
	</Popover.Content>
</Popover.Root>
