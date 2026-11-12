<script lang="ts">
	import { whenFresh } from '#lib/api/auth.svelte.js';
	import { serviceAccount as saApi } from '#lib/api/service_account.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import CopyText from '#lib/components/blocks/CopyText.svelte';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import AddFederationModal, {
		GITHUB_ISSUER,
		GITLAB_ISSUER
	} from '#lib/components/modals/AddFederationModal.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import type { ServiceAccountFederation } from '#lib/gen/nokku/v1/service_account_pb.js';
	import { confirm } from '#lib/hooks/index.js';
	import { formatTs } from '#lib/utils.js';
	import { Plus, Trash, Workflow } from '@lucide/svelte';

	let { serviceAccountId, name }: { serviceAccountId: string; name: string } = $props();

	const can = user.can();
	const rules = saApi.federations.list(() => serviceAccountId);
	const ruleList = $derived(rules.data ?? []);
	const remove = saApi.federations.remove();

	let addOpen = $state(false);

	function platform(issuer: string) {
		if (issuer === GITHUB_ISSUER) return 'GitHub Actions';
		if (issuer === GITLAB_ISSUER) return 'GitLab';
		return issuer;
	}

	function askRemove(rule: ServiceAccountFederation) {
		void whenFresh(() => {
			void confirm({
				title: `Remove this ${platform(rule.issuer)} rule?`,
				description:
					'New jobs stop signing in. A session a job already holds runs out within the hour, revoke it under Tokens to end it now.',
				confirmText: 'Remove',
				onConfirm: () => remove.mutateAsync({ serviceAccountId, id: rule.id })
			});
		});
	}
</script>

{#if rules.isLoading}
	<Skeleton class="h-20 w-full rounded-xl" />
{:else if !ruleList.length}
	<Empty.Root class="border border-dashed">
		<Empty.Header>
			<Empty.Media variant="icon"><Workflow /></Empty.Media>
			<Empty.Title>No rules</Empty.Title>
			<Empty.Description>
				A CI job signs in with its platform's own token, so nothing is stored in CI. A rule says
				which jobs may.
			</Empty.Description>
		</Empty.Header>
		{#if can.edit}
			<Empty.Content>
				<Button size="sm" variant="outline" onclick={() => whenFresh(() => (addOpen = true))}>
					<Plus data-icon="inline-start" />
					Add rule
				</Button>
			</Empty.Content>
		{/if}
	</Empty.Root>
{:else}
	<div class="flex items-center justify-between gap-2">
		<p class="min-w-0 text-xs text-muted-foreground">
			In the job, run <CopyText value={`nk login --ci ${name}`} mono />
		</p>
		{#if can.edit}
			<Button size="sm" variant="outline" onclick={() => whenFresh(() => (addOpen = true))}>
				<Plus data-icon="inline-start" />
				New rule
			</Button>
		{/if}
	</div>
	{#each ruleList as rule (rule.id)}
		<div class="flex items-start gap-3 rounded-xl border bg-card p-3">
			<div class="flex min-w-0 flex-1 flex-col gap-2">
				<p class="truncate text-sm font-medium">{platform(rule.issuer)}</p>
				<div class="flex flex-wrap gap-1.5">
					{#each Object.entries(rule.claims) as [claim, value] (claim)}
						<Badge variant="outline" class="font-mono">{claim} = {value}</Badge>
					{/each}
				</div>
				<p class="text-xs text-muted-foreground">Added {formatTs(rule.createdAt, 'relative')}</p>
			</div>
			{#if can.edit}
				<Button
					variant="ghost"
					size="icon-sm"
					aria-label={`Remove the ${platform(rule.issuer)} rule`}
					onclick={() => askRemove(rule)}
				>
					<Trash />
				</Button>
			{/if}
		</div>
	{/each}
{/if}

<AddFederationModal bind:open={addOpen} {serviceAccountId} {name} />
