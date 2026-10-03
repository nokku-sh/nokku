<script lang="ts">
	import { domain } from '#lib/api/sso.svelte.js';
	import CopyText from '#lib/components/blocks/CopyText.svelte';
	import FormModal from '#lib/components/blocks/FormModal.svelte';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import { confirm } from '#lib/hooks/index.js';
	import { formatTs } from '#lib/utils.js';
	import { CircleCheckBig, Clock, Globe, Plus, RefreshCw, Trash2 } from '@lucide/svelte';

	const domains = domain.list();
	const createDomain = domain.create();
	const verifyDomain = domain.verify();
	const deleteDomain = domain.delete();
	const regenerateToken = domain.regenerate();

	let addOpen = $state(false);
	let newDomain = $state('');

	async function add() {
		await createDomain.mutateAsync({ domain: newDomain.trim() });
		newDomain = '';
	}

	function askRegenerate(name: string) {
		void confirm({
			title: `New token for ${name}?`,
			description: 'The old TXT record stops working, so update your DNS with the new value.',
			confirmText: 'Regenerate',
			destructive: false,
			onConfirm: () => regenerateToken.mutateAsync({ domain: name })
		});
	}

	function askDelete(name: string) {
		void confirm({
			title: `Delete ${name}?`,
			description: 'SSO discovery for this domain stops working.',
			onConfirm: () => deleteDomain.mutateAsync({ domain: name })
		});
	}
</script>

<FormModal
	bind:open={addOpen}
	title="Add a domain"
	description="You prove you own it with a DNS TXT record next."
	icon={Globe}
	onSubmit={add}
	submitLabel="Add domain"
	submitDisabled={!newDomain.trim()}
>
	<Field.Field>
		<Field.Label for="domain">Domain</Field.Label>
		<Input id="domain" bind:value={newDomain} placeholder="company.com" class="font-mono" />
	</Field.Field>
</FormModal>

{#if domains.isLoading}
	<div class="flex flex-col gap-3">
		<Skeleton class="h-24 w-full rounded-xl" />
		<Skeleton class="h-24 w-full rounded-xl" />
	</div>
{:else if !domains.data?.length}
	<Empty.Root class="border border-dashed">
		<Empty.Header>
			<Empty.Media variant="icon"><Globe /></Empty.Media>
			<Empty.Title>No domains yet</Empty.Title>
			<Empty.Description
				>SSO and SCIM only match people whose email domain you own.</Empty.Description
			>
		</Empty.Header>
		<Empty.Content>
			<Button onclick={() => (addOpen = true)}>
				<Plus data-icon="inline-start" />
				Add a domain
			</Button>
		</Empty.Content>
	</Empty.Root>
{:else}
	<div class="flex flex-col gap-3">
		<Button class="self-end" onclick={() => (addOpen = true)}>
			<Plus data-icon="inline-start" />
			Add domain
		</Button>
		{#each domains.data as d (d.domain)}
			<Card.Root>
				<Card.Header>
					<Card.Title class="flex items-center gap-2 font-mono">
						{d.domain}
						{#if d.verifiedAt}
							<Badge variant="success"><CircleCheckBig data-icon="inline-start" />Verified</Badge>
						{:else}
							<Badge variant="warning"><Clock data-icon="inline-start" />Pending</Badge>
						{/if}
					</Card.Title>
					<Card.Description>
						{d.verifiedAt
							? `Verified ${formatTs(d.verifiedAt)}`
							: `Added ${formatTs(d.createdAt)}, waiting for its DNS record`}
					</Card.Description>
					<Card.Action class="flex gap-1">
						{#if !d.verifiedAt}
							<Button
								size="sm"
								variant="outline"
								disabled={verifyDomain.isPending}
								onclick={() => verifyDomain.mutate({ domain: d.domain })}
							>
								{#if verifyDomain.isPending && verifyDomain.variables?.domain === d.domain}
									<Spinner data-icon="inline-start" />
								{:else}
									<CircleCheckBig data-icon="inline-start" />
								{/if}
								Verify
							</Button>
							<Button
								size="icon-sm"
								variant="ghost"
								aria-label="Regenerate verification token"
								onclick={() => askRegenerate(d.domain)}
							>
								<RefreshCw />
							</Button>
						{/if}
						<Button
							size="icon-sm"
							variant="ghost"
							aria-label={`Delete ${d.domain}`}
							onclick={() => askDelete(d.domain)}
						>
							<Trash2 />
						</Button>
					</Card.Action>
				</Card.Header>
				{#if !d.verifiedAt}
					<Card.Content class="flex flex-col gap-3">
						<dl
							class="grid grid-cols-[auto_1fr] items-center gap-x-4 gap-y-2 rounded-lg border bg-muted/40 p-3 text-sm"
						>
							<dt class="spec-label">Type</dt>
							<dd class="font-mono text-xs">TXT</dd>
							<dt class="spec-label">Name</dt>
							<dd class="min-w-0"><CopyText value={`_nokku-verify.${d.domain}`} mono /></dd>
							<dt class="spec-label">Value</dt>
							<dd class="min-w-0"><CopyText value={d.verificationToken} mono /></dd>
						</dl>
						<p class="text-xs text-muted-foreground">
							Some DNS providers, like Cloudflare, add the domain for you. Then the name is just
							<code class="font-mono">_nokku-verify</code>.
						</p>
					</Card.Content>
				{/if}
			</Card.Root>
		{/each}
	</div>
{/if}
