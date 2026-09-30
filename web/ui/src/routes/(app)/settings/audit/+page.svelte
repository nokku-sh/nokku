<script lang="ts">
	import { create } from '@bufbuild/protobuf';
	import { Dices, ScrollText } from '@lucide/svelte';
	import { billing } from '$lib/api/billing.svelte';
	import { workspace } from '$lib/api/workspaces.svelte';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import * as Empty from '$lib/components/ui/empty';
	import * as Field from '$lib/components/ui/field';
	import { Input } from '$lib/components/ui/input';
	import { Skeleton } from '$lib/components/ui/skeleton';
	import { Spinner } from '$lib/components/ui/spinner';
	import PageHeader from '$lib/components/layout/PageHeader.svelte';
	import { UpgradeURL } from '$lib/config';
	import { WorkspaceSettingsSchema } from '$lib/gen/nokku/v1/workspace_pb';

	const ws = workspace.get();
	const plan = billing.get();
	const available = $derived(plan.data?.features?.['audit_streaming'] === true);

	const update = workspace.update();

	let url = $state('');
	let secret = $state('');
	$effect(() => {
		if (ws.data?.settings) {
			url = ws.data.settings.auditWebhookUrl;
			secret = ws.data.settings.auditWebhookSecret;
		}
	});

	function generateSecret() {
		const bytes = crypto.getRandomValues(new Uint8Array(32));
		secret = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
	}

	function save() {
		const settings = create(WorkspaceSettingsSchema, ws.data?.settings);
		settings.auditWebhookUrl = url;
		settings.auditWebhookSecret = secret;
		update.mutate({ workspaceId: ws.data?.id, settings });
	}
</script>

<PageHeader
	title="Audit streaming"
	description="Send this workspace's audit events to your own system as they happen"
/>

{#snippet needsUpgrade()}
	<Empty.Root class="border border-dashed">
		<Empty.Header>
			<Empty.Media variant="icon">
				<ScrollText />
			</Empty.Media>
			<Empty.Title>Available on Enterprise</Empty.Title>
			<Empty.Description>
				Audit streaming posts every audit event to your own endpoint, so your SIEM, data lake, or
				object storage holds the record. Upgrade to Enterprise to stream events as they happen.
			</Empty.Description>
		</Empty.Header>
		<Empty.Content>
			<Button onclick={() => window.open(UpgradeURL, '_blank', 'noopener')}>See plans</Button>
		</Empty.Content>
	</Empty.Root>
{/snippet}

{#if plan.isPending}
	<Skeleton class="h-64 w-full rounded-xl" />
{:else if plan.isError || !plan.data}
	<Empty.Root class="border border-dashed">
		<Empty.Header>
			<Empty.Media variant="icon">
				<ScrollText />
			</Empty.Media>
			<Empty.Title>Could not load your plan</Empty.Title>
			<Empty.Description>
				The plan decides whether streaming is available, so this cannot be shown yet.
			</Empty.Description>
		</Empty.Header>
		<Empty.Content>
			<Button variant="outline" onclick={() => plan.refetch()}>Retry</Button>
		</Empty.Content>
	</Empty.Root>
{:else if !available}
	{@render needsUpgrade()}
{:else}
	<Card.Root class="overflow-hidden rounded-xl border">
		<Card.Header>
			<Card.Title class="flex items-center gap-2 text-base">
				<ScrollText size={18} />
				Webhook destination
			</Card.Title>
			<Card.Description>
				One JSON object per event, POSTed as it is written. A destination that is down is retried
				with backoff, and the audit log in Nokku is the record either way.
			</Card.Description>
		</Card.Header>
		<Card.Content class="flex flex-col gap-6">
			<Field.Group>
				<Field.Field>
					<Field.Label for="audit-url">Endpoint URL</Field.Label>
					<Field.Content>
						<Input id="audit-url" placeholder="https://siem.example.com/nokku" bind:value={url} />
					</Field.Content>
					<Field.Description>
						Leave empty to stop streaming. Only http and https destinations are accepted.
					</Field.Description>
				</Field.Field>

				<Field.Field>
					<Field.Label for="audit-secret">Signing secret</Field.Label>
					<Field.Content>
						<div class="flex items-center gap-2">
							<Input
								id="audit-secret"
								type="password"
								placeholder="Optional"
								class="font-mono"
								bind:value={secret}
							/>
							<Button variant="outline" onclick={generateSecret}>
								<Dices data-icon="inline-start" />
								Generate
							</Button>
						</div>
					</Field.Content>
					<Field.Description>
						Signs each request with HMAC-SHA256. Verify the header as
						<span class="font-mono text-xs">
							sha256=hex(hmac(secret, timestamp + "." + body))
						</span>
						using the <span class="font-mono text-xs">X-Nokku-Timestamp</span> and
						<span class="font-mono text-xs">X-Nokku-Signature</span> headers. Empty sends the payload
						unsigned.
					</Field.Description>
				</Field.Field>
			</Field.Group>

			<div class="flex justify-end">
				<Button onclick={save} disabled={update.isPending}>
					{#if update.isPending}
						<Spinner data-icon="inline-start" />
					{/if}
					Save
				</Button>
			</div>
		</Card.Content>
	</Card.Root>
{/if}
