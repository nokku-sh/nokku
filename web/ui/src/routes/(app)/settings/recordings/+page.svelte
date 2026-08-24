<script lang="ts">
	import { billing } from '$lib/api/billing.svelte';
	import { recordings } from '$lib/api/recordings.svelte';
	import { parseBillingCapabilities } from '$lib/billing-capabilities';
	import * as Card from '$lib/components/ui/card';
	import * as Alert from '$lib/components/ui/alert';
	import { Progress } from '$lib/components/ui/progress';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import { formatBytes } from '$lib/utils';
	import { Database, Lock } from '@lucide/svelte';

	const list = $derived(recordings.list());
	const billingData = $derived(billing.get());
	const capabilities = $derived(parseBillingCapabilities(billingData.data?.metadata));

	const recordingQuota = $derived(capabilities.limit('recordings_storage'));
	const totalBytes = $derived(list.data?.totalBytes ?? 0);
	const hasQuota = $derived(recordingQuota !== undefined && recordingQuota.hard > 0);
</script>

<PageHeader
	icon={Lock}
	title="Session Recordings"
	description="Recordings are streamed by your daemons and encrypted at rest in this instance's storage. They are never stored in plaintext."
/>

<!-- Storage usage -->
<Card.Root>
	<Card.Header>
		<Card.Title class="flex items-center gap-2 text-base">
			<Database size={18} />
			Storage Usage
		</Card.Title>
	</Card.Header>
	<Card.Content class="space-y-3">
		{#if hasQuota}
			<div class="flex items-baseline justify-between">
				<span class="text-sm text-muted-foreground">
					{formatBytes(Number(totalBytes))} of {formatBytes(recordingQuota!.hard)} used
				</span>
				<span class="text-sm font-medium">
					{Math.min(100, Math.round((Number(totalBytes) / recordingQuota!.hard) * 100))}%
				</span>
			</div>
			<Progress value={Math.min(100, (Number(totalBytes) / recordingQuota!.hard) * 100)} />
			{#if Number(totalBytes) >= recordingQuota!.hard}
				<Alert.Root variant="destructive">
					<Alert.Description>
						Storage limit reached. The oldest recordings are deleted automatically to keep new
						recordings flowing. Delete recordings or upgrade your plan to keep them longer.
					</Alert.Description>
				</Alert.Root>
			{/if}
		{:else}
			<p class="text-sm text-muted-foreground">
				{formatBytes(Number(totalBytes))} stored
				{#if recordingQuota === undefined}
					— unlimited on your plan
				{/if}
			</p>
		{/if}
		<p class="text-xs text-muted-foreground">
			Recordings are uploaded by your daemons and stored in this instance's storage.
		</p>
	</Card.Content>
</Card.Root>

<!-- Encryption -->
<Card.Root>
	<Card.Header>
		<Card.Title class="flex items-center gap-2 text-base">
			<Lock size={18} />
			Encryption
		</Card.Title>
	</Card.Header>
	<Card.Content>
		<p class="text-sm text-muted-foreground">
			Each recording is encrypted at rest with this instance's key before it touches object storage,
			so an exfiltrated object store never yields readable session output. Decryption happens
			server-side when a recording is played, sealed in your session. No client-held key is required
			and nothing is unrecoverable if a browser is lost.
		</p>
	</Card.Content>
</Card.Root>
