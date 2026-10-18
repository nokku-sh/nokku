<script lang="ts">
	import { auditStreams } from '#lib/api/audit-streams.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import { useFeatures } from '#lib/api/workspaces.svelte.js';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import * as Item from '#lib/components/ui/item/index.js';
	import * as Select from '#lib/components/ui/select/index.js';
	import * as Sheet from '#lib/components/ui/sheet/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import { Switch } from '#lib/components/ui/switch/index.js';
	import { AuditStreamKind, type AuditStream } from '#lib/gen/nokku/v1/audit_stream_pb.js';
	import { confirm } from '#lib/hooks/index.js';
	import PlanBadge from '#lib/components/blocks/PlanBadge.svelte';
	import { formatTs } from '#lib/utils.js';
	import { Radio, Send, Trash2 } from '@lucide/svelte';

	// maxAuditStreams in core.
	const maxStreams = 3;

	let open = $state(false);

	const can = user.can();
	const has = useFeatures();
	const available = $derived(has('audit_streaming'));
	const streams = auditStreams.list();
	const create = auditStreams.create();
	const update = auditStreams.update();
	const remove = auditStreams.remove();
	const test = auditStreams.test();

	const kinds = [
		{
			kind: AuditStreamKind.WEBHOOK,
			label: 'Webhook',
			url: 'https://siem.example.com/nokku',
			secret: 'Signing secret',
			hint: 'Each POST carries X-Nokku-Signature, an HMAC-SHA256 of the timestamp, a dot and the body.'
		},
		{
			kind: AuditStreamKind.SPLUNK,
			label: 'Splunk HEC',
			url: 'https://splunk.example.com:8088/services/collector/event',
			secret: 'HEC token',
			hint: 'Events arrive with sourcetype nokku:audit.'
		},
		{
			kind: AuditStreamKind.DATADOG,
			label: 'Datadog',
			url: 'https://http-intake.logs.datadoghq.eu/api/v2/logs',
			secret: 'API key',
			hint: 'Logs arrive with source nokku. Use the intake of your Datadog site.'
		}
	];
	const label = (k: AuditStreamKind) => kinds.find((x) => x.kind === k)?.label ?? 'Stream';

	let kind = $state(AuditStreamKind.WEBHOOK);
	let url = $state('');
	let secret = $state('');
	const preset = $derived(kinds.find((k) => k.kind === kind)!);
	const valid = $derived(url.startsWith('https://') && secret.length >= 8);

	async function add(e: SubmitEvent) {
		e.preventDefault();
		if (!valid) return;
		await create.mutateAsync({ kind, url, secret });
		url = secret = '';
	}

	function askRemove(s: AuditStream) {
		void confirm({
			title: `Remove the ${label(s.kind)} stream?`,
			description: `Events stop going to ${s.url}. What was sent stays there.`,
			confirmText: 'Remove',
			onConfirm: () => remove.mutateAsync({ id: s.id })
		});
	}

	function status(s: AuditStream) {
		if (!s.enabled) return 'Paused';
		if (s.lastError) return `Failing since ${formatTs(s.failingSince, 'relative')}: ${s.lastError}`;
		if (s.lastSentAt) return `Sent ${formatTs(s.lastSentAt, 'relative')}`;
		return 'Waiting for the first event';
	}
</script>

<Sheet.Root bind:open>
	<Sheet.Trigger>
		{#snippet child({ props })}
			<Button {...props} variant="outline">
				<Radio data-icon="inline-start" />
				Streaming
				{#if streams.data?.some((s) => s.lastError)}<Badge variant="destructive">Failing</Badge
					>{/if}
			</Button>
		{/snippet}
	</Sheet.Trigger>
	<Sheet.Content class="flex w-full flex-col gap-0 sm:max-w-md">
		<Sheet.Header>
			<Sheet.Title class="flex items-center gap-2">
				Streaming
				<PlanBadge feature="audit_streaming" />
			</Sheet.Title>
			<Sheet.Description>
				Sends every audit event to your SIEM within seconds. A destination that is down gets what it
				missed once it is back. A retry can send an event again, its id tells.
			</Sheet.Description>
		</Sheet.Header>

		<div class="flex flex-1 flex-col gap-6 overflow-y-auto px-4 pb-4">
			{#if can.own && available && (streams.data?.length ?? 0) < maxStreams}
				<form class="rounded-xl border p-4" onsubmit={add}>
					<Field.Group>
						<Field.Field>
							<Field.Label for="stream-kind">Destination</Field.Label>
							<Select.Root
								type="single"
								value={String(kind)}
								onValueChange={(v) => (kind = Number(v) as AuditStreamKind)}
							>
								<Select.Trigger id="stream-kind" class="w-full">{preset.label}</Select.Trigger>
								<Select.Content>
									{#each kinds as k (k.kind)}
										<Select.Item value={String(k.kind)}>{k.label}</Select.Item>
									{/each}
								</Select.Content>
							</Select.Root>
							<Field.Description>{preset.hint}</Field.Description>
						</Field.Field>
						<Field.Field>
							<Field.Label for="stream-url">URL</Field.Label>
							<Input id="stream-url" type="url" bind:value={url} placeholder={preset.url} />
						</Field.Field>
						<Field.Field>
							<Field.Label for="stream-secret">{preset.secret}</Field.Label>
							<Input id="stream-secret" type="password" bind:value={secret} autocomplete="off" />
							<Field.Description>Stored encrypted and never shown again.</Field.Description>
						</Field.Field>
						<Button type="submit" disabled={!valid || create.isPending}>
							{#if create.isPending}<Spinner data-icon="inline-start" />{/if}
							Add stream
						</Button>
					</Field.Group>
				</form>
			{/if}

			{#if streams.data?.length}
				<Item.Group class="gap-2">
					{#each streams.data as s (s.id)}
						<Item.Root variant="outline">
							<Item.Content class="min-w-0">
								<Item.Title>{label(s.kind)}</Item.Title>
								<Item.Description class="truncate font-mono text-xs">{s.url}</Item.Description>
								<Item.Description class={s.lastError ? 'text-destructive' : ''}>
									{status(s)}
								</Item.Description>
							</Item.Content>
							{#if can.own}
								<Item.Actions>
									<Switch
										checked={s.enabled}
										aria-label="Send events"
										disabled={update.isPending || (!s.enabled && !available)}
										onCheckedChange={(on) => update.mutate({ id: s.id, enabled: on })}
									/>
									<Button
										variant="ghost"
										size="icon-sm"
										aria-label="Send a test event"
										disabled={!available || test.isPending}
										onclick={() => test.mutate({ id: s.id })}
									>
										<Send />
									</Button>
									<Button
										variant="ghost"
										size="icon-sm"
										aria-label="Remove stream"
										onclick={() => askRemove(s)}
									>
										<Trash2 />
									</Button>
								</Item.Actions>
							{/if}
						</Item.Root>
					{/each}
				</Item.Group>
			{:else if !streams.isLoading}
				<Empty.Root class="border border-dashed">
					<Empty.Header>
						<Empty.Media variant="icon"><Radio /></Empty.Media>
						<Empty.Title>No streams</Empty.Title>
						<Empty.Description>
							{can.own ? 'Add your SIEM above, or export the log by hand.' : 'The owner adds them.'}
						</Empty.Description>
					</Empty.Header>
				</Empty.Root>
			{/if}
		</div>
	</Sheet.Content>
</Sheet.Root>
