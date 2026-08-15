<script lang="ts">
	import { create } from '@bufbuild/protobuf';
	import { durationFromMs, durationMs } from '@bufbuild/protobuf/wkt';
	import { daemon } from '$lib/api/daemons.svelte';
	import { Badge } from '$lib/components/ui/badge';
	import * as Item from '$lib/components/ui/item';
	import { Input } from '$lib/components/ui/input';
	import { Switch } from '$lib/components/ui/switch';
	import * as Tabs from '$lib/components/ui/tabs';
	import {
		DaemonConfigSchema,
		DaemonStatus,
		type Daemon,
		type DaemonConfig
	} from '$lib/gen/nokku/v1/daemon_pb';
	import { enumLabel, formatTs } from '$lib/utils';
	import { CalendarIcon, ClockIcon, Info, Settings2, Terminal } from '@lucide/svelte';
	import { toast } from 'svelte-sonner';
	import Avatar from '../utils/Avatar.svelte';
	import { CopyButton } from '../ui/copy-button';
	import FormModal from './FormModal.svelte';

	interface Props {
		data: Daemon;
		open?: boolean;
	}
	let { data = $bindable({} as Daemon), open = $bindable(false) }: Props = $props();

	let config = $state<DaemonConfig>(create(DaemonConfigSchema));

	$effect(() => {
		if (data.id) {
			config = data.config ?? create(DaemonConfigSchema);
		}
	});

	const update = daemon.update();
	let isLoading = $derived(update.isPending);

	let aliveSeconds = $derived(
		config.clientAliveInterval ? Math.floor(durationMs(config.clientAliveInterval) / 1000) : 0
	);

	function setAliveInterval(e: Event) {
		const seconds = Number((e.currentTarget as HTMLInputElement).value);
		config.clientAliveInterval = durationFromMs(Math.max(0, Math.floor(seconds)) * 1000);
	}

	async function onSubmit() {
		try {
			await update.mutateAsync({
				workspaceId: data.workspaceId,
				id: data.id,
				...(data.status ? { status: data.status } : {}),
				config: create(DaemonConfigSchema, { ...config })
			});
			toast.success('Daemon configuration saved');
		} catch {
			// The global mutation cache surfaces a descriptive error toast.
		}
	}
</script>

<FormModal
	bind:open
	title={data.name || 'Daemon'}
	description="View daemon details and SSH configuration"
	submitLabel="Save configuration"
	classModal="sm:max-w-125"
	{onSubmit}
	{isLoading}
>
	<Tabs.Root class="w-full">
		<Tabs.List class="mb-4 grid w-full grid-cols-2">
			<Tabs.Trigger value="general">
				<Info />
				General
			</Tabs.Trigger>
			<Tabs.Trigger value="config">
				<Settings2 />
				Configuration
			</Tabs.Trigger>
		</Tabs.List>

		<Tabs.Content value="general" class="space-y-4">
			<Item.Root variant="muted">
				<Item.Media>
					<Avatar id={data.id} />
				</Item.Media>
				<Item.Content>
					<Item.Title class="text-lg">{data.name}</Item.Title>
					<Item.Description class="flex items-center gap-2">
						<Badge variant="secondary" class={data.online ? 'bg-chart-3' : 'bg-destructive'}>
							{data.online ? 'Online' : 'Offline'}
						</Badge>
						{#if data.status}
							<Badge variant="outline">{enumLabel(DaemonStatus[data.status])}</Badge>
						{/if}
					</Item.Description>
				</Item.Content>
				<Item.Actions>
					<CopyButton text={data.id}>Copy ID</CopyButton>
				</Item.Actions>
			</Item.Root>

			<Item.Root variant="muted" size="sm">
				<Item.Content>
					<Item.Title>Version</Item.Title>
				</Item.Content>
				<Item.Actions>
					<Badge variant="default" class="flex items-center gap-1.5 bg-muted-foreground">
						{data.metadata?.version ?? 'Unknown'}
					</Badge>
				</Item.Actions>
			</Item.Root>

			<Item.Root variant="muted" size="sm">
				<Item.Content>
					<Item.Title title={data.metadata?.fingerprint}>Fingerprint</Item.Title>
				</Item.Content>
				<Item.Actions>
					<CopyButton text={data.metadata?.fingerprint ?? ''}>Copy</CopyButton>
				</Item.Actions>
			</Item.Root>

			{#if data.metadata?.host}
				<Item.Root variant="muted" size="sm">
					<Item.Content>
						<Item.Title>Host</Item.Title>
					</Item.Content>
					<Item.Actions>
						<Badge variant="secondary" class="font-mono text-xs">{data.metadata.host}</Badge>
					</Item.Actions>
				</Item.Root>
			{/if}

			{#if data.id}
				<Item.Group class="grid grid-cols-2 gap-2">
					<Item.Root variant="muted">
						<Item.Media variant="icon">
							<CalendarIcon />
						</Item.Media>
						<Item.Content>
							<Item.Title>Created</Item.Title>
							<Item.Description class="font-mono text-xs">
								{formatTs(data.createdAt)}
							</Item.Description>
						</Item.Content>
					</Item.Root>
					<Item.Root variant="muted">
						<Item.Media variant="icon">
							<ClockIcon />
						</Item.Media>
						<Item.Content>
							<Item.Title>Last Updated</Item.Title>
							<Item.Description class="font-mono text-xs">
								{formatTs(data.updatedAt, 'relative')}
							</Item.Description>
						</Item.Content>
					</Item.Root>
				</Item.Group>
			{/if}
		</Tabs.Content>

		<Tabs.Content value="config" class="space-y-4">
			<div
				class="flex items-center gap-2 rounded-lg border bg-muted/50 p-3 text-xs text-muted-foreground"
			>
				<Terminal size={14} class="text-primary" />
				<span>
					These settings are pushed to the daemon on its next sync. Existing sessions keep running.
				</span>
			</div>

			<Item.Root variant="outline">
				<Item.Content>
					<Item.Title>Session recording</Item.Title>
					<Item.Description>Record every SSH session for later playback.</Item.Description>
				</Item.Content>
				<Item.Actions>
					<Switch
						checked={config.recordSessions}
						onCheckedChange={(v) => (config.recordSessions = v)}
					/>
				</Item.Actions>
			</Item.Root>

			<Item.Root variant="outline">
				<Item.Content>
					<Item.Title>Port forwarding</Item.Title>
					<Item.Description>Allow -L, -D and -R port forwards from sessions.</Item.Description>
				</Item.Content>
				<Item.Actions>
					<Switch
						checked={config.allowForwarding}
						onCheckedChange={(v) => (config.allowForwarding = v)}
					/>
				</Item.Actions>
			</Item.Root>

			<Item.Root variant="outline">
				<Item.Content>
					<Item.Title>Agent forwarding</Item.Title>
					<Item.Description
						>Expose the client's ssh-agent to sessions via SSH_AUTH_SOCK.</Item.Description
					>
				</Item.Content>
				<Item.Actions>
					<Switch
						checked={config.allowAgentForwarding}
						onCheckedChange={(v) => (config.allowAgentForwarding = v)}
					/>
				</Item.Actions>
			</Item.Root>

			<Item.Root variant="outline">
				<Item.Content>
					<Item.Title>Gateway ports</Item.Title>
					<Item.Description>
						Allow remote (-R) forwards to bind addresses other than loopback.
					</Item.Description>
				</Item.Content>
				<Item.Actions>
					<Switch
						checked={config.gatewayPorts}
						onCheckedChange={(v) => (config.gatewayPorts = v)}
					/>
				</Item.Actions>
			</Item.Root>

			<Item.Root variant="outline">
				<Item.Content>
					<Item.Title>Max sessions per connection</Item.Title>
					<Item.Description>Limit the number of sessions per connection.</Item.Description>
				</Item.Content>
				<Item.Actions>
					<Input
						type="number"
						min="0"
						class="w-24 text-right"
						value={config.maxSessions}
						oninput={(e) =>
							(config.maxSessions = Number((e.currentTarget as HTMLInputElement).value))}
					/>
				</Item.Actions>
			</Item.Root>

			<Item.Root variant="outline">
				<Item.Content>
					<Item.Title>Max concurrent connections</Item.Title>
					<Item.Description>Limit the number of concurrent connections.</Item.Description>
				</Item.Content>
				<Item.Actions>
					<Input
						type="number"
						min="0"
						class="w-24 text-right"
						value={config.maxConnections}
						oninput={(e) =>
							(config.maxConnections = Number((e.currentTarget as HTMLInputElement).value))}
					/>
				</Item.Actions>
			</Item.Root>

			<Item.Root variant="outline">
				<Item.Content>
					<Item.Title>Client alive interval (seconds)</Item.Title>
					<Item.Description>
						How often the server probes idle clients. Zero disables keepalive probing.
					</Item.Description>
				</Item.Content>
				<Item.Actions>
					<Input
						type="number"
						min="0"
						class="w-24 text-right"
						value={aliveSeconds}
						oninput={setAliveInterval}
					/>
				</Item.Actions>
			</Item.Root>
		</Tabs.Content>
	</Tabs.Root>
</FormModal>
