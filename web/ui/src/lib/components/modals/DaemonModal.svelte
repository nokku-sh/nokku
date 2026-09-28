<script lang="ts">
	import { create } from '@bufbuild/protobuf';
	import { Info, Settings2, Terminal } from '@lucide/svelte';
	import { daemon } from '$lib/api/daemons.svelte';
	import { Badge } from '$lib/components/ui/badge';
	import CopyButton from '$lib/components/ui/copy-button/copy-button.svelte';
	import * as Item from '$lib/components/ui/item';
	import { Switch } from '$lib/components/ui/switch';
	import * as Tabs from '$lib/components/ui/tabs';
	import { DaemonConfigSchema, DaemonStatus, type Daemon } from '$lib/gen/nokku/v1/daemon_pb';
	import { useAutoSave } from '$lib/hooks';
	import { enumLabel, formatTs } from '$lib/utils';
	import Avatar from '../utils/Avatar.svelte';
	import FormModal from './FormModal.svelte';
	import MetaInfo from './MetaInfo.svelte';
	import ModalTabs from './ModalTabs.svelte';

	interface Props {
		draft: Daemon;
		open?: boolean;
	}
	let { draft: model, open = $bindable(false) }: Props = $props();

	const cfg = $derived(model.config ?? create(DaemonConfigSchema));

	const update = daemon.update();
	const autoSave = useAutoSave(() =>
		update.mutateAsync({
			workspaceId: model.workspaceId,
			id: model.id,
			...(model.status ? { status: model.status } : {}),
			config: create(DaemonConfigSchema, { ...cfg })
		})
	);
</script>

<FormModal
	bind:open
	title={model.name || 'Daemon'}
	description="Changes save automatically and sync to the daemon."
	classModal="sm:max-w-125"
	saveState={autoSave.saveState}
>
	<ModalTabs
		tabs={[
			{ value: 'general', label: 'General', icon: Info },
			{ value: 'config', label: 'Configuration', icon: Settings2 }
		]}
	>
		<Tabs.Content value="general" class="space-y-4">
			<Item.Root variant="muted">
				<Item.Media>
					<Avatar id={model.id} />
				</Item.Media>
				<Item.Content>
					<Item.Title class="text-lg">{model.name}</Item.Title>
					<Item.Description class="flex items-center gap-2">
						<Badge variant="secondary" class={model.online ? 'bg-chart-3' : 'bg-destructive'}>
							{model.online ? 'Online' : 'Offline'}
						</Badge>
						{#if model.status}
							<Badge variant="outline">{enumLabel(DaemonStatus[model.status])}</Badge>
						{/if}
						{#if !model.online}
							<span class="text-xs text-muted-foreground">
								{model.lastSeenAt
									? `Last seen ${formatTs(model.lastSeenAt, 'relative')}`
									: 'Never connected'}
							</span>
						{/if}
					</Item.Description>
				</Item.Content>
				<Item.Actions>
					<CopyButton text={model.id}>Copy ID</CopyButton>
				</Item.Actions>
			</Item.Root>

			{#if model.metadata?.version}
				<Item.Root variant="muted" size="sm">
					<Item.Content>
						<Item.Title>Version</Item.Title>
					</Item.Content>
					<Item.Actions>
						<Badge variant="default" class="bg-muted-foreground">
							{model.metadata.version}
						</Badge>
					</Item.Actions>
				</Item.Root>
			{/if}

			{#if model.metadata?.host}
				<Item.Root variant="muted" size="sm">
					<Item.Content>
						<Item.Title>Host</Item.Title>
					</Item.Content>
					<Item.Actions>
						<Badge variant="secondary" class="font-mono text-xs">{model.metadata.host}</Badge>
					</Item.Actions>
				</Item.Root>
			{/if}

			<MetaInfo createdAt={model.createdAt} updatedAt={model.updatedAt} />
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
						checked={cfg.recordSessions}
						onCheckedChange={(v) => {
							cfg.recordSessions = v;
							autoSave.save();
						}}
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
						checked={cfg.allowForwarding}
						onCheckedChange={(v) => {
							cfg.allowForwarding = v;
							autoSave.save();
						}}
					/>
				</Item.Actions>
			</Item.Root>

			<Item.Root variant="outline">
				<Item.Content>
					<Item.Title>Agent forwarding</Item.Title>
					<Item.Description>Expose the client's ssh-agent via SSH_AUTH_SOCK.</Item.Description>
				</Item.Content>
				<Item.Actions>
					<Switch
						checked={cfg.allowAgentForwarding}
						onCheckedChange={(v) => {
							cfg.allowAgentForwarding = v;
							autoSave.save();
						}}
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
						checked={cfg.gatewayPorts}
						onCheckedChange={(v) => {
							cfg.gatewayPorts = v;
							autoSave.save();
						}}
					/>
				</Item.Actions>
			</Item.Root>

			<Item.Root variant="outline">
				<Item.Content>
					<Item.Title>Drop retired CA</Item.Title>
					<Item.Description>
						Stop trusting the previously rotated CA immediately after a rollover.
					</Item.Description>
				</Item.Content>
				<Item.Actions>
					<Switch
						checked={cfg.dropRetiredCa}
						onCheckedChange={(v) => {
							cfg.dropRetiredCa = v;
							autoSave.save();
						}}
					/>
				</Item.Actions>
			</Item.Root>
		</Tabs.Content>
	</ModalTabs>
</FormModal>
