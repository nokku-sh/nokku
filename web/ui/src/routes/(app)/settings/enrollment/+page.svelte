<script lang="ts">
	import { daemon } from '$lib/api/daemons.svelte';
	import { workspace } from '$lib/api/workspaces.svelte';
	import * as Alert from '$lib/components/ui/alert';
	import * as Stepper from '$lib/components/ui/stepper';
	import { Badge } from '$lib/components/ui/badge';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import * as Empty from '$lib/components/ui/empty';
	import * as Item from '$lib/components/ui/item';
	import { Switch } from '$lib/components/ui/switch';
	import InputGroupVariants from '$lib/components/ui/input-group/input-group-variants.svelte';
	import { Label } from '$lib/components/ui/label';
	import Separator from '$lib/components/ui/separator/separator.svelte';
	import { Spinner } from '$lib/components/ui/spinner';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import { formatTs, toDate } from '$lib/utils';
	import {
		Bot,
		ClipboardCheck,
		Clock,
		Download,
		ExternalLink,
		KeyRound,
		LoaderCircle,
		MonitorPlay,
		PartyPopper,
		RefreshCw,
		ShieldCheck,
		Terminal,
		Trash2
	} from '@lucide/svelte';
	import CopyButton from '$lib/components/ui/copy-button/copy-button.svelte';
	import { useDebounce } from 'runed';
	import { Input } from '$lib/components/ui/input';
	import { create } from '@bufbuild/protobuf';
	import { WorkspaceSettingsSchema } from '$lib/gen/nokku/v1/workspace_pb';
	import { durationFromMs } from '@bufbuild/protobuf/wkt';
	import { DaemonConfigSchema } from '$lib/gen/nokku/v1/daemon_pb';

	const ws = $derived(workspace.get());
	const token = daemon.refreshToken();
	const revoke = daemon.revokeToken();

	// A proper protobuf message (not a plain object) so mutations and the
	// transport both work. defaultDaemonConfig is always present, which keeps
	// the bindings below free of undefined-guards.
	let settings = $derived.by(() => {
		const s = create(WorkspaceSettingsSchema, ws.data?.settings);
		if (!s.defaultDaemonConfig) s.defaultDaemonConfig = create(DaemonConfigSchema);
		return s;
	});
	const daemonConfig = $derived(settings.defaultDaemonConfig!);

	let curlCommand = $derived(
		`curl -fsSL https://get.nokku.sh/nokkud | TOKEN=${token.data?.token} sh`
	);
	let cmdCommand = $derived(`nokkud --enroll ${token.data?.token}`);

	const update = workspace.update();
	const set = useDebounce(() => update.mutate({ settings: settings }), 500);
</script>

<PageHeader
	icon={Bot}
	title="Daemon Enrollment"
	description="Manage how new daemons join your workspace"
/>

<!-- Enrollment Settings -->
<Card.Root>
	<Card.Header>
		<Card.Title class="flex items-center gap-2 text-base">
			<ShieldCheck size={18} />
			Enrollment Policy
		</Card.Title>
	</Card.Header>
	<Card.Content>
		<Item.Root variant="outline">
			<Item.Content>
				<Item.Title>Auto-approve new daemons</Item.Title>
				<Item.Description>
					{settings.enrollAutoApprove
						? 'Daemons are automatically approved when they enroll with a valid token.'
						: 'New daemons require manual approval before they can connect.'}
				</Item.Description>
			</Item.Content>
			<Item.Actions>
				<Switch
					checked={settings.enrollAutoApprove}
					onCheckedChange={(v) => {
						settings.enrollAutoApprove = v;
						set();
					}}
				/>
			</Item.Actions>
		</Item.Root>
	</Card.Content>
</Card.Root>

<!-- Default Daemon Configuration -->
<Card.Root>
	<Card.Header>
		<Card.Title class="flex items-center gap-2 text-base">
			<Terminal size={18} />
			Daemon Configuration
		</Card.Title>
		<Card.Description>
			SSH server settings new daemons inherit on enrollment. Existing daemons keep their own
			configuration.
		</Card.Description>
	</Card.Header>
	<Card.Content class="flex flex-col gap-4">
		<Item.Root variant="outline">
			<Item.Content>
				<Item.Title>Session recording</Item.Title>
				<Item.Description>Record every SSH session for later playback.</Item.Description>
			</Item.Content>
			<Item.Actions>
				<Switch
					checked={daemonConfig.recordSessions}
					onCheckedChange={(v) => {
						daemonConfig.recordSessions = v;
						set();
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
					checked={daemonConfig.allowForwarding}
					onCheckedChange={(v) => {
						daemonConfig.allowForwarding = v;
						set();
					}}
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
					checked={daemonConfig.allowAgentForwarding}
					onCheckedChange={(v) => {
						daemonConfig.allowAgentForwarding = v;
						set();
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
					checked={daemonConfig.gatewayPorts}
					onCheckedChange={(v) => {
						daemonConfig.gatewayPorts = v;
						set();
					}}
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
					id="cfg-max-sessions"
					type="number"
					min="0"
					value={daemonConfig.maxSessions}
					oninput={(e) => {
						daemonConfig.maxSessions = Number((e.currentTarget as HTMLInputElement).value);
						set();
					}}
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
					id="cfg-max-conns"
					type="number"
					min="0"
					value={daemonConfig.maxConnections}
					oninput={(e) => {
						daemonConfig.maxConnections = Number((e.currentTarget as HTMLInputElement).value);
						set();
					}}
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
					id="cfg-alive-interval"
					type="number"
					min="0"
					value={daemonConfig.clientAliveInterval?.seconds}
					oninput={(e) => {
						let seconds = Number((e.currentTarget as HTMLInputElement).value);
						daemonConfig.clientAliveInterval = durationFromMs(
							Math.max(0, Math.floor(seconds)) * 1000
						);
						set();
					}}
				/>
			</Item.Actions>
		</Item.Root>
	</Card.Content>
</Card.Root>

<!-- Enrollment Token -->
<Card.Root>
	<Card.Header>
		<Card.Title class="flex items-center gap-2 text-base">
			<KeyRound size={18} />
			Enrollment Token
		</Card.Title>
		<Card.Description>
			Generate a token for daemons to authenticate during enrollment. Tokens are valid for 24 hours.
		</Card.Description>
	</Card.Header>
	<Card.Content>
		{#if token.isIdle}
			<Empty.Root class="border border-dashed">
				<Empty.Header>
					<Empty.Media variant="icon">
						<KeyRound />
					</Empty.Media>
					<Empty.Title>
						{#if ws.data?.enrollExpiresAt && toDate(ws.data.enrollExpiresAt) > new Date()}
							Token expires {formatTs(ws.data.enrollExpiresAt, 'relative')}
						{:else}
							No active enrollment token
						{/if}
					</Empty.Title>
					<Empty.Description>
						Generate a new token to allow daemons to join your workspace
					</Empty.Description>
				</Empty.Header>
				<Empty.Content>
					<div class="flex items-center gap-2">
						<Button size="sm" onclick={token.mutate}>Generate token</Button>
						{#if ws.data?.enrollExpiresAt && toDate(ws.data.enrollExpiresAt) > new Date()}
							<Button
								variant="destructive"
								size="sm"
								onclick={revoke.mutate}
								disabled={revoke.isPending}
							>
								Revoke token
							</Button>
						{/if}
					</div>
				</Empty.Content>
			</Empty.Root>
		{:else if token.isPending}
			<div class="flex items-center justify-center p-8">
				<LoaderCircle class="animate-spin text-muted-foreground" size={24} />
			</div>
		{:else if token.isSuccess}
			<div class="space-y-4">
				<div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
					<InputGroupVariants
						variant="copy-input"
						value={token.data?.token}
						class="flex-1"
						readonly
					/>
					<div class="flex gap-2">
						<Button variant="outline" size="sm" onclick={token.mutate} disabled={token.isPending}>
							<RefreshCw size={14} />
							Regenerate
						</Button>
						<Button
							variant="destructive"
							size="sm"
							onclick={() => {
								revoke.mutate({});
								token.reset();
							}}
							disabled={revoke.isPending}
						>
							{#if revoke.isPending}
								<Spinner />
							{:else}
								<Trash2 size={14} />
							{/if}
							Revoke
						</Button>
					</div>
				</div>

				<Alert.Root
					variant="default"
					class="border-amber-200 bg-amber-50 dark:border-amber-900 dark:bg-amber-950"
				>
					<Clock size={16} class="text-amber-600 dark:text-amber-400" />
					<Alert.Description class="text-amber-800 dark:text-amber-200">
						This token expires {formatTs(token.data?.expiresAt, 'withTime')}
					</Alert.Description>
				</Alert.Root>
			</div>
		{/if}
	</Card.Content>
</Card.Root>

<!-- Installation Instructions (only shown when token is active) -->
{#if token.isSuccess}
	<Card.Root>
		<Card.Header>
			<Card.Title class="flex items-center gap-2 text-base">
				<Terminal size={18} />
				Install Daemon
			</Card.Title>
			<Card.Description>Run one of these on your target machine</Card.Description>
		</Card.Header>
		<Card.Content class="space-y-6">
			<!-- Quick Install -->
			<div class="space-y-2">
				<div class="flex items-center gap-2">
					<Label class="text-sm font-semibold">Quick install</Label>
					<Badge variant="secondary">Recommended</Badge>
				</div>
				<p class="text-sm text-muted-foreground">
					Downloads, installs, and enrolls the daemon in one step.
				</p>
				<InputGroupVariants variant="code-area" value={curlCommand} truncate={100} readonly />
			</div>

			<div class="grid grid-cols-[1fr_auto_1fr] items-center gap-3">
				<Separator />
				<span class="text-xs text-muted-foreground">OR</span>
				<Separator />
			</div>

			<!-- Manual Install -->
			<div class="space-y-4">
				<div>
					<Label class="text-sm font-semibold">Manual installation</Label>
					<p class="text-sm text-muted-foreground">
						Install step-by-step if you prefer more control.
					</p>
				</div>

				<Stepper.Root>
					<Stepper.Nav orientation="vertical" class="w-full px-4">
						<Stepper.Item>
							<Stepper.Trigger>
								<Stepper.Indicator>
									<Download />
								</Stepper.Indicator>
								<div class="flex flex-col">
									<Stepper.Title>
										<a
											href="https://github.com/nokku-sh/nokkud/releases"
											target="_blank"
											class="font-medium text-primary underline-offset-2 hover:underline"
										>
											Download
											<ExternalLink size={12} class="inline" />
										</a>
									</Stepper.Title>
									<Stepper.Description>
										Place the binary in
										<code class="rounded bg-muted px-1 font-mono text-xs">/usr/local/bin</code>
										and make it executable.
									</Stepper.Description>
								</div>
							</Stepper.Trigger>
							<Stepper.Separator />
						</Stepper.Item>

						<Stepper.Item>
							<Stepper.Trigger>
								<Stepper.Indicator>
									<MonitorPlay />
								</Stepper.Indicator>
								<div class="flex flex-col">
									<Stepper.Title>Enroll</Stepper.Title>
									<Stepper.Description class="flex flex-col">
										<CopyButton text={cmdCommand} class="max-w-sm p-0">
											<span class="truncate text-left font-mono text-sm font-light">
												{cmdCommand}
											</span>
										</CopyButton>
									</Stepper.Description>
								</div>
							</Stepper.Trigger>
							<Stepper.Separator />
						</Stepper.Item>

						<Stepper.Item>
							<Stepper.Trigger>
								<Stepper.Indicator>
									<ClipboardCheck />
								</Stepper.Indicator>
								<div class="flex flex-col">
									<Stepper.Title>Service</Stepper.Title>
									<Stepper.Description class="flex flex-col">
										Create a systemd service to run the daemon in the background.
									</Stepper.Description>
								</div>
							</Stepper.Trigger>
							<Stepper.Separator />
						</Stepper.Item>

						<Stepper.Item>
							<Stepper.Trigger>
								<Stepper.Indicator>
									<PartyPopper />
								</Stepper.Indicator>
								<div class="flex flex-col">
									<Stepper.Title>Done</Stepper.Title>
									<Stepper.Description>
										You are all set! Your daemon will appear in the daemons list.
									</Stepper.Description>
								</div>
							</Stepper.Trigger>

							<Stepper.Separator />
						</Stepper.Item>
					</Stepper.Nav>
				</Stepper.Root>
			</div>
		</Card.Content>
	</Card.Root>
{/if}
