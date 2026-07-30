<script lang="ts">
	import { ca } from '$lib/api/certificates.svelte';
	import { principal } from '$lib/api/principals.svelte';
	import { target } from '$lib/api/targets.svelte';
	import { Badge } from '$lib/components/ui/badge';
	import * as Card from '$lib/components/ui/card';
	import * as Field from '$lib/components/ui/field';
	import { Button } from '$lib/components/ui/button';
	import { CopyButton } from '$lib/components/ui/copy-button';
	import { Input } from '$lib/components/ui/input';
	import * as InputGroup from '$lib/components/ui/input-group/index.js';
	import * as Select from '$lib/components/ui/select';
	import * as Item from '$lib/components/ui/item';
	import { InputGroupVariants } from '$lib/components/ui/input-group';
	import * as Tabs from '$lib/components/ui/tabs';
	import { Textarea } from '$lib/components/ui/textarea';
	import { type Target } from '$lib/gen/nokku/v1/target_pb';
	import {
		CircleUserIcon,
		Globe,
		Info,
		Monitor,
		Plus,
		Server,
		Settings2,
		Terminal,
		Users,
		UsersIcon,
		X
	} from '@lucide/svelte';
	import FormModal from '$lib/components/modals/FormModal.svelte';
	import { formatTs } from '$lib/utils';
	import { CalendarIcon, ClockIcon } from '@lucide/svelte';

	interface Props {
		data: Target;
		open?: boolean;
	}
	let { data = $bindable({} as Target), open = $bindable(false) }: Props = $props();

	let sshPorts = $derived(
		JSON.parse(data.metadata['ssh-ports'] ?? '[]') as Array<{
			port: string;
			listening: boolean;
		}>
	);

	const principalsQuery = $derived(
		data?.id ? principal.list(() => ({ targetId: data.id, limit: 100 })) : undefined
	);

	const caData = $derived(ca.list());

	let defaultCA = $derived(caData.data?.find((ca) => ca.isDefault));
	let newEndpointValue = $state('');

	$effect(() => {
		if (principalsQuery?.data?.principals) {
			data.principals = principalsQuery.data.principals;
		}
	});

	$effect(() => {
		if (defaultCA && !data.id) data.caId = defaultCA.id;
	});

	const createTarget = target.create();
	const updateTarget = target.update();
	const setPrincipals = principal.set();

	async function onSubmit() {
		if (data.id) {
			updateTarget.mutate({ ...data });
		} else {
			createTarget.mutate({ ...data });
		}
		open = false;
	}

	function addEndpoint() {
		const value = newEndpointValue.trim();
		if (!value) return;
		if (data.endpoints?.includes(value)) return;

		data.endpoints = [...(data.endpoints || []), value];
		newEndpointValue = '';
	}

	function removeEndpoint(endpoint: string) {
		data.endpoints = data.endpoints?.filter((e) => e !== endpoint) || [];
	}

	let isLoading = $derived(createTarget.isPending || updateTarget.isPending);

	let userCount = $derived(data.principals?.reduce((acc, p) => acc + p.userIds.length, 0) ?? 0);
	let teamCount = $derived(data.principals?.reduce((acc, p) => acc + p.teamIds.length, 0) ?? 0);
</script>

<FormModal
	bind:open
	title="{data?.id ? 'Edit' : 'Create'} Target"
	description="Configure your target settings"
	submitLabel={data.id ? 'Update' : 'Create'}
	classModal="sm:max-w-[600px]"
	{onSubmit}
	{isLoading}
>
	<Tabs.Root class="w-full">
		<Tabs.List class="mb-4 grid w-full grid-cols-3">
			<Tabs.Trigger value="general">
				<Settings2 />
				General
			</Tabs.Trigger>
			<Tabs.Trigger value="endpoints">
				<Globe />
				Endpoints
			</Tabs.Trigger>
			<Tabs.Trigger value="info">
				<Monitor />
				Info
			</Tabs.Trigger>
		</Tabs.List>

		<Tabs.Content value="general" class="space-y-4">
			<div class="grid grid-cols-6 gap-2">
				<Field.Field class="col-span-4">
					<Field.Label for="name">Name</Field.Label>
					<Field.Content>
						<Input id="name" bind:value={data.name} placeholder="My Target" />
					</Field.Content>
				</Field.Field>

				<Field.Field class="col-span-2">
					<Field.Label for="caId" class="text-sm font-medium">Certificate</Field.Label>
					<Field.Content>
						<Select.Root type="single" bind:value={data.caId}>
							<Select.Trigger class="w-full">
								<span class="truncate">
									{caData.data?.find((c) => c.id === data.caId)?.name || 'Select a certificate'}
								</span>
							</Select.Trigger>
							<Select.Content>
								{#each caData.data || [] as ca (ca.id)}
									<Select.Item value={ca.id}>{ca.name}</Select.Item>
								{/each}
							</Select.Content>
						</Select.Root>
					</Field.Content>
				</Field.Field>
			</div>

			<Field.Field>
				<Field.Label for="description">Description</Field.Label>
				<Field.Content>
					<Textarea
						id="description"
						bind:value={data.description}
						placeholder="My target description"
					/>
				</Field.Content>
			</Field.Field>

			<Field.Field>
				<Field.Label for="principals">Principals</Field.Label>
				<Field.Content>
					<InputGroupVariants
						variant="tags"
						icon={{ tags: Users }}
						tags={data.principals?.map((p) => p.username)}
						onTagChange={(p) => setPrincipals.mutate({ targetId: data.id, usernames: p })}
						placeholder="root, ubuntu, ec2-user, admin"
					/>
				</Field.Content>
			</Field.Field>

			<Field.Field>
				<Field.Label for="tags">Tags</Field.Label>
				<Field.Content>
					<InputGroupVariants
						variant="tags"
						tags={data.tags || []}
						onTagChange={(tags) => (data.tags = tags)}
						placeholder="linux, server, production"
					/>
				</Field.Content>
			</Field.Field>
		</Tabs.Content>

		<Tabs.Content value="endpoints" class="space-y-4">
			{#if data.endpoints?.length}
				<div class="space-y-2">
					{#each data.endpoints as e (e)}
						<Item.Root variant="outline" size="sm">
							<Item.Content>
								<Item.Description class="font-mono">
									<CopyButton text={e} icon={false} class="p-0 hover:bg-transparent">
										<span class="font-mono text-sm font-light">{e}</span>
									</CopyButton>
								</Item.Description>
							</Item.Content>
							<Item.Actions>
								<Button variant="ghost" size="icon-sm" onclick={() => removeEndpoint(e)}>
									<X size={14} />
								</Button>
							</Item.Actions>
						</Item.Root>
					{/each}
				</div>
			{:else}
				<div class="rounded-md border border-dashed p-6 text-center">
					<Globe class="mx-auto mb-2 h-8 w-8 text-muted-foreground" />
					<p class="text-sm text-muted-foreground">No endpoints configured</p>
				</div>
			{/if}

			<div>
				<InputGroup.Root>
					<InputGroup.Input
						bind:value={newEndpointValue}
						placeholder="Add a new endpoint (e.g. 192.168.1.100)"
						onkeydown={(e) => {
							if (e.key === 'Enter') {
								e.preventDefault();
								e.stopPropagation();
								addEndpoint();
							}
						}}
					/>
					<InputGroup.Addon>
						<Globe />
					</InputGroup.Addon>
					<InputGroup.Addon align="inline-end">
						<InputGroup.Button
							variant="secondary"
							size="icon-xs"
							class="h-6 w-6"
							onclick={addEndpoint}
						>
							<Plus />
						</InputGroup.Button>
					</InputGroup.Addon>
				</InputGroup.Root>
			</div>
		</Tabs.Content>

		<Tabs.Content value="info" class="space-y-4">
			{#if data.metadata}
				<Card.Root>
					<Card.Header>
						<Card.Title class="flex items-center gap-2 text-base">
							<Server size={16} />
							System Information
						</Card.Title>
					</Card.Header>
					<Card.Content class="space-y-3">
						{#if data.metadata['host-id']}
							<div class="flex items-center justify-between">
								<span class="text-sm font-medium">Host ID</span>
								<Badge variant="outline" class="font-mono text-xs">
									{data.metadata['host-id']}
								</Badge>
							</div>
						{/if}
						{#if data.metadata.hostname}
							<div class="flex items-center justify-between">
								<span class="text-sm font-medium">Hostname</span>
								<Badge variant="secondary" class="font-mono text-xs">
									{data.metadata.hostname}
								</Badge>
							</div>
						{/if}
						{#if data.metadata.os}
							<div class="flex items-center justify-between">
								<span class="text-sm font-medium">Operating System</span>
								<Badge variant="secondary" class="text-xs">{data.metadata.os}</Badge>
							</div>
						{/if}
						{#if data.metadata.platform}
							<div class="flex items-center justify-between">
								<span class="text-sm font-medium">Platform</span>
								<Badge variant="secondary" class="text-xs">
									{data.metadata.platform}
									{#if data.metadata['platform-version']}
										{data.metadata['platform-version']}
									{/if}
								</Badge>
							</div>
						{/if}
						{#if data.metadata.arch}
							<div class="flex items-center justify-between">
								<span class="text-sm font-medium">Architecture</span>
								<Badge variant="secondary" class="text-xs">{data.metadata.arch}</Badge>
							</div>
						{/if}
						<div class="flex items-center justify-between">
							<span class="text-sm font-medium">Access</span>
							<div
								class="flex items-center gap-1 rounded-full bg-secondary px-2 py-1 text-xs font-semibold"
								title="Users: {userCount}, Teams: {teamCount}"
							>
								<CircleUserIcon size={12} />
								<span class="pr-1 font-mono">{userCount}</span>
								<UsersIcon size={12} />
								<span class="font-mono">{teamCount}</span>
							</div>
						</div>
					</Card.Content>
				</Card.Root>

				{#if data.metadata['ssh-version'] || data.metadata['ssh-ports']?.length}
					<Card.Root>
						<Card.Header>
							<Card.Title class="flex items-center gap-2 text-base">
								<Terminal size={16} />
								SSH Details
							</Card.Title>
						</Card.Header>
						<Card.Content class="space-y-3">
							{#if data.metadata['ssh-version']}
								<div class="flex items-center justify-between">
									<span class="text-sm font-medium">Version</span>
									<Badge variant="secondary" class="font-mono text-xs">
										{data.metadata['ssh-version']}
									</Badge>
								</div>
							{/if}
							{#if sshPorts.length > 0}
								<div class="flex items-center justify-between">
									<span class="text-sm font-medium">Ports</span>
									<div class="flex flex-wrap gap-1">
										{#each sshPorts as p (p.port)}
											<Badge
												variant={p.listening ? 'secondary' : 'destructive'}
												class="font-mono text-xs"
											>
												{p.port}
											</Badge>
										{/each}
									</div>
								</div>
							{/if}
							{#if data.metadata['ssh-root-login']}
								{@const allowed = data.metadata['ssh-root-login'] === 'yes'}
								<div class="flex items-center justify-between">
									<span class="text-sm font-medium">Root Login</span>
									<Badge variant={allowed ? 'destructive' : 'secondary'} class="font-mono text-xs">
										{allowed ? 'Allowed' : 'Not Allowed'}
									</Badge>
								</div>
							{/if}
							{#if data.metadata['ssh-auth-methods']}
								<div class="flex items-center justify-between">
									<span class="text-sm font-medium">Auth Methods</span>
									<div class="flex flex-wrap gap-1">
										{#each data.metadata['ssh-auth-methods']?.split(',') as method (method)}
											<Badge variant="secondary" class="font-mono text-xs">{method}</Badge>
										{/each}
									</div>
								</div>
							{/if}
							{#if data.metadata['ssh-host-key-types']}
								<div class="flex items-center justify-between">
									<span class="text-sm font-medium">Host Key Types</span>
									<div class="flex flex-wrap gap-1">
										{#each data.metadata['ssh-host-key-types']?.split(',') as type (type)}
											<Badge variant="secondary" class="font-mono text-xs">{type}</Badge>
										{/each}
									</div>
								</div>
							{/if}
						</Card.Content>
					</Card.Root>
				{/if}
			{:else}
				<Card.Root>
					<Card.Content class="flex flex-col items-center justify-center py-8 text-center">
						<Info class="h-8 w-8 text-muted-foreground" />
						<h3 class="mt-2 text-sm font-medium">No metadata available</h3>
						<p class="mt-1 text-xs text-muted-foreground">
							This target doesn't have any metadata configured yet. Metadata is populated when a
							daemon connects to this target.
						</p>
					</Card.Content>
				</Card.Root>
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
	</Tabs.Root>
</FormModal>
