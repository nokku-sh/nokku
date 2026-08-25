<script lang="ts">
	import { create } from '@bufbuild/protobuf';
	import { Globe, Info, Monitor, Plus, Server, Users, X } from '@lucide/svelte';
	import { ca } from '$lib/api/certificates.svelte';
	import { principal } from '$lib/api/principals.svelte';
	import { target as targetApi } from '$lib/api/targets.svelte';
	import * as Card from '$lib/components/ui/card';
	import { Badge } from '$lib/components/ui/badge';
	import { Button } from '$lib/components/ui/button';
	import CopyButton from '$lib/components/ui/copy-button/copy-button.svelte';
	import * as Field from '$lib/components/ui/field';
	import { Input } from '$lib/components/ui/input';
	import * as InputGroup from '$lib/components/ui/input-group/index.js';
	import InputGroupVariants from '$lib/components/ui/input-group/input-group-variants.svelte';
	import * as Item from '$lib/components/ui/item';
	import * as Select from '$lib/components/ui/select';
	import * as Tabs from '$lib/components/ui/tabs';
	import { Textarea } from '$lib/components/ui/textarea';
	import { PrincipalSchema } from '$lib/gen/nokku/v1/principal_pb';
	import type { Target } from '$lib/gen/nokku/v1/target_pb';
	import { useAutoSave } from '$lib/hooks';
	import FormModal from './FormModal.svelte';
	import MetaInfo from './MetaInfo.svelte';
	import ModalTabs from './ModalTabs.svelte';

	interface Props {
		draft: Target;
		open?: boolean;
	}
	let { draft: model, open = $bindable(false) }: Props = $props();

	const isEdit = $derived(!!model.id);

	const caData = $derived(ca.list());
	const defaultCA = $derived(caData.data?.find((c) => c.isDefault));

	const createTarget = targetApi.create();
	const updateTarget = targetApi.update();
	const setPrincipals = principal.set();
	const isLoading = $derived(createTarget.isPending);

	const autoSave = useAutoSave(() => updateTarget.mutateAsync({ ...model }));
	function save() {
		if (isEdit) autoSave.save();
	}

	let newEndpointValue = $state('');

	function addEndpoint() {
		const value = newEndpointValue.trim();
		if (!value || model.endpoints?.includes(value)) return;
		model.endpoints = [...(model.endpoints ?? []), value];
		newEndpointValue = '';
		save();
	}

	function removeEndpoint(endpoint: string) {
		model.endpoints = model.endpoints?.filter((e) => e !== endpoint) ?? [];
		save();
	}

	function changePrincipals(usernames: string[]) {
		model.principals = usernames.map((username) => create(PrincipalSchema, { username }));
		if (isEdit) setPrincipals.mutate({ targetId: model.id, usernames });
	}

	function onSubmit() {
		createTarget.mutate({ ...model, caId: model.caId || defaultCA?.id });
		open = false;
	}
</script>

<FormModal
	bind:open
	title={isEdit ? model.name : 'Create Target'}
	description={isEdit
		? 'Changes save automatically.'
		: 'Register a server that a daemon can tunnel to.'}
	classModal="sm:max-w-125"
	onSubmit={isEdit ? undefined : onSubmit}
	{isLoading}
	saveState={autoSave.saveState}
>
	<ModalTabs
		tabs={[
			{ value: 'general', label: 'General', icon: Info },
			{ value: 'endpoints', label: 'Endpoints', icon: Globe },
			{ value: 'info', label: 'Info', icon: Monitor }
		]}
	>
		<Tabs.Content value="general" class="space-y-4">
			<div class="grid grid-cols-6 gap-2">
				<Field.Field class="col-span-4">
					<Field.Label for="name">Name</Field.Label>
					<Field.Content>
						<Input id="name" bind:value={model.name} placeholder="web-prod-1" oninput={save} />
					</Field.Content>
				</Field.Field>

				<Field.Field class="col-span-2">
					<Field.Label for="caId">Certificate</Field.Label>
					<Field.Content>
						<Select.Root
							type="single"
							value={model.caId}
							onValueChange={(v) => {
								model.caId = v;
								save();
							}}
						>
							<Select.Trigger class="w-full">
								<span class="truncate">
									{caData.data?.find((c) => c.id === model.caId)?.name || 'Default CA'}
								</span>
							</Select.Trigger>
							<Select.Content>
								{#each caData.data ?? [] as c (c.id)}
									<Select.Item value={c.id}>{c.name}</Select.Item>
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
						bind:value={model.description}
						placeholder="Production web server"
						oninput={save}
					/>
				</Field.Content>
			</Field.Field>

			<Field.Field>
				<Field.Label for="principals">Principals</Field.Label>
				<Field.Content>
					<InputGroupVariants
						variant="tags"
						icon={{ tags: Users }}
						tags={model.principals?.map((p) => p.username)}
						onTagChange={changePrincipals}
						placeholder="root, ubuntu, ec2-user"
					/>
				</Field.Content>
			</Field.Field>

			<Field.Field>
				<Field.Label for="tags">Tags</Field.Label>
				<Field.Content>
					<InputGroupVariants
						variant="tags"
						tags={model.tags ?? []}
						onTagChange={(tags) => {
							model.tags = tags;
							save();
						}}
						placeholder="linux, production"
					/>
				</Field.Content>
			</Field.Field>
			{#if isEdit}
				<MetaInfo createdAt={model.createdAt} updatedAt={model.updatedAt} />
			{/if}
		</Tabs.Content>

		<Tabs.Content value="endpoints" class="space-y-4">
			{#if model.endpoints?.length}
				<div class="space-y-2">
					{#each model.endpoints as e (e)}
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
					<Globe class="mx-auto mb-2 size-8 text-muted-foreground" />
					<p class="text-sm text-muted-foreground">No endpoints configured</p>
				</div>
			{/if}

			<InputGroup.Root>
				<InputGroup.Input
					bind:value={newEndpointValue}
					placeholder="Add an endpoint (e.g. 192.168.1.100)"
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
						class="size-6"
						onclick={addEndpoint}
					>
						<Plus />
					</InputGroup.Button>
				</InputGroup.Addon>
			</InputGroup.Root>
		</Tabs.Content>

		<Tabs.Content value="info" class="space-y-4">
			{#if model.metadata}
				<Card.Root>
					<Card.Header>
						<Card.Title class="flex items-center gap-2 text-base">
							<Server size={16} />
							System Information
						</Card.Title>
					</Card.Header>
					<Card.Content class="space-y-3">
						{#each Object.entries(model.metadata) as [key, value] (key)}
							<div class="flex items-center justify-between">
								<span class="text-sm font-medium capitalize">{key.replace(/-/g, ' ')}</span>
								<Badge variant="secondary" class="font-mono text-xs">{value}</Badge>
							</div>
						{/each}
					</Card.Content>
				</Card.Root>
			{:else}
				<Card.Root>
					<Card.Content class="flex flex-col items-center justify-center py-8 text-center">
						<Info class="size-8 text-muted-foreground" />
						<h3 class="mt-2 text-sm font-medium">No metadata available</h3>
						<p class="mt-1 text-xs text-muted-foreground">
							Metadata is populated when the daemon connects to this target.
						</p>
					</Card.Content>
				</Card.Root>
			{/if}
		</Tabs.Content>
	</ModalTabs>
</FormModal>
