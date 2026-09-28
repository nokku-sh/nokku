<script lang="ts">
	import { timestampFromDate } from '@bufbuild/protobuf/wkt';
	import { CalendarIcon, WaypointsIcon, XIcon } from '@lucide/svelte';
	import type { DateValue } from '@internationalized/date';
	import { getLocalTimeZone, today } from '@internationalized/date';
	import { serviceAccount } from '$lib/api/service_account.svelte';
	import { roles as rolesApi } from '$lib/api/roles.svelte';
	import { roleIcon, roleLabel } from '$lib/roles';
	import { Button } from '$lib/components/ui/button';
	import { Calendar } from '$lib/components/ui/calendar';
	import * as Dialog from '$lib/components/ui/dialog/';
	import * as Field from '$lib/components/ui/field';
	import { Input } from '$lib/components/ui/input';
	import InputGroupVariants from '$lib/components/ui/input-group/input-group-variants.svelte';
	import * as Popover from '$lib/components/ui/popover';
	import * as Select from '$lib/components/ui/select';
	import Textarea from '$lib/components/ui/textarea/textarea.svelte';
	import type { ServiceAccount } from '$lib/gen/nokku/v1/service_account_pb';
	import { useAutoSave } from '$lib/hooks';
	import { cn, DateValueFormat } from '$lib/utils';
	import FormModal from './FormModal.svelte';
	import MetaInfo from './MetaInfo.svelte';

	interface Props {
		draft: ServiceAccount;
		open?: boolean;
	}
	let { draft: model, open = $bindable(false) }: Props = $props();

	const isEdit = $derived(!!model.id);

	const rolesQuery = $derived(rolesApi.list());
	const roleOptions = $derived(
		(rolesQuery.data ?? []).map((r) => ({
			value: r.name,
			label: roleLabel(r.name),
			description: r.description,
			icon: roleIcon(r.name)
		}))
	);
	const selectedRole = $derived(roleOptions.find((r) => r.value === model.roleName));

	let expiry = $state<DateValue>();
	let calendarOpen = $state(false);

	const expiryPresets = [
		{ label: '30 days', days: 30 },
		{ label: '60 days', days: 60 },
		{ label: '90 days', days: 90 },
		{ label: '6 months', days: 180 },
		{ label: '1 year', days: 365 }
	];

	const createMutation = serviceAccount.create();
	const updateMutation = serviceAccount.update();
	const isLoading = $derived(createMutation.isPending);

	const autoSave = useAutoSave(() => updateMutation.mutateAsync({ ...model }));
	function save() {
		if (isEdit) autoSave.save();
	}

	function setExpiryPreset(days: number) {
		expiry = today(getLocalTimeZone()).add({ days });
		calendarOpen = false;
	}

	function clearExpiry() {
		expiry = undefined;
		calendarOpen = false;
	}

	function onSubmit() {
		const expiresAt = expiry ? timestampFromDate(expiry.toDate(getLocalTimeZone())) : undefined;
		createMutation.mutate({ ...model, expiresAt });
		open = false;
	}
</script>

<Dialog.Root bind:open={createMutation.isSuccess}>
	<Dialog.Content class="no-scrollbar max-h-[95vh] w-125 overflow-y-auto">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2">
				<WaypointsIcon size={20} />
				API Token
			</Dialog.Title>
			<Dialog.Description>
				This token will only be shown once. Copy it now and store it securely.
			</Dialog.Description>
		</Dialog.Header>
		<InputGroupVariants variant="copy-input" value={createMutation.data?.token} readonly />
	</Dialog.Content>
</Dialog.Root>

<FormModal
	bind:open
	title={isEdit ? model.name : 'Create Service Account'}
	description={isEdit
		? 'Changes save automatically.'
		: 'Service accounts provide API access for automation and CI/CD workflows.'}
	onSubmit={isEdit ? undefined : onSubmit}
	{isLoading}
	saveState={autoSave.saveState}
>
	<Field.Field>
		<Field.Label for="name">Name</Field.Label>
		<Field.Content>
			<Input
				id="name"
				bind:value={model.name}
				placeholder="ci-cd, ansible-prod"
				required
				oninput={save}
			/>
			<Field.Description>A unique identifier for this service account</Field.Description>
		</Field.Content>
	</Field.Field>

	<Field.Field>
		<Field.Label for="description">Description</Field.Label>
		<Field.Content>
			<Textarea
				id="description"
				bind:value={model.description}
				placeholder="CI/CD pipeline account for production deployments"
				class="min-h-20 resize-none"
				rows={3}
				oninput={save}
			/>
		</Field.Content>
	</Field.Field>

	<Field.Field>
		<Field.Label for="role">Role</Field.Label>
		<Field.Content>
			<Select.Root
				type="single"
				value={model.roleName}
				onValueChange={(v) => {
					model.roleName = v;
					save();
				}}
			>
				<Select.Trigger class="w-full" id="role">
					<div class="flex items-center gap-2">
						{#if selectedRole}
							<selectedRole.icon class="size-4 text-foreground/70" />
							<span>{selectedRole.label}</span>
						{:else}
							<span class="text-muted-foreground">Select a role</span>
						{/if}
					</div>
				</Select.Trigger>
				<Select.Content class="max-w-88" side="bottom" align="start">
					{#each roleOptions as role (role.value)}
						<Select.Item value={role.value} label={role.label}>
							<role.icon size={16} class="text-foreground/70" />
							<div class="flex flex-col gap-1 text-left">
								<span class="text-sm font-medium">{role.label}</span>
								<span class="text-xs text-muted-foreground">{role.description}</span>
							</div>
						</Select.Item>
					{/each}
				</Select.Content>
			</Select.Root>
		</Field.Content>
	</Field.Field>

	{#if !isEdit}
		<Field.Field>
			<Field.Label>Token Expiry</Field.Label>
			<Field.Content class="space-y-2">
				<div class="grid grid-cols-5 gap-2">
					{#each expiryPresets as preset (preset.label)}
						<Button
							type="button"
							variant="outline"
							size="sm"
							class="h-8 text-xs"
							onclick={() => setExpiryPreset(preset.days)}
						>
							{preset.label}
						</Button>
					{/each}
				</div>

				<Popover.Root bind:open={calendarOpen}>
					<Popover.Trigger class="w-full">
						<Button
							variant="outline"
							class={cn(
								'w-full justify-start text-left font-normal',
								!expiry && 'text-muted-foreground'
							)}
						>
							<CalendarIcon class="mr-2 size-4" />
							{expiry ? DateValueFormat(expiry) : 'Custom date or no expiry'}
							{#if expiry}
								<button
									type="button"
									onclick={(e) => {
										e.stopPropagation();
										clearExpiry();
									}}
									class="ml-auto rounded-sm opacity-70 ring-offset-background transition-opacity hover:opacity-100 focus:ring-2 focus:ring-ring focus:ring-offset-2 focus:outline-none"
								>
									<XIcon size={16} />
								</button>
							{/if}
						</Button>
					</Popover.Trigger>
					<Popover.Content class="w-auto p-0" align="start" side="top">
						<Calendar bind:value={expiry} type="single" initialFocus class="min-h-70" fixedWeeks />
					</Popover.Content>
				</Popover.Root>

				<Field.Description>
					Choose a quick preset or select a custom date. Leave empty for no expiration.
				</Field.Description>
			</Field.Content>
		</Field.Field>
	{:else}
		<MetaInfo createdAt={model.createdAt} updatedAt={model.updatedAt} />
	{/if}
</FormModal>
