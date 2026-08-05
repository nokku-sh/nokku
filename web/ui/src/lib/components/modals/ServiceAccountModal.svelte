<script lang="ts">
	import { serviceAccount } from '$lib/api/service_account.svelte';
	import { roles as rolesApi } from '$lib/api/roles.svelte';
	import { assignableRoles, roleIcon, roleLabel } from '$lib/roles';
	import * as Alert from '$lib/components/ui/alert';
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
	import { cn, DateValueFormat, formatTs } from '$lib/utils';
	import { timestampFromDate } from '@bufbuild/protobuf/wkt';
	import { type DateValue, getLocalTimeZone, today } from '@internationalized/date';
	import { CalendarIcon, CircleAlert, WaypointsIcon, XIcon } from '@lucide/svelte';
	import FormModal from './FormModal.svelte';

	interface Props {
		data?: ServiceAccount;
		open?: boolean;
	}
	let { data, open = $bindable(false) }: Props = $props();

	let saData = $state({} as ServiceAccount);
	$effect(() => {
		if (data) saData = { ...data, roleName: data.roleName || 'viewer' };
	});

	const rolesQuery = $derived(rolesApi.list());
	const roleOptions = $derived(
		assignableRoles(rolesQuery.data ?? [], 'serviceAccounts').map((r) => ({
			value: r.name,
			label: roleLabel(r.name),
			description: r.description,
			icon: roleIcon(r.name)
		}))
	);
	const selectedRole = $derived(roleOptions.find((r) => r.value === saData.roleName));

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
	const isLoading = $derived(createMutation.isPending || updateMutation.isPending);

	function setExpiryPreset(days: number) {
		expiry = today(getLocalTimeZone()).add({ days });
		calendarOpen = false;
	}

	function clearExpiry() {
		expiry = undefined;
		calendarOpen = false;
	}

	function onSubmit() {
		if (saData.id) {
			updateMutation.mutate({ ...saData });
		} else {
			const expiresAt = expiry ? timestampFromDate(expiry.toDate(getLocalTimeZone())) : undefined;
			createMutation.mutate({ ...saData, expiresAt });
		}
		open = false;
	}
</script>

<!-- Token Display Modal (shown after creation) -->
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

<!-- Create/Edit Modal -->
<FormModal
	bind:open
	title="{saData?.id ? 'Edit' : 'Create'} Service Account"
	description="Service accounts provide API access for automation and CI/CD workflows"
	{onSubmit}
	submitLabel={saData.id ? 'Update' : 'Create'}
	{isLoading}
>
	<Field.Field>
		<Field.Label for="name">Name *</Field.Label>
		<Field.Content>
			<Input
				id="name"
				bind:value={saData.name}
				placeholder="ci-cd, ansible-prod, github-actions"
				required
			/>
			<Field.Description>A unique identifier for this service account</Field.Description>
		</Field.Content>
	</Field.Field>

	<Field.Field>
		<Field.Label for="description">Description</Field.Label>
		<Field.Content>
			<Textarea
				id="description"
				bind:value={saData.description}
				placeholder="CI/CD pipeline account for production deployments"
				class="min-h-20 resize-none"
				rows={3}
			/>
		</Field.Content>
	</Field.Field>

	<Field.Field>
		<Field.Label for="role">Role</Field.Label>
		<Field.Content>
			<Select.Root type="single" bind:value={saData.roleName}>
				<Select.Trigger class="w-full" id="role">
					{#if selectedRole}
						<selectedRole.icon class="size-4 text-foreground/70" />
						<span>{selectedRole.label}</span>
					{:else}
						<span class="text-muted-foreground">Select a role</span>
					{/if}
				</Select.Trigger>
				<Select.Content class="max-w-80">
					<Select.Group>
						{#each roleOptions as role (role.value)}
							<Select.Item
								value={role.value}
								label={role.label}
								class="cursor-pointer items-center gap-3 py-2.5"
							>
								<role.icon size={16} class="mt-0.5 text-foreground/70" />
								<div class="flex flex-col gap-1 text-left">
									<span class="text-sm leading-none font-medium">{role.label}</span>
									<span class="text-xs leading-snug text-muted-foreground">{role.description}</span>
								</div>
							</Select.Item>
						{/each}
					</Select.Group>
				</Select.Content>
			</Select.Root>
			<Field.Description>
				Viewer can view workspace resources; Editor can also manage operational resources and
				certificate authorities.
			</Field.Description>
		</Field.Content>
	</Field.Field>

	<!-- Expiry Configuration (only for new accounts) -->
	{#if !saData.id}
		<Field.Separator />
		<Field.Field>
			<Field.Label>Token Expiry</Field.Label>
			<Field.Content class="space-y-2">
				<!-- Quick Presets -->
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

				<!-- Calendar Picker -->
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
	{/if}

	<!-- Existing Account Info -->
	{#if saData.id}
		<Alert.Root>
			<CircleAlert />
			<Alert.Title>Token Security</Alert.Title>
			<Alert.Description>
				The token cannot be retrieved after creation. To change it, create a new service account.
				{#if saData.expiresAt}
					<div class="mt-2 text-xs">
						<span class="font-medium">Expires:</span>
						{formatTs(saData.expiresAt)}
					</div>
				{/if}
				{#if saData.lastUsedAt}
					<div class="text-xs">
						<span class="font-medium">Last used:</span>
						{formatTs(saData.lastUsedAt)}
					</div>
				{/if}
			</Alert.Description>
		</Alert.Root>
	{/if}
</FormModal>
