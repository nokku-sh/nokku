<script lang="ts">
	import { WorkspaceRole } from '#lib/gen/nokku/v1/access_pb.js';
	import SecretReveal from '#lib/components/blocks/SecretReveal.svelte';
	import { create } from '@bufbuild/protobuf';
	import { timestampFromDate } from '@bufbuild/protobuf/wkt';
	import { getLocalTimeZone, today, type DateValue } from '@internationalized/date';
	import { Bot, CalendarIcon, KeyRound } from '@lucide/svelte';
	import { serviceAccount as saApi } from '#lib/api/service_account.svelte.js';
	import RolePicker from '#lib/components/access/RolePicker.svelte';
	import { SERVICE_ACCOUNT_MAX_ROLE } from '#lib/roles.js';
	import * as Alert from '#lib/components/ext/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Calendar } from '#lib/components/ui/calendar/index.js';
	import * as Dialog from '#lib/components/ui/dialog/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import * as Popover from '#lib/components/ui/popover/index.js';
	import { Textarea } from '#lib/components/ui/textarea/index.js';
	import * as ToggleGroup from '#lib/components/ui/toggle-group/index.js';
	import { ServiceAccountSchema } from '#lib/gen/nokku/v1/service_account_pb.js';
	import { useSheet } from '#lib/hooks/index.js';
	import { DateValueFormat } from '#lib/utils.js';
	import FormModal from '#lib/components/blocks/FormModal.svelte';

	let { open = $bindable(false) }: { open?: boolean } = $props();

	const sheet = useSheet();
	const createSA = saApi.create();

	let model = $state(create(ServiceAccountSchema, { role: WorkspaceRole.VIEWER }));
	let preset = $state('90');
	let customDate = $state<DateValue>();
	let calendarOpen = $state(false);

	let token = $state('');
	let createdId = $state('');

	const presets = [
		{ value: '30', label: '30 days' },
		{ value: '90', label: '90 days' },
		{ value: '365', label: '1 year' },
		{ value: 'never', label: 'Never' },
		{ value: 'custom', label: 'Custom' }
	];

	const expiry = $derived.by(() => {
		if (preset === 'never') return undefined;
		if (preset === 'custom') return customDate;
		return today(getLocalTimeZone()).add({ days: Number(preset) });
	});

	async function onSubmit() {
		const res = await createSA.mutateAsync({
			...model,
			expiresAt: expiry ? timestampFromDate(expiry.toDate(getLocalTimeZone())) : undefined
		});
		token = res.token;
		createdId = res.serviceAccount?.id ?? '';
		model = create(ServiceAccountSchema, { role: WorkspaceRole.VIEWER });
		preset = '90';
	}

	function finish() {
		const id = createdId;
		token = '';
		createdId = '';
		if (id) sheet.show(id, 'access');
	}
</script>

<FormModal
	bind:open
	title="Create a service account"
	description="An API identity for CI, Ansible and other automation."
	icon={Bot}
	submitLabel="Create and show token"
	{onSubmit}
>
	<Field.Field>
		<Field.Label for="new-sa-name">Name</Field.Label>
		<Input id="new-sa-name" bind:value={model.name} placeholder="github-deploy" required />
	</Field.Field>

	<Field.Field>
		<Field.Label for="new-sa-description">What it's for</Field.Label>
		<Textarea
			id="new-sa-description"
			bind:value={model.description}
			placeholder="Deploys from the main branch"
			rows={2}
		/>
	</Field.Field>

	<Field.Set>
		<Field.Legend variant="label">Workspace role</Field.Legend>
		<RolePicker
			value={model.role}
			max={SERVICE_ACCOUNT_MAX_ROLE}
			onChange={(role) => (model.role = role)}
		/>
	</Field.Set>

	<Field.Set>
		<Field.Legend variant="label">Token expires</Field.Legend>
		<ToggleGroup.Root
			type="single"
			variant="outline"
			size="sm"
			value={preset}
			onValueChange={(v) => {
				if (!v) return;
				preset = v;
				calendarOpen = v === 'custom';
			}}
			class="w-full flex-wrap"
		>
			{#each presets as p (p.value)}
				<ToggleGroup.Item value={p.value} class="flex-1">{p.label}</ToggleGroup.Item>
			{/each}
		</ToggleGroup.Root>
		{#if preset === 'custom'}
			<Popover.Root bind:open={calendarOpen}>
				<Popover.Trigger>
					{#snippet child({ props })}
						<Button {...props} variant="outline" class="w-full justify-start font-normal">
							<CalendarIcon data-icon="inline-start" />
							{customDate ? DateValueFormat(customDate) : 'Pick a date'}
						</Button>
					{/snippet}
				</Popover.Trigger>
				<Popover.Content class="w-auto p-0" align="start">
					<Calendar
						type="single"
						bind:value={customDate}
						minValue={today(getLocalTimeZone()).add({ days: 1 })}
						onValueChange={() => (calendarOpen = false)}
					/>
				</Popover.Content>
			</Popover.Root>
		{/if}
		<Field.Description>
			{#if expiry}
				Stops working on {DateValueFormat(expiry)}.
			{:else if preset === 'never'}
				Never expires. Rotate it by hand if it leaks.
			{/if}
		</Field.Description>
	</Field.Set>
</FormModal>

<Dialog.Root open={!!token} onOpenChange={(v) => !v && finish()}>
	<Dialog.Content class="sm:max-w-lg">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2">
				<KeyRound class="size-4" />
				Copy the token now
			</Dialog.Title>
			<Dialog.Description>Store it in your CI secrets.</Dialog.Description>
		</Dialog.Header>
		<SecretReveal
			values={[{ value: token }, { label: 'As an env var', value: `export NK_TOKEN=${token}` }]}
		/>
		<Alert.Root variant="info">
			<KeyRound />
			<Alert.Description>
				Next, grant it a login account on the targets it deploys to.
			</Alert.Description>
		</Alert.Root>
		<Dialog.Footer>
			<Button onclick={finish}>I saved it, set up access</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
