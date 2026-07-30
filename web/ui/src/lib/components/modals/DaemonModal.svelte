<script lang="ts">
	import { Badge } from '$lib/components/ui/badge';
	import * as Dialog from '$lib/components/ui/dialog/';
	import * as Item from '$lib/components/ui/item';
	import type { Daemon } from '$lib/gen/nokku/v1/daemon_pb';
	import { formatTs } from '$lib/utils';
	import { CalendarIcon, ClockIcon } from '@lucide/svelte';
	import { CopyButton } from '../ui/copy-button';
	import Avatar from '../utils/Avatar.svelte';

	interface Props {
		data: Daemon;
		open?: boolean;
	}
	let { data = $bindable({} as Daemon), open = $bindable(false) }: Props = $props();
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="no-scrollbar max-h-[95vh] w-125 overflow-y-auto">
		<Dialog.Header>
			<Dialog.Title>{data.name}</Dialog.Title>
			<Dialog.Description>View daemon details and status</Dialog.Description>
		</Dialog.Header>

		<Item.Root variant="muted">
			<Item.Media>
				<Avatar id={data.id} />
			</Item.Media>
			<Item.Content>
				<Item.Title class="text-lg">{data.name}</Item.Title>
				<Item.Description>
					<Badge variant="secondary" class={data.online ? 'bg-chart-3' : 'bg-destructive'}>
						{data.online ? 'Online' : 'Offline'}
					</Badge>
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
					{data?.metadata.version ?? 'Unknown'}
				</Badge>
			</Item.Actions>
		</Item.Root>

		<Item.Root variant="muted" size="sm">
			<Item.Content>
				<Item.Title title={data.metadata.fingerprint}>Fingerprint</Item.Title>
			</Item.Content>
			<Item.Actions>
				<CopyButton text={data.metadata.fingerprint}>Copy</CopyButton>
			</Item.Actions>
		</Item.Root>

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
	</Dialog.Content>
</Dialog.Root>
