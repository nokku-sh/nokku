<script lang="ts">
	import { user } from '$lib/api/user.svelte';
	import { util } from '$lib/api/workspaces.svelte';
	import ActivityModal from '$lib/components/modals/ActivityModal.svelte';
	import { Button } from '$lib/components/ui/button';
	import * as DropdownMenu from '$lib/components/ui/dropdown-menu';
	import * as Empty from '$lib/components/ui/empty';
	import DateRangePicker from '$lib/components/utils/DateRangePicker.svelte';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import { ExportAuditLogsRequest_Format, type EventLog } from '$lib/gen/nokku/v1/util_pb';
	import { auditStatusOk, DateValueStartTs, DateValueToTimestamp, formatTs } from '$lib/utils';
	import { getLocalTimeZone, today } from '@internationalized/date';
	import {
		ActivityIcon,
		Calendar,
		CircleCheckBig,
		CircleXIcon,
		Download,
		InfoIcon,
		LoaderCircle,
		MapPinIcon
	} from '@lucide/svelte';
	import type { DateRange } from 'bits-ui';

	let logRange = $state<DateRange>({
		start: today(getLocalTimeZone()).subtract({ days: 14 }),
		end: today(getLocalTimeZone())
	});

	const currentUser = $derived(user.self());
	const logs = $derived(
		user.activity({
			userID: currentUser.data?.id ?? '',
			startDate: DateValueStartTs(logRange.start),
			endDate: DateValueToTimestamp(logRange.end)
		})
	);
	const exportMutation = util.exportLogs();

	let selected = $state({} as EventLog);
	let open = $state(false);
</script>

<PageHeader
	icon={ActivityIcon}
	title="Personal Activity"
	description="View your authentication history and account activity."
/>

<ActivityModal bind:open log={selected} />

<div class="mb-6 flex flex-col justify-end gap-4 sm:flex-row sm:items-center">
	<div class="flex items-center gap-2">
		<DateRangePicker bind:value={logRange} />
		<DropdownMenu.Root>
			<DropdownMenu.Trigger>
				<Button variant="outline" size="icon" disabled={logs.isPending}>
					<Download class="h-4 w-4" />
				</Button>
			</DropdownMenu.Trigger>
			<DropdownMenu.Content align="end">
				<DropdownMenu.Label>Export Format</DropdownMenu.Label>
				<DropdownMenu.Separator />
				<DropdownMenu.Item
					onclick={() =>
						exportMutation.mutate({
							format: ExportAuditLogsRequest_Format.CSV,
							workspaceId: '',
							startDate: DateValueStartTs(logRange.start),
							endDate: DateValueToTimestamp(logRange.end)
						})}
				>
					CSV
				</DropdownMenu.Item>
				<DropdownMenu.Item
					onclick={() =>
						exportMutation.mutate({
							format: ExportAuditLogsRequest_Format.JSON,
							workspaceId: '',
							startDate: DateValueStartTs(logRange.start),
							endDate: DateValueToTimestamp(logRange.end)
						})}
				>
					JSON
				</DropdownMenu.Item>
			</DropdownMenu.Content>
		</DropdownMenu.Root>
	</div>
</div>

{#if logs.isPending}
	<div class="flex h-48 items-center justify-center">
		<LoaderCircle class="h-6 w-6 animate-spin text-muted-foreground" />
	</div>
{:else if logs.isSuccess && logs.data?.total > 0}
	<div class="space-y-4">
		{#each logs.data.logs as log}
			{@const isError = !auditStatusOk(log.statusCode)}
			<div
				class="group flex justify-between gap-4 rounded-lg border bg-background/50 p-4 transition-colors hover:bg-background"
			>
				<!-- Status indicator -->
				<div class="flex flex-col items-center">
					<div class={`rounded-full p-2 ${isError ? 'bg-destructive/10' : 'bg-chart-3/10'}`}>
						{#if isError}
							<CircleXIcon class="text-destructive" size={16} />
						{:else}
							<CircleCheckBig class="text-chart-3" size={16} />
						{/if}
					</div>
					<div class="mt-2 h-full w-px bg-border group-last:hidden"></div>
				</div>

				<!-- Event details -->
				<div class="flex-1 space-y-2 py-1">
					<div>
						<p class="text-sm font-medium capitalize">
							{log.action.replace('_', ' ')}
						</p>
						<p class="mt-0.5 text-xs text-muted-foreground">
							{formatTs(log.timestamp)} ({formatTs(log.timestamp, 'relative')})
						</p>
					</div>

					<div class="flex flex-wrap gap-x-4 gap-y-1 text-xs">
						{#if log.ipAddress}
							<div class="flex items-center gap-1.5 text-muted-foreground">
								<MapPinIcon class="h-3 w-3" />
								<span>{log.ipAddress}</span>
							</div>
						{/if}
						{#if log.userAgent}
							<p class="max-w-xs truncate text-muted-foreground xl:max-w-md">{log.userAgent}</p>
						{/if}
					</div>
				</div>

				<div class="flex items-start">
					<Button
						variant="ghost"
						size="icon"
						class="h-8 w-8 rounded-lg text-muted-foreground hover:text-foreground"
						onclick={() => {
							selected = { ...log };
							open = true;
						}}
					>
						<InfoIcon size={16} />
					</Button>
				</div>
			</div>
		{/each}
	</div>
{:else}
	<Empty.Root class="border border-dashed bg-background/50 py-12">
		<Empty.Header>
			<Empty.Media variant="icon">
				<Calendar />
			</Empty.Media>
			<Empty.Title>No Activity</Empty.Title>
			<Empty.Description>Your login and account activity will appear here</Empty.Description>
		</Empty.Header>
	</Empty.Root>
{/if}
