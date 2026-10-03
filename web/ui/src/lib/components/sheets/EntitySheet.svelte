<script lang="ts" module>
	import type { LucideIcon } from '@lucide/svelte';
	import type { Timestamp } from '@bufbuild/protobuf/wkt';

	export type SheetTab = { value: string; label: string; icon?: LucideIcon; count?: number };

	export type SheetMeta = {
		id?: string;
		createdAt?: Timestamp;
		updatedAt?: Timestamp;
		extra?: { label: string; value?: string; copy?: boolean }[];
	};
</script>

<script lang="ts">
	import type { Snippet } from 'svelte';
	import * as Sheet from '#lib/components/ui/sheet/index.js';
	import * as Tabs from '#lib/components/ui/tabs/index.js';
	import { Rename } from '#lib/components/ui/rename/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { IsMobile, type SaveState } from '#lib/hooks/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Popover from '#lib/components/ui/popover/index.js';
	import CopyText from '#lib/components/blocks/CopyText.svelte';
	import { formatTs } from '#lib/utils.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import { FileQuestion, Info } from '@lucide/svelte';
	import SaveStatus from '#lib/components/blocks/SaveStatus.svelte';

	interface Props {
		open: boolean;
		onClose: () => void;
		title: string;
		/** Makes the title editable in place. */
		onRename?: (value: string) => void;
		loading?: boolean;
		/** Set when the entity failed to load, e.g. it was deleted. */
		missing?: boolean;
		tabs?: SheetTab[];
		tab?: string;
		onTabChange?: (tab: string) => void;
		/** Shows the autosave footer. */
		saveState?: SaveState;
		media?: Snippet;
		subtitle?: Snippet;
		/** Primary actions under the title. */
		actions?: Snippet;
		/** Extra buttons next to close, usually a ⋯ menu. */
		menu?: Snippet;
		/** IDs and timestamps, tucked into an info popover in the header. */
		meta?: SheetMeta;
		children: Snippet;
	}

	let {
		open,
		onClose,
		title,
		onRename,
		loading: loadingProp = false,
		missing = false,
		tabs,
		tab,
		onTabChange,
		saveState,
		media,
		subtitle,
		actions,
		menu,
		meta,
		children
	}: Props = $props();

	const timestamps = $derived(
		[
			{ label: 'Created', ts: meta?.createdAt },
			{ label: 'Updated', ts: meta?.updatedAt }
		].filter((t) => t.ts)
	);

	const loading = $derived(loadingProp && !missing);
	const mobile = new IsMobile();
	const activeTab = $derived(tabs?.some((t) => t.value === tab) ? tab : tabs?.[0]?.value);
</script>

<Sheet.Root {open} onOpenChange={(value) => !value && onClose()}>
	<Sheet.Content
		side={mobile.current ? 'bottom' : 'right'}
		class="w-full gap-0 p-0 data-[side=bottom]:max-h-[92dvh] data-[side=bottom]:rounded-t-2xl data-[side=right]:sm:max-w-xl"
	>
		<Sheet.Header class="gap-3 border-b px-5 pt-5 pb-4">
			<div class="flex items-start gap-3 pr-20">
				{#if media}
					<div class="shrink-0">{@render media()}</div>
				{/if}
				<div class="flex min-w-0 flex-1 flex-col gap-1">
					<Sheet.Title class="min-w-0 text-lg">
						{#if missing}
							<span class="block truncate text-muted-foreground">Not found</span>
						{:else if loading}
							<Skeleton class="h-7 w-48" />
						{:else if onRename}
							<Rename
								this="span"
								value={title}
								class="block truncate rounded-md font-semibold hover:bg-muted"
								onSave={onRename}
								validate={(v) => v.trim().length > 0}
							/>
						{:else}
							<span class="block truncate">{title}</span>
						{/if}
					</Sheet.Title>
					<Sheet.Description class="flex flex-wrap items-center gap-x-2 gap-y-1">
						{#if loading}
							<Skeleton class="h-4 w-32" />
						{:else}
							{@render subtitle?.()}
						{/if}
					</Sheet.Description>
				</div>
			</div>
			{#if (menu || meta) && !loading}
				<div class="absolute top-3 right-11 flex items-center gap-0.5">
					{#if meta}
						<Popover.Root>
							<Popover.Trigger>
								{#snippet child({ props })}
									<Button {...props} variant="ghost" size="icon-sm" aria-label="Details">
										<Info />
									</Button>
								{/snippet}
							</Popover.Trigger>
							<Popover.Content align="end" class="w-72">
								<dl class="grid grid-cols-[auto_1fr] items-center gap-x-4 gap-y-2 text-sm">
									{#if meta.id}
										<dt class="text-muted-foreground">ID</dt>
										<dd class="flex min-w-0 justify-end"><CopyText value={meta.id} mono /></dd>
									{/if}
									{#each meta.extra?.filter((e) => e.value) ?? [] as e (e.label)}
										<dt class="text-muted-foreground">{e.label}</dt>
										<dd class="flex min-w-0 justify-end">
											{#if e.copy}
												<CopyText value={e.value ?? ''} mono />
											{:else}
												<span class="truncate">{e.value}</span>
											{/if}
										</dd>
									{/each}
									{#each timestamps as t (t.label)}
										<dt class="text-muted-foreground">{t.label}</dt>
										<dd class="text-right" title={formatTs(t.ts, 'withTime')}>
											{formatTs(t.ts, 'relative')}
										</dd>
									{/each}
								</dl>
							</Popover.Content>
						</Popover.Root>
					{/if}
					{@render menu?.()}
				</div>
			{/if}
			{#if actions && !loading}
				<div class="flex flex-wrap items-center gap-2">{@render actions()}</div>
			{/if}
		</Sheet.Header>

		{#if missing}
			<Empty.Root class="flex-1">
				<Empty.Header>
					<Empty.Media variant="icon"><FileQuestion /></Empty.Media>
					<Empty.Title>Not found</Empty.Title>
					<Empty.Description
						>It may have been deleted, or the link is out of date.</Empty.Description
					>
				</Empty.Header>
			</Empty.Root>
		{:else if loading}
			<div class="flex flex-col gap-3 px-5 py-5">
				<Skeleton class="h-9 w-full" />
				<Skeleton class="h-24 w-full" />
				<Skeleton class="h-24 w-full" />
			</div>
		{:else if tabs?.length}
			<Tabs.Root value={activeTab} onValueChange={onTabChange} class="min-h-0 flex-1 gap-0">
				<Tabs.List variant="line" class="w-full justify-start border-b px-3">
					{#each tabs as t (t.value)}
						<Tabs.Trigger value={t.value} class="flex-none">
							{#if t.icon}
								<t.icon />
							{/if}
							{t.label}
							{#if t.count !== undefined}
								<span class="text-xs text-muted-foreground tabular-nums">{t.count}</span>
							{/if}
						</Tabs.Trigger>
					{/each}
				</Tabs.List>
				<div class="min-h-0 flex-1 overflow-y-auto px-5 py-5">
					{@render children()}
				</div>
			</Tabs.Root>
		{:else}
			<div class="min-h-0 flex-1 overflow-y-auto px-5 py-5">
				{@render children()}
			</div>
		{/if}

		{#if saveState !== undefined && !loading && !missing}
			<Sheet.Footer class="border-t px-5 py-3">
				<SaveStatus state={saveState} idleText="Changes save automatically" />
			</Sheet.Footer>
		{/if}
	</Sheet.Content>
</Sheet.Root>
