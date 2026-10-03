<script lang="ts">
	import * as InputGroup from '#lib/components/ui/input-group/index.js';
	import {
		CheckIcon,
		CopyIcon,
		SearchIcon,
		DeleteIcon,
		CodeIcon,
		EyeOffIcon,
		EyeIcon,
		DownloadIcon,
		type LucideIcon
	} from '@lucide/svelte';
	import { UseClipboard } from '#lib/hooks/use-clipboard.svelte.js';
	import type { ComponentProps } from 'svelte';
	import type { Textarea } from '#lib/components/ui/textarea/index.js';
	import type { Input } from '#lib/components/ui/input/index.js';

	type Variant = 'copy-input' | 'code-area' | 'search' | 'password';

	interface Props {
		variant: Variant;
		value?: string;
		placeholder?: string;
		readonly?: boolean;
		icon?: {
			copy?: LucideIcon;
			code?: LucideIcon;
		};
		codeHeader?: string;
		truncate?: number;
		class?: string;
		searchResults?: number;
		downloadFilename?: string;
		onSearchClear?: () => void;
		inputProps?: ComponentProps<typeof Input>;
		areaProps?: ComponentProps<typeof Textarea>;
	}

	let {
		variant,
		value = $bindable(''),
		placeholder = '',
		readonly = false,
		icon = { code: CodeIcon },
		codeHeader = 'bash',
		truncate = 0,
		class: className = '',
		searchResults,
		downloadFilename,
		onSearchClear = () => (value = ''),
		inputProps = {},
		areaProps = {}
	}: Props = $props();

	const clipboard = new UseClipboard();

	function handleSearchClear() {
		onSearchClear?.();
		value = '';
	}
	let showPassword = $state(false);

	function handleDownload() {
		if (!downloadFilename || !value) return;

		const blob = new Blob([value], { type: 'text/plain' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = downloadFilename;
		document.body.appendChild(a);
		a.click();
		document.body.removeChild(a);
		URL.revokeObjectURL(url);
	}
</script>

{#if variant === 'copy-input'}
	<InputGroup.Root class={className}>
		{#if icon.copy}
			<InputGroup.Addon>
				<InputGroup.Text class="text-accent-foreground" title={placeholder}>
					<icon.copy />
				</InputGroup.Text>
			</InputGroup.Addon>
		{/if}
		<InputGroup.Input bind:value class="truncate" {placeholder} {readonly} {...inputProps} />
		<InputGroup.Addon align="inline-end">
			<InputGroup.Button
				aria-label="Copy"
				title="Copy"
				size="icon-xs"
				onclick={() => clipboard.copy(value)}
			>
				{#if clipboard.copied}
					<CheckIcon />
				{:else}
					<CopyIcon />
				{/if}
			</InputGroup.Button>
		</InputGroup.Addon>
	</InputGroup.Root>
{:else if variant === 'code-area'}
	<InputGroup.Root>
		<InputGroup.Addon align="block-start" class="flex h-10 items-center justify-between border-b">
			<InputGroup.Text class="font-sm font-mono">
				<icon.code />
				{codeHeader}
			</InputGroup.Text>
			<div class="flex items-center gap-2">
				<InputGroup.Button
					aria-label="Copy"
					title="Copy"
					size="icon-xs"
					onclick={() => clipboard.copy(value)}
				>
					{#if clipboard.copied}
						<CheckIcon />
					{:else}
						<CopyIcon />
					{/if}
				</InputGroup.Button>
				{#if downloadFilename}
					<InputGroup.Button
						aria-label="Download"
						title="Download"
						size="icon-xs"
						onclick={handleDownload}
					>
						<DownloadIcon />
					</InputGroup.Button>
				{/if}
			</div>
		</InputGroup.Addon>
		{#if truncate > 0}
			<InputGroup.Textarea
				value={value.slice(0, truncate) + '...'}
				class="max-w-full overflow-x-hidden font-mono break-all whitespace-pre-wrap"
				{placeholder}
				{readonly}
				{...areaProps}
			/>
		{:else}
			<InputGroup.Textarea
				bind:value
				class="max-w-full overflow-x-hidden pb-8 font-mono break-all whitespace-pre-wrap"
				{placeholder}
				{readonly}
				{...areaProps}
			/>
		{/if}
	</InputGroup.Root>
{:else if variant === 'search'}
	<InputGroup.Root class={className}>
		<InputGroup.Input bind:value placeholder={placeholder || 'Search...'} {...inputProps} />
		<InputGroup.Addon align="inline-end">
			{#if value}
				{#if searchResults}
					<span class="text-xs text-muted-foreground">
						{searchResults}
						{searchResults === 1 ? 'result' : 'results'}
					</span>
				{/if}
				<InputGroup.Button variant="ghost" size="icon-xs" onclick={handleSearchClear}>
					<DeleteIcon />
				</InputGroup.Button>
			{/if}
		</InputGroup.Addon>
		<InputGroup.Addon>
			<SearchIcon />
		</InputGroup.Addon>
	</InputGroup.Root>
{:else if variant === 'password'}
	<InputGroup.Root class={className}>
		<InputGroup.Input
			type={showPassword ? 'text' : 'password'}
			bind:value
			placeholder={placeholder || 'Enter your password'}
			{...inputProps}
		/>
		<InputGroup.Addon align="inline-end">
			<InputGroup.Button
				aria-label="Show password"
				title="Show password"
				variant="ghost"
				size="icon-xs"
				class="h-7 w-7"
				onclick={() => (showPassword = !showPassword)}
			>
				{#if showPassword}
					<EyeIcon size={16} />
				{:else}
					<EyeOffIcon size={16} />
				{/if}
			</InputGroup.Button>
		</InputGroup.Addon>
	</InputGroup.Root>
{/if}
