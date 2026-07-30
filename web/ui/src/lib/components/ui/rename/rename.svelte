<script lang="ts" module>
	export type RenameProps<TagName extends TextElementTagNames> = {
		id?: string;
		this: TagName;
		inputTag?: 'input' | 'textarea';
		mode?: 'edit' | 'view';
		blurBehavior?: 'exit' | 'save' | 'none';
		fallbackSelectionBehavior?: 'start' | 'end' | 'all';
		value: string;
		/** Applied first to both the input and text elements*/
		class?: string;
		/** Applied to the input element, overrides class */
		inputClass?: string;
		/** Applied to the text element, overrides class */
		textClass?: string;
		/** Called when the user saves the value. Return true to accept and edit false to show and invalid state */
		onSave?: (value: string) => void;
		onCancel?: () => void;
		validate?: (value: string) => boolean;
	};
</script>

<script lang="ts" generics="TagName extends TextElementTagNames">
	import { cn } from '$lib/utils.js';
	import { box } from 'svelte-toolbelt';
	import { useRenameInput } from './rename.svelte.js';
	import type { TextElementTagNames } from './types.js';

	const uid = $props.id();

	let {
		id = uid,
		this: tagName,
		inputTag = 'input',
		mode = $bindable('view'),
		value = $bindable(),
		class: className,
		blurBehavior = 'save',
		fallbackSelectionBehavior = 'end',
		inputClass,
		textClass,
		onSave = () => {},
		onCancel = () => {},
		validate = () => true
	}: RenameProps<TagName> = $props();

	let inputRef = $state<HTMLInputElement | HTMLTextAreaElement | null>(null);
	let textRef = $state<HTMLElement | null>(null);

	const rootState = useRenameInput({
		id: box.with(() => id),
		mode: box.with(
			() => mode,
			(v) => (mode = v)
		),
		value: box.with(
			() => value,
			(v) => (value = v)
		),
		inputRef: box.with(
			() => inputRef,
			(v) => (inputRef = v)
		),
		textRef: box.with(
			() => textRef,
			(v) => (textRef = v)
		),
		onSave: box.with(() => onSave),
		onCancel: box.with(() => onCancel),
		blurBehavior: box.with(() => blurBehavior),
		validate: box.with(() => validate),
		fallbackSelectionBehavior: box.with(() => fallbackSelectionBehavior)
	});

	const commonClass = cn('w-full min-w-0 text-base');

	const inputProps = $derived({
		'data-mode': 'edit',
		id,
		class: cn(
			commonClass,
			'h-8 w-full min-w-0 rounded-lg border border-input bg-transparent px-2.5 py-1 text-base transition-colors outline-none file:inline-flex file:h-6 file:border-0 file:bg-transparent file:text-sm file:font-medium file:text-foreground placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 disabled:pointer-events-none disabled:cursor-not-allowed disabled:bg-input/50 disabled:opacity-50 aria-invalid:border-destructive aria-invalid:ring-3 aria-invalid:ring-destructive/20 md:text-sm dark:bg-input/30 dark:disabled:bg-input/80 dark:aria-invalid:border-destructive/50 dark:aria-invalid:ring-destructive/40',
			className,
			inputClass
		),
		'aria-invalid': rootState.invalid,
		onkeydown: rootState.onInputKeydown,
		onblur: rootState.onInputBlur
	});
</script>

{#if mode === 'edit'}
	{#if inputTag === 'textarea'}
		<textarea bind:this={inputRef} bind:value={rootState.editingValue} {...inputProps}></textarea>
	{:else}
		<input
			bind:this={inputRef}
			type="text"
			autocomplete="off"
			bind:value={rootState.editingValue}
			{...inputProps}
		/>
	{/if}
{:else if mode === 'view'}
	<!-- svelte-ignore a11y_no_static_element_interactions -->
	<svelte:element
		this={tagName as never}
		{id}
		data-mode="view"
		class={cn(commonClass, className, textClass)}
		onclick={rootState.onTextClick}
		bind:this={textRef}
	>
		{value}
	</svelte:element>
{/if}
