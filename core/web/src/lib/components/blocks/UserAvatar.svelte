<script lang="ts">
	import * as Avatar from '#lib/components/ui/avatar/index.js';
	import type { User } from '#lib/gen/nokku/v1/account_pb.js';
	import type { ComponentProps } from 'svelte';
	import {
		avatarColors,
		getBoolean,
		getContrast,
		getRandomColor,
		getUnit,
		hashCode
	} from './boring-avatars-utils';

	interface Props extends ComponentProps<typeof Avatar.Root> {
		user?: User;
		colors?: string[];
	}
	let { user, colors = avatarColors, ...restProps }: Props = $props();

	const SIZE = 32;

	const maskId = `mask__beam_${Math.random().toString(36).slice(2)}`;

	function generateData(name: string, colors: string[]) {
		const numFromName = hashCode(name);
		const range = colors.length;
		const wrapperColor = getRandomColor(numFromName, colors, range);

		const preTranslateX = getUnit(numFromName, 10, 1);
		const wrapperTranslateX = preTranslateX < 5 ? preTranslateX + SIZE / 9 : preTranslateX;

		const preTranslateY = getUnit(numFromName, 10, 2);
		const wrapperTranslateY = preTranslateY < 5 ? preTranslateY + SIZE / 9 : preTranslateY;

		return {
			wrapperColor,
			faceColor: getContrast(wrapperColor),
			backgroundColor: getRandomColor(numFromName + 13, colors, range),
			wrapperTranslateX,
			wrapperTranslateY,
			wrapperRotate: getUnit(numFromName, 360),
			wrapperScale: 1 + getUnit(numFromName, SIZE / 12) / 10,
			isMouthOpen: getBoolean(numFromName, 2),
			isCircle: getBoolean(numFromName, 1),
			eyeSpread: getUnit(numFromName, 5),
			mouthSpread: getUnit(numFromName, 3),
			faceRotate: getUnit(numFromName, 10, 3),
			faceTranslateX:
				wrapperTranslateX > SIZE / 6 ? wrapperTranslateX / 2 : getUnit(numFromName, 8, 1),
			faceTranslateY:
				wrapperTranslateY > SIZE / 6 ? wrapperTranslateY / 2 : getUnit(numFromName, 7, 2)
		};
	}

	let data = $derived(generateData(user?.email || '', colors));
</script>

<Avatar.Root {...restProps}>
	<Avatar.Image src={user?.picture} alt={user?.name || user?.email} referrerpolicy="no-referrer" />
	<Avatar.Fallback class="bg-transparent">
		<svg
			viewBox="0 0 {SIZE} {SIZE}"
			fill="none"
			xmlns="http://www.w3.org/2000/svg"
			width="100%"
			height="100%"
			class="h-full! w-full! rounded-full"
		>
			<mask id={maskId} maskUnits="userSpaceOnUse" x={0} y={0} width={SIZE} height={SIZE}>
				<rect width={SIZE} height={SIZE} fill="white" />
			</mask>
			<g mask="url(#{maskId})">
				<rect width={SIZE} height={SIZE} fill={data.backgroundColor} />
				<rect
					x="0"
					y="0"
					width={SIZE}
					height={SIZE}
					transform="translate({data.wrapperTranslateX} {data.wrapperTranslateY}) rotate({data.wrapperRotate} {SIZE /
						2} {SIZE / 2}) scale({data.wrapperScale})"
					fill={data.wrapperColor}
					rx={data.isCircle ? SIZE : SIZE / 6}
				/>
				<g
					transform="translate({data.faceTranslateX} {data.faceTranslateY}) rotate({data.faceRotate} {SIZE /
						2} {SIZE / 2})"
				>
					{#if data.isMouthOpen}
						<path
							d="M15 {19 + data.mouthSpread}c2 1 4 1 6 0"
							stroke={data.faceColor}
							fill="none"
							stroke-linecap="round"
						/>
					{:else}
						<path d="M13,{19 + data.mouthSpread} a1,0.75 0 0,0 10,0" fill={data.faceColor} />
					{/if}

					<rect
						x={14 - data.eyeSpread}
						y={14}
						width={1.5}
						height={2}
						rx={1}
						stroke="none"
						fill={data.faceColor}
					/>
					<rect
						x={20 + data.eyeSpread}
						y={14}
						width={1.5}
						height={2}
						rx={1}
						stroke="none"
						fill={data.faceColor}
					/>
				</g>
			</g>
		</svg>
	</Avatar.Fallback>
</Avatar.Root>
