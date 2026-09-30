<script lang="ts">
	import * as Avatar from '$lib/components/ui/avatar';
	import {
		getBoolean,
		getContrast,
		getRandomColor,
		getUnit,
		hashCode
	} from './boring-avatars-utils';
	import type { HTMLAttributes } from 'svelte/elements';

	export type Variant = 'pixel' | 'marble' | 'beam' | 'bauhaus';

	interface Props extends HTMLAttributes<HTMLDivElement> {
		id?: string;
		variant?: Variant;
		colors?: string[];
	}
	let {
		id = '',
		variant = 'marble',
		colors = ['#093C5D', '#3B7597', '#6FD1D7', '#5DF8D8'],
		...restProps
	}: Props = $props();

	const PIXEL_ELEMENTS = 64;
	const PIXEL_SIZE = 80;

	const rectCoords = [
		[0, 0],
		[20, 0],
		[40, 0],
		[60, 0],
		[10, 0],
		[30, 0],
		[50, 0],
		[70, 0],
		[0, 10],
		[0, 20],
		[0, 30],
		[0, 40],
		[0, 50],
		[0, 60],
		[0, 70],
		[20, 10],
		[20, 20],
		[20, 30],
		[20, 40],
		[20, 50],
		[20, 60],
		[20, 70],
		[40, 10],
		[40, 20],
		[40, 30],
		[40, 40],
		[40, 50],
		[40, 60],
		[40, 70],
		[60, 10],
		[60, 20],
		[60, 30],
		[60, 40],
		[60, 50],
		[60, 60],
		[60, 70],
		[10, 10],
		[10, 20],
		[10, 30],
		[10, 40],
		[10, 50],
		[10, 60],
		[10, 70],
		[30, 10],
		[30, 20],
		[30, 30],
		[30, 40],
		[30, 50],
		[30, 60],
		[30, 70],
		[50, 10],
		[50, 20],
		[50, 30],
		[50, 40],
		[50, 50],
		[50, 60],
		[50, 70],
		[70, 10],
		[70, 20],
		[70, 30],
		[70, 40],
		[70, 50],
		[70, 60],
		[70, 70]
	];

	const MARBLE_ELEMENTS = 3;
	const MARBLE_SIZE = 80;

	const BEAM_SIZE = 36;

	const BAUHAUS_ELEMENTS = 4;
	const BAUHAUS_SIZE = 80;

	function genPixel(name: string, colors: string[]) {
		const num = hashCode(name);
		const range = colors.length;
		return Array.from({ length: PIXEL_ELEMENTS }, (_, i) => {
			const index = (num % (i + 1)) % range;
			return colors[index];
		});
	}

	function genMarble(name: string, colors: string[]) {
		const num = hashCode(name);
		const range = colors.length;
		return Array.from({ length: MARBLE_ELEMENTS }, (_, i) => ({
			color: getRandomColor(num + i, colors, range),
			translateX: getUnit(num * (i + 1), MARBLE_SIZE / 10, 1),
			translateY: getUnit(num * (i + 1), MARBLE_SIZE / 10, 2),
			scale: 1.2 + getUnit(num * (i + 1), MARBLE_SIZE / 20) / 10,
			rotate: getUnit(num * (i + 1), 360, 1)
		}));
	}

	function genBeam(name: string, colors: string[]) {
		const num = hashCode(name);
		const range = colors.length;
		const wrapperColor = getRandomColor(num, colors, range);
		const preX = getUnit(num, 10, 1);
		const wx = preX < 5 ? preX + BEAM_SIZE / 9 : preX;
		const preY = getUnit(num, 10, 2);
		const wy = preY < 5 ? preY + BEAM_SIZE / 9 : preY;
		return {
			wrapperColor,
			faceColor: getContrast(wrapperColor),
			backgroundColor: getRandomColor(num + 13, colors, range),
			wrapperTranslateX: wx,
			wrapperTranslateY: wy,
			wrapperRotate: getUnit(num, 360),
			wrapperScale: 1 + getUnit(num, BEAM_SIZE / 12) / 10,
			isMouthOpen: getBoolean(num, 2),
			isCircle: getBoolean(num, 1),
			eyeSpread: getUnit(num, 5),
			mouthSpread: getUnit(num, 3),
			faceRotate: getUnit(num, 10, 3),
			faceTranslateX: wx > BEAM_SIZE / 6 ? wx / 2 : getUnit(num, 8, 1),
			faceTranslateY: wy > BEAM_SIZE / 6 ? wy / 2 : getUnit(num, 7, 2)
		};
	}

	function genBauhaus(name: string, colors: string[]) {
		const num = hashCode(name);
		const range = colors.length;
		return Array.from({ length: BAUHAUS_ELEMENTS }, (_, i) => ({
			color: getRandomColor(num + i, colors, range),
			translateX: getUnit(num * (i + 1), BAUHAUS_SIZE / 2 - (i + 17), 1),
			translateY: getUnit(num * (i + 1), BAUHAUS_SIZE / 2 - (i + 17), 2),
			rotate: getUnit(num * (i + 1), 360),
			isSquare: getBoolean(num, 2)
		}));
	}

	let pixelColors = $derived(genPixel(id, colors));
	let marbleProps = $derived(genMarble(id, colors));
	let beamData = $derived(genBeam(id, colors));
	let bauhausProps = $derived(genBauhaus(id, colors));

	const maskId = `mask__avatar_${Math.random().toString(36).slice(2)}`;
</script>

<Avatar.Root {...restProps}>
	<Avatar.Fallback class="bg-transparent">
		{#if variant === 'pixel'}
			<svg
				viewBox="0 0 {PIXEL_SIZE} {PIXEL_SIZE}"
				fill="none"
				role="img"
				xmlns="http://www.w3.org/2000/svg"
				width="100%"
				height="100%"
				class="h-full! w-full! rounded-full"
			>
				<mask
					id={maskId}
					maskUnits="userSpaceOnUse"
					x={0}
					y={0}
					width={PIXEL_SIZE}
					height={PIXEL_SIZE}
				>
					<rect width={PIXEL_SIZE} height={PIXEL_SIZE} fill="#FFFFFF" rx={PIXEL_SIZE * 2} />
				</mask>
				<g mask="url(#{maskId})">
					{#each rectCoords as [x, y], i}
						<rect {x} {y} width={10} height={10} fill={pixelColors[i]} />
					{/each}
				</g>
			</svg>
		{:else if variant === 'marble'}
			<svg
				viewBox="0 0 {MARBLE_SIZE} {MARBLE_SIZE}"
				fill="none"
				role="img"
				xmlns="http://www.w3.org/2000/svg"
				width="100%"
				height="100%"
				class="h-full! w-full! rounded-full"
			>
				<mask
					id={maskId}
					maskUnits="userSpaceOnUse"
					x={0}
					y={0}
					width={MARBLE_SIZE}
					height={MARBLE_SIZE}
				>
					<rect width={MARBLE_SIZE} height={MARBLE_SIZE} rx={MARBLE_SIZE * 2} fill="#FFFFFF" />
				</mask>
				<g mask="url(#{maskId})">
					<rect width={MARBLE_SIZE} height={MARBLE_SIZE} fill={marbleProps[0].color} />
					<path
						filter="url(#filter_{maskId})"
						d="M32.414 59.35L50.376 70.5H72.5v-71H33.728L26.5 13.381l19.057 27.08L32.414 59.35z"
						fill={marbleProps[1].color}
						transform="translate({marbleProps[1].translateX} {marbleProps[1]
							.translateY}) rotate({marbleProps[1].rotate} {MARBLE_SIZE / 2} {MARBLE_SIZE /
							2}) scale({marbleProps[2].scale})"
					/>
					<path
						filter="url(#filter_{maskId})"
						style="mix-blend-mode: overlay"
						d="M22.216 24L0 46.75l14.108 38.129L78 86l-3.081-59.276-22.378 4.005 12.972 20.186-23.35 27.395L22.215 24z"
						fill={marbleProps[2].color}
						transform="translate({marbleProps[2].translateX} {marbleProps[2]
							.translateY}) rotate({marbleProps[2].rotate} {MARBLE_SIZE / 2} {MARBLE_SIZE /
							2}) scale({marbleProps[2].scale})"
					/>
				</g>
				<defs>
					<filter
						id="filter_{maskId}"
						filterUnits="userSpaceOnUse"
						color-interpolation-filters="sRGB"
					>
						<feFlood flood-opacity={0} result="BackgroundImageFix" />
						<feBlend in="SourceGraphic" in2="BackgroundImageFix" result="shape" />
						<feGaussianBlur stdDeviation={7} result="effect1_foregroundBlur" />
					</filter>
				</defs>
			</svg>
		{:else if variant === 'beam'}
			<svg
				viewBox="0 0 {BEAM_SIZE} {BEAM_SIZE}"
				fill="none"
				role="img"
				xmlns="http://www.w3.org/2000/svg"
				width="100%"
				height="100%"
				class="h-full! w-full! rounded-full"
			>
				<mask
					id={maskId}
					maskUnits="userSpaceOnUse"
					x={0}
					y={0}
					width={BEAM_SIZE}
					height={BEAM_SIZE}
				>
					<rect width={BEAM_SIZE} height={BEAM_SIZE} rx={BEAM_SIZE * 2} fill="#FFFFFF" />
				</mask>
				<g mask="url(#{maskId})">
					<rect width={BEAM_SIZE} height={BEAM_SIZE} fill={beamData.backgroundColor} />
					<rect
						x="0"
						y="0"
						width={BEAM_SIZE}
						height={BEAM_SIZE}
						transform="translate({beamData.wrapperTranslateX} {beamData.wrapperTranslateY}) rotate({beamData.wrapperRotate} {BEAM_SIZE /
							2} {BEAM_SIZE / 2}) scale({beamData.wrapperScale})"
						fill={beamData.wrapperColor}
						rx={beamData.isCircle ? BEAM_SIZE : BEAM_SIZE / 6}
					/>
					<g
						transform="translate({beamData.faceTranslateX} {beamData.faceTranslateY}) rotate({beamData.faceRotate} {BEAM_SIZE /
							2} {BEAM_SIZE / 2})"
					>
						{#if beamData.isMouthOpen}
							<path
								d="M15 {19 + beamData.mouthSpread}c2 1 4 1 6 0"
								stroke={beamData.faceColor}
								fill="none"
								stroke-linecap="round"
							/>
						{:else}
							<path
								d="M13,{19 + beamData.mouthSpread} a1,0.75 0 0,0 10,0"
								fill={beamData.faceColor}
							/>
						{/if}
						<rect
							x={14 - beamData.eyeSpread}
							y={14}
							width={1.5}
							height={2}
							rx={1}
							stroke="none"
							fill={beamData.faceColor}
						/>
						<rect
							x={20 + beamData.eyeSpread}
							y={14}
							width={1.5}
							height={2}
							rx={1}
							stroke="none"
							fill={beamData.faceColor}
						/>
					</g>
				</g>
			</svg>
		{:else if variant === 'bauhaus'}
			<svg
				viewBox="0 0 {BAUHAUS_SIZE} {BAUHAUS_SIZE}"
				fill="none"
				role="img"
				xmlns="http://www.w3.org/2000/svg"
				width="100%"
				height="100%"
				class="h-full! w-full! rounded-full"
			>
				<mask
					id={maskId}
					maskUnits="userSpaceOnUse"
					x={0}
					y={0}
					width={BAUHAUS_SIZE}
					height={BAUHAUS_SIZE}
				>
					<rect width={BAUHAUS_SIZE} height={BAUHAUS_SIZE} rx={BAUHAUS_SIZE * 2} fill="#FFFFFF" />
				</mask>
				<g mask="url(#{maskId})">
					<rect width={BAUHAUS_SIZE} height={BAUHAUS_SIZE} fill={bauhausProps[0].color} />
					<rect
						x={(BAUHAUS_SIZE - 60) / 2}
						y={(BAUHAUS_SIZE - 20) / 2}
						width={BAUHAUS_SIZE}
						height={bauhausProps[1].isSquare ? BAUHAUS_SIZE : BAUHAUS_SIZE / 8}
						fill={bauhausProps[1].color}
						transform="translate({bauhausProps[1].translateX} {bauhausProps[1]
							.translateY}) rotate({bauhausProps[1].rotate} {BAUHAUS_SIZE / 2} {BAUHAUS_SIZE / 2})"
					/>
					<circle
						cx={BAUHAUS_SIZE / 2}
						cy={BAUHAUS_SIZE / 2}
						fill={bauhausProps[2].color}
						r={BAUHAUS_SIZE / 5}
						transform="translate({bauhausProps[2].translateX} {bauhausProps[2].translateY})"
					/>
					<line
						x1={0}
						y1={BAUHAUS_SIZE / 2}
						x2={BAUHAUS_SIZE}
						y2={BAUHAUS_SIZE / 2}
						stroke-width={2}
						stroke={bauhausProps[3].color}
						transform="translate({bauhausProps[3].translateX} {bauhausProps[3]
							.translateY}) rotate({bauhausProps[3].rotate} {BAUHAUS_SIZE / 2} {BAUHAUS_SIZE / 2})"
					/>
				</g>
			</svg>
		{/if}
	</Avatar.Fallback>
</Avatar.Root>
