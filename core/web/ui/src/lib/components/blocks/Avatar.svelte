<script lang="ts">
	import * as Avatar from '#lib/components/ui/avatar/index.js';
	import { avatarColors, getRandomColor, getUnit, hashCode } from './boring-avatars-utils';
	import type { HTMLAttributes } from 'svelte/elements';

	interface Props extends HTMLAttributes<HTMLDivElement> {
		id?: string;
		colors?: string[];
	}
	let { id = '', colors = avatarColors, ...restProps }: Props = $props();

	const MARBLE_ELEMENTS = 3;
	const MARBLE_SIZE = 80;

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

	const marbleProps = $derived(genMarble(id, colors));

	const maskId = `mask__avatar_${Math.random().toString(36).slice(2)}`;
</script>

<Avatar.Root {...restProps}>
	<Avatar.Fallback class="bg-transparent">
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
	</Avatar.Fallback>
</Avatar.Root>
