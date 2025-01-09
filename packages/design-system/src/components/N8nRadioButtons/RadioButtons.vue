<script lang="ts" setup generic="Value extends string">
import RadioButton from './RadioButton.vue';

interface RadioOption {
	label: string;
	value: Value;
	disabled?: boolean;
}

interface RadioButtonsProps {
	modelValue?: Value;
	options?: RadioOption[];
	/** @default medium */
	size?: 'small' | 'medium';
	disabled?: boolean;
}

const props = withDefaults(defineProps<RadioButtonsProps>(), {
	active: false,
	disabled: false,
	size: 'medium',
});

const emit = defineEmits<{
	'update:modelValue': [value: Value, e: MouseEvent];
}>();

const onClick = (
	option: { label: string; value: Value; disabled?: boolean },
	event: MouseEvent,
) => {
	if (props.disabled || option.disabled) {
		return;
	}
	emit('update:modelValue', option.value, event);
};
</script>

<template>
	<div
		role="radiogroup"
		:class="{ 'n8n-radio-buttons': true, [$style.radioGroup]: true, [$style.disabled]: disabled }"
	>
		<RadioButton
			v-for="option in options"
			:key="option.value"
			v-bind="option"
			:active="modelValue === option.value"
			:size="size"
			:disabled="disabled || option.disabled"
			@click.prevent.stop="onClick(option, $event)"
		/>
	</div>
</template>

<<<<<<< HEAD
<script lang="ts">
import RadioButton from './RadioButton.vue';

import type { PropType } from 'vue';
import { defineComponent } from 'vue';

export interface RadioOption {
	label: string;
	value: string;
	disabled?: boolean;
}

export default defineComponent({
	name: 'N8nRadioButtons',
	components: {
		RadioButton,
	},
	props: {
		modelValue: {
			type: String,
		},
		options: {
			type: Array as PropType<RadioOption[]>,
			default: (): RadioOption[] => [],
		},
		size: {
			type: String,
		},
		disabled: {
			type: Boolean,
		},
	},
	emits: ['update:modelValue'],
	methods: {
		onClick(option: { label: string; value: string; disabled?: boolean }, event: MouseEvent) {
			if (this.disabled || option.disabled) {
				return;
			}
			this.$emit('update:modelValue', option.value, event);
		},
	},
});
</script>

=======
>>>>>>> tags/n8n@1.74.1
<style lang="scss" module>
.radioGroup {
	display: inline-flex;
	line-height: 1;
	vertical-align: middle;
	font-size: 0;
	background-color: var(--color-foreground-base);
	padding: var(--spacing-5xs);
	border-radius: var(--border-radius-base);
}

.disabled {
	cursor: not-allowed;
}
</style>
