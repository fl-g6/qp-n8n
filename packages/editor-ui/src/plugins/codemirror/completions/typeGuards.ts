<<<<<<< HEAD
import type { AutocompleteOptionType, FunctionOptionType } from './types';
=======
import { AutocompleteOptionType, FunctionOptionType } from './types';
>>>>>>> master

export const isFunctionOption = (value: AutocompleteOptionType): value is FunctionOptionType => {
	return value === 'native-function' || value === 'extension-function';
};
