import type { ElTooltipProps } from 'element-plus';
import type { AnchorHTMLAttributes } from 'vue';
import type { RouteLocationRaw, RouterLinkProps } from 'vue-router';

export type IMenuItem = {
	id: string;
	label: string;
	icon?: string | { type: 'icon' | 'emoji'; value: string };
	secondaryIcon?: {
		name: string;
<<<<<<< HEAD
		size?: 'xsmall' | 'small' | 'medium' | 'large' | 'xlarge';
=======
		size?: 'xsmall' | 'small' | 'medium' | 'large';
>>>>>>> tags/n8n@1.74.1
		tooltip?: Partial<ElTooltipProps>;
	};
	customIconSize?: 'medium' | 'small';
	available?: boolean;
	position?: 'top' | 'bottom';

	/** Use this for external links */
	link?: ILinkMenuItemProperties;
	/** Use this for defining a vue-router target */
	route?: RouterLinkProps;
	/**
	 * If given, item will be activated on these route names. Note that if
	 * route is provided, it will be highlighted automatically
	 */
	activateOnRouteNames?: string[];
	activateOnRoutePaths?: string[];

	children?: IMenuItem[];
	isLoading?: boolean;
	disabled?: boolean;
};

export type IRouteMenuItemProperties = {
	route: RouteLocationRaw;
};

export type IRouteMenuItemProperties = {
	route: RouteLocationRaw;
};

export type ILinkMenuItemProperties = {
	href: string;
	target?: AnchorHTMLAttributes['target'];
	rel?: AnchorHTMLAttributes['rel'];
};
