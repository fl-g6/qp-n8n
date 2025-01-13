import type { INodeProperties } from 'n8n-workflow';
import { cronNodeOptions } from 'n8n-workflow';

const { NODE_ENV } = process.env;
export const inProduction = NODE_ENV === 'production';
export const inDevelopment = !NODE_ENV || NODE_ENV === 'development';

export const CUSTOM_EXTENSION_ENV = 'N8N_CUSTOM_EXTENSIONS';
export const PLACEHOLDER_EMPTY_EXECUTION_ID = '__UNKNOWN__';
export const PLACEHOLDER_EMPTY_WORKFLOW_ID = '__EMPTY__';
export const HTTP_REQUEST_NODE_TYPE = 'n8n-nodes-base.httpRequest';
export const HTTP_REQUEST_TOOL_NODE_TYPE = '@n8n/n8n-nodes-langchain.toolHttpRequest';

export const CUSTOM_NODES_CATEGORY = 'Custom Nodes';

export const RESTRICT_FILE_ACCESS_TO = 'N8N_RESTRICT_FILE_ACCESS_TO';
export const BLOCK_FILE_ACCESS_TO_N8N_FILES = 'N8N_BLOCK_FILE_ACCESS_TO_N8N_FILES';
export const CONFIG_FILES = 'N8N_CONFIG_FILES';
export const BINARY_DATA_STORAGE_PATH = 'N8N_BINARY_DATA_STORAGE_PATH';
export const UM_EMAIL_TEMPLATES_INVITE = 'N8N_UM_EMAIL_TEMPLATES_INVITE';
export const UM_EMAIL_TEMPLATES_PWRESET = 'N8N_UM_EMAIL_TEMPLATES_PWRESET';

export const JWT_AUTH_ACTIVE = 'N8N_JWT_AUTH_ACTIVE';
export const JWT_AUTH_HEADER = 'N8N_JWT_AUTH_HEADER';
export const JWT_AUTH_HEADER_VALUE_PREFIX = 'N8N_JWT_AUTH_HEADER_VALUE_PREFIX';
export const JWT_JWKS_URI = 'N8N_JWKS_URI';
export const JWT_ISSUER = 'N8N_JWT_ISSUER';
export const JWT_NAMESPACE = 'N8N_JWT_NAMESPACE';
export const JWT_ALLOWED_TENANT_KEY = 'N8N_JWT_ALLOWED_TENANT_KEY';
export const JWT_ALLOWED_TENANT = 'N8N_JWT_ALLOWED_TENANT';

export const commonPollingParameters: INodeProperties[] = [
	{
		displayName: 'Poll Times',
		name: 'pollTimes',
		type: 'fixedCollection',
		typeOptions: {
			multipleValues: true,
			multipleValueButtonText: 'Add Poll Time',
		},
		default: { item: [{ mode: 'everyMinute' }] },
		description: 'Time at which polling should occur',
		placeholder: 'Add Poll Time',
		options: cronNodeOptions,
	},
];

export const commonCORSParameters: INodeProperties[] = [
	{
		displayName: 'Allowed Origins (CORS)',
		name: 'allowedOrigins',
		type: 'string',
		default: '*',
		description:
			'Comma-separated list of URLs allowed for cross-origin non-preflight requests. Use * (default) to allow all origins.',
	},
];
