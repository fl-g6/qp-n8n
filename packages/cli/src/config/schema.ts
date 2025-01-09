import { GlobalConfig } from '@n8n/config';
import { Container } from '@n8n/di';
import convict from 'convict';
import { InstanceSettings } from 'n8n-core';
import path from 'path';

import { ensureStringArray } from './utils';

convict.addFormat({
	name: 'comma-separated-list',
	coerce: (rawStr: string) => rawStr.split(','),
	validate: ensureStringArray,
});

export const schema = {
	executions: {
		// TODO: remove this and all usage of `executions.process` when we're sure that nobody has this in their config file anymore.
		process: {
			doc: 'Deprecated key, that will be removed in the future. Please remove it from your configuration and environment variables to prevent issues in the future.',
			format: String,
			default: '',
			env: 'EXECUTIONS_PROCESS',
		},
		mode: {
			doc: 'If it should run executions directly or via queue',
			format: ['regular', 'queue'] as const,
			default: 'regular',
			env: 'EXECUTIONS_MODE',
		},

		concurrency: {
			productionLimit: {
				doc: "Max production executions allowed to run concurrently, in main process for regular mode and in worker for queue mode. Default for main mode is `-1` (disabled). Default for queue mode is taken from the worker's `--concurrency` flag.",
				format: Number,
				default: -1,
				env: 'N8N_CONCURRENCY_PRODUCTION_LIMIT',
			},
		},

		// A Workflow times out and gets canceled after this time (seconds).
		// If the workflow is executed in the main process a soft timeout
		// is executed (takes effect after the current node finishes).
		// If a workflow is running in its own process is a soft timeout
		// tried first, before killing the process after waiting for an
		// additional fifth of the given timeout duration.
		//
		// To deactivate timeout set it to -1
		//
		// Timeout is currently not activated by default which will change
		// in a future version.
		timeout: {
			doc: 'Max run time (seconds) before stopping the workflow execution',
			format: Number,
			default: -1,
			env: 'EXECUTIONS_TIMEOUT',
		},
		maxTimeout: {
			doc: 'Max execution time (seconds) that can be set for a workflow individually',
			format: Number,
			default: 3600,
			env: 'EXECUTIONS_TIMEOUT_MAX',
		},

		// If a workflow executes all the data gets saved by default. This
		// could be a problem when a workflow gets executed a lot and processes
		// a lot of data. To not exceed the database's capacity it is possible to
		// prune the database regularly or to not save the execution at all.
		// Depending on if the execution did succeed or error a different
		// save behaviour can be set.
		saveDataOnError: {
			doc: 'What workflow execution data to save on error',
			format: ['all', 'none'] as const,
			default: 'all',
			env: 'EXECUTIONS_DATA_SAVE_ON_ERROR',
		},
		saveDataOnSuccess: {
			doc: 'What workflow execution data to save on success',
			format: ['all', 'none'] as const,
			default: 'all',
			env: 'EXECUTIONS_DATA_SAVE_ON_SUCCESS',
		},
		saveExecutionProgress: {
			doc: 'Whether or not to save progress for each node executed',
			format: Boolean,
			default: false,
			env: 'EXECUTIONS_DATA_SAVE_ON_PROGRESS',
		},

		// If the executions of workflows which got started via the editor
		// should be saved. By default they will not be saved as this runs
		// are normally only for testing and debugging. This setting can
		// also be overwritten on a per workflow basis in the workflow settings
		// in the editor.
		saveDataManualExecutions: {
			doc: 'Save data of executions when started manually via editor',
			format: Boolean,
			default: true,
			env: 'EXECUTIONS_DATA_SAVE_MANUAL_EXECUTIONS',
		},

		queueRecovery: {
			interval: {
				doc: 'How often (minutes) to check for queue recovery',
				format: Number,
				default: 180,
				env: 'N8N_EXECUTIONS_QUEUE_RECOVERY_INTERVAL',
			},
			batchSize: {
				doc: 'Size of batch of executions to check for queue recovery',
				format: Number,
				default: 100,
				env: 'N8N_EXECUTIONS_QUEUE_RECOVERY_BATCH',
			},
		},
	},

	secure_cookie: {
		doc: 'This sets the `Secure` flag on n8n auth cookie',
		format: Boolean,
		default: true,
		env: 'N8N_SECURE_COOKIE',
	},
	ssl_key: {
		format: String,
		default: '',
		env: 'N8N_SSL_KEY',
		doc: 'SSL Key for HTTPS Protocol',
	},
	ssl_cert: {
		format: String,
		default: '',
		env: 'N8N_SSL_CERT',
		doc: 'SSL Cert for HTTPS Protocol',
	},
	editorBaseUrl: {
		format: String,
		default: '',
		env: 'N8N_EDITOR_BASE_URL',
		doc: 'Public URL where the editor is accessible. Also used for emails sent from n8n.',
	},

<<<<<<< HEAD
	security: {
		restrictFileAccessTo: {
			doc: 'If set only files in that directories can be accessed. Multiple directories can be separated by semicolon (";").',
			format: String,
			default: '',
			env: 'N8N_RESTRICT_FILE_ACCESS_TO',
		},
		blockFileAccessToN8nFiles: {
			doc: 'If set to true it will block access to all files in the ".n8n" directory and user defined config files.',
			format: Boolean,
			default: true,
			env: 'N8N_BLOCK_FILE_ACCESS_TO_N8N_FILES',
		},
		audit: {
			daysAbandonedWorkflow: {
				doc: 'Days for a workflow to be considered abandoned if not executed',
				format: Number,
				default: 90,
				env: 'N8N_SECURITY_AUDIT_DAYS_ABANDONED_WORKFLOW',
			},
		},
		excludeEndpoints: {
			doc: 'Additional endpoints to exclude auth checks. Multiple endpoints can be separated by colon (":")',
			format: String,
			default: '',
			env: 'N8N_AUTH_EXCLUDE_ENDPOINTS',
		},
		jwtAuth: {
			active: {
				format: 'Boolean',
				default: false,
				env: 'N8N_JWT_AUTH_ACTIVE',
				doc: '[DEPRECATED] If JWT auth should be activated for editor and REST-API',
			},
			jwtHeader: {
				format: String,
				default: '',
				env: 'N8N_JWT_AUTH_HEADER',
				doc: '[DEPRECATED] The request header containing a signed JWT',
			},
			jwtHeaderValuePrefix: {
				format: String,
				default: '',
				env: 'N8N_JWT_AUTH_HEADER_VALUE_PREFIX',
				doc: '[DEPRECATED] The request header value prefix to strip (optional)',
			},
			jwksUri: {
				format: String,
				default: '',
				env: 'N8N_JWKS_URI',
				doc: '[DEPRECATED] The URI to fetch JWK Set for JWT authentication',
			},
			jwtIssuer: {
				format: String,
				default: '',
				env: 'N8N_JWT_ISSUER',
				doc: '[DEPRECATED] JWT issuer to expect (optional)',
			},
			jwtNamespace: {
				format: String,
				default: '',
				env: 'N8N_JWT_NAMESPACE',
				doc: '[DEPRECATED] JWT namespace to expect (optional)',
			},
			jwtAllowedTenantKey: {
				format: String,
				default: '',
				env: 'N8N_JWT_ALLOWED_TENANT_KEY',
				doc: '[DEPRECATED] JWT tenant key name to inspect within JWT namespace (optional)',
			},
			jwtAllowedTenant: {
				format: String,
				default: '',
				env: 'N8N_JWT_ALLOWED_TENANT',
				doc: '[DEPRECATED] JWT tenant to allow (optional)',
			},
		},
	},

	endpoints: {
		payloadSizeMax: {
			format: Number,
			default: 16,
			env: 'N8N_PAYLOAD_SIZE_MAX',
			doc: 'Maximum payload size in MB.',
		},
		metrics: {
			enable: {
				format: Boolean,
				default: false,
				env: 'N8N_METRICS',
				doc: 'Enable /metrics endpoint. Default: false',
			},
			prefix: {
				format: String,
				default: 'n8n_',
				env: 'N8N_METRICS_PREFIX',
				doc: 'An optional prefix for metric names. Default: n8n_',
			},
			includeDefaultMetrics: {
				format: Boolean,
				default: true,
				env: 'N8N_METRICS_INCLUDE_DEFAULT_METRICS',
				doc: 'Whether to expose default system and node.js metrics. Default: true',
			},
			includeWorkflowIdLabel: {
				format: Boolean,
				default: false,
				env: 'N8N_METRICS_INCLUDE_WORKFLOW_ID_LABEL',
				doc: 'Whether to include a label for the workflow ID on workflow metrics. Default: false',
			},
			includeNodeTypeLabel: {
				format: Boolean,
				default: false,
				env: 'N8N_METRICS_INCLUDE_NODE_TYPE_LABEL',
				doc: 'Whether to include a label for the node type on node metrics. Default: false',
			},
			includeCredentialTypeLabel: {
				format: Boolean,
				default: false,
				env: 'N8N_METRICS_INCLUDE_CREDENTIAL_TYPE_LABEL',
				doc: 'Whether to include a label for the credential type on credential metrics. Default: false',
			},
			includeApiEndpoints: {
				format: Boolean,
				default: false,
				env: 'N8N_METRICS_INCLUDE_API_ENDPOINTS',
				doc: 'Whether to expose metrics for API endpoints. Default: false',
			},
			includeApiPathLabel: {
				format: Boolean,
				default: false,
				env: 'N8N_METRICS_INCLUDE_API_PATH_LABEL',
				doc: 'Whether to include a label for the path of API invocations. Default: false',
			},
			includeApiMethodLabel: {
				format: Boolean,
				default: false,
				env: 'N8N_METRICS_INCLUDE_API_METHOD_LABEL',
				doc: 'Whether to include a label for the HTTP method (GET, POST, ...) of API invocations. Default: false',
			},
			includeApiStatusCodeLabel: {
				format: Boolean,
				default: false,
				env: 'N8N_METRICS_INCLUDE_API_STATUS_CODE_LABEL',
				doc: 'Whether to include a label for the HTTP status code (200, 404, ...) of API invocations. Default: false',
			},
			includeCacheMetrics: {
				format: Boolean,
				default: false,
				env: 'N8N_METRICS_INCLUDE_CACHE_METRICS',
				doc: 'Whether to include metrics for cache hits and misses. Default: false',
			},
			includeMessageEventBusMetrics: {
				format: Boolean,
				default: true,
				env: 'N8N_METRICS_INCLUDE_MESSAGE_EVENT_BUS_METRICS',
				doc: 'Whether to include metrics for events. Default: false',
			},
		},
		rest: {
			format: String,
			default: 'rest',
			env: 'N8N_ENDPOINT_REST',
			doc: 'Path for rest endpoint',
		},
		form: {
			format: String,
			default: 'form',
			env: 'N8N_ENDPOINT_FORM',
			doc: 'Path for form endpoint',
		},
		formTest: {
			format: String,
			default: 'form-test',
			env: 'N8N_ENDPOINT_FORM_TEST',
			doc: 'Path for test form endpoint',
		},
		formWaiting: {
			format: String,
			default: 'form-waiting',
			env: 'N8N_ENDPOINT_FORM_WAIT',
			doc: 'Path for waiting form endpoint',
		},
		webhook: {
			format: String,
			default: 'webhook',
			env: 'N8N_ENDPOINT_WEBHOOK',
			doc: 'Path for webhook endpoint',
		},
		webhookWaiting: {
			format: String,
			default: 'webhook-waiting',
			env: 'N8N_ENDPOINT_WEBHOOK_WAIT',
			doc: 'Path for waiting-webhook endpoint',
		},
		webhookTest: {
			format: String,
			default: 'webhook-test',
			env: 'N8N_ENDPOINT_WEBHOOK_TEST',
			doc: 'Path for test-webhook endpoint',
		},
		disableUi: {
			format: Boolean,
			default: false,
			env: 'N8N_DISABLE_UI',
			doc: 'Disable N8N UI (Frontend).',
		},
		disableProductionWebhooksOnMainProcess: {
			format: Boolean,
			default: false,
			env: 'N8N_DISABLE_PRODUCTION_MAIN_PROCESS',
			doc: 'Disable production webhooks from main process. This helps ensures no http traffic load to main process when using webhook-specific processes.',
		},
	},

	publicApi: {
		disabled: {
			format: Boolean,
			default: false,
			env: 'N8N_PUBLIC_API_DISABLED',
			doc: 'Whether to disable the Public API',
		},
		path: {
			format: String,
			default: 'api',
			env: 'N8N_PUBLIC_API_ENDPOINT',
			doc: 'Path for the public api endpoints',
		},
		swaggerUi: {
			disabled: {
				format: Boolean,
				default: false,
				env: 'N8N_PUBLIC_API_SWAGGERUI_DISABLED',
				doc: 'Whether to disable the Swagger UI for the Public API',
			},
		},
	},

=======
>>>>>>> tags/n8n@1.74.1
	workflowTagsDisabled: {
		format: Boolean,
		default: false,
		env: 'N8N_WORKFLOW_TAGS_DISABLED',
		doc: 'Disable workflow tags.',
	},

	userManagement: {
		jwtSecret: {
			doc: 'Set a specific JWT secret (optional - n8n can generate one)', // Generated @ start.ts
			format: String,
			default: '',
			env: 'N8N_USER_MANAGEMENT_JWT_SECRET',
		},
		jwtSessionDurationHours: {
			doc: 'Set a specific expiration date for the JWTs in hours.',
			format: Number,
			default: 168,
			env: 'N8N_USER_MANAGEMENT_JWT_DURATION_HOURS',
		},
		jwtRefreshTimeoutHours: {
			doc: 'How long before the JWT expires to automatically refresh it. 0 means 25% of N8N_USER_MANAGEMENT_JWT_DURATION_HOURS. -1 means it will never refresh, which forces users to login again after the defined period in N8N_USER_MANAGEMENT_JWT_DURATION_HOURS.',
			format: Number,
			default: 0,
			env: 'N8N_USER_MANAGEMENT_JWT_REFRESH_TIMEOUT_HOURS',
		},

		/**
		 * @important Do not remove until after cloud hooks are updated to stop using convict config.
		 */
		isInstanceOwnerSetUp: {
			// n8n loads this setting from DB on startup
			doc: "Whether the instance owner's account has been set up",
			format: Boolean,
			default: false,
		},

		authenticationMethod: {
			doc: 'How to authenticate users (e.g. "email", "ldap", "saml")',
			format: ['email', 'ldap', 'saml'] as const,
			default: 'email',
		},
	},

	externalFrontendHooksUrls: {
		doc: 'URLs to external frontend hooks files, ; separated',
		format: String,
		default: '',
		env: 'EXTERNAL_FRONTEND_HOOKS_URLS',
	},

	externalHookFiles: {
		doc: 'Files containing external hooks. Multiple files can be separated by colon (":")',
		format: String,
		default: '',
		env: 'EXTERNAL_HOOK_FILES',
	},

	push: {
		backend: {
			format: ['sse', 'websocket'] as const,
			default: 'websocket',
			env: 'N8N_PUSH_BACKEND',
			doc: 'Backend to use for push notifications',
		},
	},

	binaryDataManager: {
		availableModes: {
			format: 'comma-separated-list',
			default: 'filesystem',
			env: 'N8N_AVAILABLE_BINARY_DATA_MODES',
			doc: 'Available modes of binary data storage, as comma separated strings',
		},
		mode: {
			format: ['default', 'filesystem', 's3'] as const,
			default: 'default',
			env: 'N8N_DEFAULT_BINARY_DATA_MODE',
			doc: 'Storage mode for binary data',
		},
		localStoragePath: {
			format: String,
			default: path.join(Container.get(InstanceSettings).n8nFolder, 'binaryData'),
			env: 'N8N_BINARY_DATA_STORAGE_PATH',
			doc: 'Path for binary data storage in "filesystem" mode',
		},
	},

	deployment: {
		type: {
			format: String,
			default: 'default',
			env: 'N8N_DEPLOYMENT_TYPE',
		},
	},

	mfa: {
		enabled: {
			format: Boolean,
			default: true,
			doc: 'Whether to enable MFA feature in instance.',
			env: 'N8N_MFA_ENABLED',
		},
	},

	sso: {
		justInTimeProvisioning: {
			format: Boolean,
			default: true,
			doc: 'Whether to automatically create users when they login via SSO.',
		},
		redirectLoginToSso: {
			format: Boolean,
			default: true,
			doc: 'Whether to automatically redirect users from login dialog to initialize SSO flow.',
		},
		saml: {
			loginEnabled: {
				format: Boolean,
				default: false,
				doc: 'Whether to enable SAML SSO.',
			},
			loginLabel: {
				format: String,
				default: '',
			},
		},
		ldap: {
			loginEnabled: {
				format: Boolean,
				default: false,
			},
			loginLabel: {
				format: String,
				default: '',
			},
		},
	},

	hiringBanner: {
		enabled: {
			doc: 'Whether hiring banner in browser console is enabled.',
			format: Boolean,
			default: true,
			env: 'N8N_HIRING_BANNER_ENABLED',
		},
	},

	personalization: {
		enabled: {
			doc: 'Whether personalization is enabled.',
			format: Boolean,
			default: true,
			env: 'N8N_PERSONALIZATION_ENABLED',
		},
	},

<<<<<<< HEAD
	diagnostics: {
		enabled: {
			doc: 'Whether diagnostic mode is enabled.',
			format: Boolean,
			default: true,
			env: 'N8N_DIAGNOSTICS_ENABLED',
		},
		config: {
			posthog: {
				apiKey: {
					doc: 'API key for PostHog',
					format: String,
					default: 'phc_4URIAm1uYfJO7j8kWSe0J8lc8IqnstRLS7Jx8NcakHo',
					env: 'N8N_DIAGNOSTICS_POSTHOG_API_KEY',
				},
				apiHost: {
					doc: 'API host for PostHog',
					format: String,
					default: 'https://ph.n8n.io',
					env: 'N8N_DIAGNOSTICS_POSTHOG_API_HOST',
				},
			},
			sentry: {
				dsn: {
					doc: 'Data source name for error tracking on Sentry',
					format: String,
					default: '',
					env: 'N8N_SENTRY_DSN',
				},
			},
			frontend: {
				doc: 'Diagnostics config for frontend.',
				format: String,
				default: '1zPn9bgWPzlQc0p8Gj1uiK6DOTn;https://telemetry.n8n.io',
				env: 'N8N_DIAGNOSTICS_CONFIG_FRONTEND',
			},
			backend: {
				doc: 'Diagnostics config for backend.',
				format: String,
				default: '1zPn7YoGC3ZXE9zLeTKLuQCB4F6;https://telemetry.n8n.io/v1/batch',
				env: 'N8N_DIAGNOSTICS_CONFIG_BACKEND',
			},
		},
	},

=======
>>>>>>> tags/n8n@1.74.1
	defaultLocale: {
		doc: 'Default locale for the UI',
		format: String,
		default: 'en',
		env: 'N8N_DEFAULT_LOCALE',
	},

	hideUsagePage: {
		format: Boolean,
		default: false,
		env: 'N8N_HIDE_USAGE_PAGE',
		doc: 'Hide or show the usage page',
	},

	redis: {
		prefix: {
			doc: 'Prefix for all n8n related keys',
			format: String,
			default: 'n8n',
			env: 'N8N_REDIS_KEY_PREFIX',
		},
	},

	/**
	 * @important Do not remove until after cloud hooks are updated to stop using convict config.
	 */
	endpoints: {
		rest: {
			format: String,
			default: Container.get(GlobalConfig).endpoints.rest,
		},
	},

	/**
	 * @important Do not remove until after cloud hooks are updated to stop using convict config.
	 */
	ai: {
		enabled: {
			doc: 'Whether AI features are enabled',
			format: Boolean,
			default: false,
			env: 'N8N_AI_ENABLED',
		},
	},

	expression: {
		evaluator: {
			doc: 'Expression evaluator to use',
			format: ['tmpl', 'tournament'] as const,
			default: 'tournament',
			env: 'N8N_EXPRESSION_EVALUATOR',
		},
		reportDifference: {
			doc: 'Whether to report differences in the evaluator outputs',
			format: Boolean,
			default: false,
			env: 'N8N_EXPRESSION_REPORT_DIFFERENCE',
		},
	},

	sourceControl: {
		defaultKeyPairType: {
			doc: 'Default SSH key type to use when generating SSH keys',
			format: ['rsa', 'ed25519'] as const,
			default: 'ed25519',
			env: 'N8N_SOURCECONTROL_DEFAULT_SSH_KEY_TYPE',
		},
	},

	workflowHistory: {
		enabled: {
			doc: 'Whether to save workflow history versions',
			format: Boolean,
			default: true,
			env: 'N8N_WORKFLOW_HISTORY_ENABLED',
		},

		pruneTime: {
			doc: 'Time (in hours) to keep workflow history versions for',
			format: Number,
			default: -1,
			env: 'N8N_WORKFLOW_HISTORY_PRUNE_TIME',
		},
	},

	proxy_hops: {
		format: Number,
		default: 0,
		env: 'N8N_PROXY_HOPS',
		doc: 'Number of reverse-proxies n8n is running behind',
	},

	featureFlags: {
		partialExecutionVersionDefault: {
			format: String,
			default: '0',
			env: 'PARTIAL_EXECUTION_VERSION_DEFAULT',
			doc: 'Set this to 1 to enable the new partial execution logic by default.',
		},
	},
};
