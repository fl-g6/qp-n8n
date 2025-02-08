import { Config, Env, Nested } from '../decorators';

/*
	Deprecated in n8n
*/
@Config
export class JWTAuthConfig {
	@Env('N8N_JWT_AUTH_ACTIVE')
	active: boolean = false;

	@Env('N8N_JWT_AUTH_HEADER')
	jwtHeader: string = '';

	@Env('N8N_JWT_AUTH_HEADER_VALUE_PREFIX')
	jwtHeaderValuePrefix: string = '';

	@Env('N8N_JWKS_URI')
	jwksUri: string = '';

	@Env('N8N_JWT_ISSUER')
	jwtIssuer: string = '';

	@Env('N8N_JWT_NAMESPACE')
	jwtNamespace: string = '';

	@Env('N8N_JWT_ALLOWED_TENANT_KEY')
	jwtAllowedTenantKey: string = '';

	@Env('N8N_JWT_ALLOWED_TENANT')
	jwtAllowedTenant: string = '';
}

@Config
export class SecurityConfig {
	/**
	 * Which directories to limit n8n's access to. Separate multiple dirs with semicolon `;`.
	 *
	 * @example N8N_RESTRICT_FILE_ACCESS_TO=/home/user/.n8n;/home/user/n8n-data
	 */
	@Env('N8N_RESTRICT_FILE_ACCESS_TO')
	restrictFileAccessTo: string = '';

	/**
	 * Whether to block access to all files at:
	 * - the ".n8n" directory,
	 * - the static cache dir at ~/.cache/n8n/public, and
	 * - user-defined config files.
	 */
	@Env('N8N_BLOCK_FILE_ACCESS_TO_N8N_FILES')
	blockFileAccessToN8nFiles: boolean = true;

	/**
	 * In a [security audit](https://docs.n8n.io/hosting/securing/security-audit/), how many days for a workflow to be considered abandoned if not executed.
	 */
	@Env('N8N_SECURITY_AUDIT_DAYS_ABANDONED_WORKFLOW')
	daysAbandonedWorkflow: number = 90;

	@Nested
	jwtAuth: JWTAuthConfig;
}
