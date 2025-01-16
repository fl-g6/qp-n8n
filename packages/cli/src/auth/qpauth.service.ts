import { GlobalConfig } from '@n8n/config';
import { Container, Service } from '@n8n/di';
import { createHash } from 'crypto';
import type { NextFunction, Response } from 'express';
import { TokenExpiredError } from 'jsonwebtoken';
import jwt = require('jsonwebtoken');
import jwks = require('jwks-rsa');
import {
	JWT_ALLOWED_TENANT,
	JWT_ALLOWED_TENANT_KEY,
	JWT_AUTH_HEADER,
	JWT_AUTH_HEADER_VALUE_PREFIX,
	JWT_ISSUER,
	JWT_JWKS_URI,
	JWT_NAMESPACE,
	Logger,
} from 'n8n-core';
// eslint-disable-next-line import/no-extraneous-dependencies

import config from '@/config';
import { AUTH_COOKIE_NAME, RESPONSE_ERROR_MESSAGES, Time } from '@/constants';
import type { User } from '@/databases/entities/user';
import { InvalidAuthTokenRepository } from '@/databases/repositories/invalid-auth-token.repository';
import { UserRepository } from '@/databases/repositories/user.repository';
import { AuthError } from '@/errors/response-errors/auth.error';
import { ForbiddenError } from '@/errors/response-errors/forbidden.error';
import { License } from '@/license';
import { jwtAuthAuthorizationError } from '@/middlewares/external-jwt-auth';
import type { QpJwtRequest, QpJwt } from '@/middlewares/external-jwt-auth';
import type { AuthenticatedRequest } from '@/requests';
import { JwtService } from '@/services/jwt.service';
import { UrlService } from '@/services/url.service';

interface AuthJwtPayload {
	/** User Id */
	id: string;
	/** This hash is derived from email and bcrypt of password */
	hash: string;
	/** This is a client generated unique string to prevent session hijacking */
	browserId?: string;
	email: string;
}

interface IssuedJWT extends AuthJwtPayload {
	exp: number;
}

interface PasswordResetToken {
	sub?: string;
	hash?: string;
}

const restEndpoint = Container.get(GlobalConfig).endpoints.rest;
// The browser-id check needs to be skipped on these endpoints
const skipBrowserIdCheckEndpoints = [
	// we need to exclude push endpoint because we can't send custom header on websocket requests
	// TODO: Implement a custom handshake for push, to avoid having to send any data on querystring or headers
	`/${restEndpoint}/push`,

	// We need to exclude binary-data downloading endpoint because we can't send custom headers on `<embed>` tags
	`/${restEndpoint}/binary-data/`,
];

@Service()
export class QPAuthService {
	constructor(
		private readonly logger: Logger,
		private readonly license: License,
		private readonly jwtService: JwtService,
		private readonly urlService: UrlService,
		private readonly userRepository: UserRepository,
		private readonly invalidAuthTokenRepository: InvalidAuthTokenRepository,
		private readonly jwtAuthHeader: string,
		private jwksUri: string,
		private jwtHeaderValuePrefix: string,
		private jwtIssuer: string,
		private jwtNamespace: string,
		private jwtAllowedTenantKey: string,
		private jwtAllowedTenant: string,
	) {
		// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
		this.qpAuthMiddleware = this.qpAuthMiddleware.bind(this);
		this.jwtAuthHeader = process.env[JWT_AUTH_HEADER] ?? '';
		this.jwksUri = process.env[JWT_JWKS_URI] ?? '';
		if (this.jwtAuthHeader === '') {
			// throw new ApplicationError('JWT auth is activated but no request header was defined. Please set one!')
		}
		if (this.jwksUri === '') {
			// throw new ApplicationError('JWT auth is activated but no JWK Set URI was defined. Please set one!')
		}
		jwtHeaderValuePrefix = process.env[JWT_AUTH_HEADER_VALUE_PREFIX] ?? '';
		jwtIssuer = process.env[JWT_ISSUER] ?? '';
		jwtNamespace = process.env[JWT_NAMESPACE] ?? '';
		jwtAllowedTenantKey = process.env[JWT_ALLOWED_TENANT_KEY] ?? '';
		jwtAllowedTenant = process.env[JWT_ALLOWED_TENANT] ?? '';
	}

	// async qpAuthMiddleware(req: QpJwtRequest, res: Response, next: NextFunction) {

	// 	let tokenHeader = req.header(this.jwtAuthHeader) as string;
	// 	if (tokenHeader === undefined || tokenHeader === '') {
	// 		return jwtAuthAuthorizationError(res, 'Missing token');
	// 	}

	// 	if (this.jwtHeaderValuePrefix !== '' && tokenHeader.startsWith(this.jwtHeaderValuePrefix)) {
	// 		tokenHeader = tokenHeader.replace(`${this.jwtHeaderValuePrefix} `, '').trimStart();
	// 	}

	// 	const jwkClient = jwks({ cache: true,jwksUri: this.jwksUri });
	// 	const getKey: jwt.GetPublicKeyOrSecret = (header, callbackFn) => {
	// 		// eslint-disable-next-line @typescript-eslint/no-throw-literal
	// 		if (!header.kid) throw jwtAuthAuthorizationError(res, 'No JWT key found');
	// 		jwkClient.getSigningKey(header.kid, (error, key) => {
	// 			// eslint-disable-next-line @typescript-eslint/no-throw-literal
	// 			if (error) throw jwtAuthAuthorizationError(res, error.message);
	// 			callbackFn(null, key?.getPublicKey());
	// 		});
	// 	};

	// 	const jwtVerifyOptions: jwt.VerifyOptions = {
	// 		issuer: this.jwtIssuer !== '' ? this.jwtIssuer : undefined,
	// 		ignoreExpiration: false,
	// 	};

	// 	// eslint-disable-next-line no-inner-declarations
	// 	function isTenantAllowed(decodedToken: object): boolean {

	// 		// // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
	// 		// if (this.jwtNamespace === '' || this.jwtAllowedTenantKey === '' || this.jwtAllowedTenant === '') {
	// 		// 	return true;
	// 		// }

	// 		// for (const [k, v] of Object.entries(decodedToken)) {
	// 		// 	// eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
	// 		// 	if (k === this.jwtNamespace) {
	// 		// 		// eslint-disable-next-line @typescript-eslint/no-unsafe-argument
	// 		// 		for (const [kn, kv] of Object.entries(v)) {
	// 		// 			// eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
	// 		// 			if (kn === this.jwtAllowedTenantKey && kv === this.jwtAllowedTenant) {
	// 		// 				return true;
	// 		// 			}
	// 		// 		}
	// 		// 	}
	// 		// }

	// 		return true;
	// 	}

	// 	jwt.verify(tokenHeader, getKey, jwtVerifyOptions, (error: jwt.VerifyErrors, decoded: QpJwt) => {
	// 		if (error) {
	// 			jwtAuthAuthorizationError(res, 'Invalid token error');
	// 		} else if (!isTenantAllowed(decoded)) {
	// 			jwtAuthAuthorizationError(res, 'Tenant not allowed');
	// 		} else {
	// 			req.jwt = decoded;
	// 			next();
	// 		}
	// 	});

	// 	// const token = req.cookies[AUTH_COOKIE_NAME];
	// 	// if (token) {
	// 	// 	try {
	// 	// 		const isInvalid = await this.invalidAuthTokenRepository.existsBy({ token });
	// 	// 		if (isInvalid) throw new AuthError('Unauthorized');
	// 	// 		req.user = await this.resolveJwt(token, req, res);
	// 	// 	} catch (error) {
	// 	// 		if (error instanceof JsonWebTokenError || error instanceof AuthError) {
	// 	// 			this.clearCookie(res);
	// 	// 		} else {
	// 	// 			throw error;
	// 	// 		}
	// 	// 	}
	// 	// }

	// 	// if (req.user) next();
	// 	// else res.status(401).json({ status: 'error', message: 'Unauthorized' });
	// }

	async qpAuthMiddleware(req: QpJwtRequest, res: Response, next: NextFunction) {
		try {
			const token = this.extractToken(req, res);

			// Use the promise-based verifyJwtToken method
			const decoded = await this.verifyJwtToken(token, res);

			// Check tenant validity explicitly
			if (!this.isTenantAllowed(decoded)) {
				this.handleJwtError(res, 'Tenant not allowed');
				return;
			}

			// Attach decoded token to request and proceed
			req.jwt = decoded;
			next();
		} catch (error) {
			console.error('Middleware error:', error);
		}
	}

	async verifyJwtToken(token: string, res: Response): Promise<QpJwt> {
		const getKey = this.createKeyRetriever(res);
		const jwtVerifyOptions = this.getJwtVerifyOptions();

		return await new Promise((resolve, reject) => {
			jwt.verify(token, getKey, jwtVerifyOptions, (error: jwt.VerifyErrors, decoded: QpJwt) => {
				if (error) {
					this.handleJwtError(res, 'Invalid token error');
					reject(error);
				} else {
					resolve(decoded);
				}
			});
		});
	}

	// Function to extract token from the request headers
	private extractToken(req: QpJwtRequest, res: Response): string {
		let tokenHeader = req.header(this.jwtAuthHeader) as string;
		if (!tokenHeader) {
			// eslint-disable-next-line @typescript-eslint/no-throw-literal
			throw this.handleJwtError(res, 'Missing token');
		}

		if (this.jwtHeaderValuePrefix && tokenHeader.startsWith(this.jwtHeaderValuePrefix)) {
			tokenHeader = tokenHeader.replace(`${this.jwtHeaderValuePrefix} `, '').trimStart();
		}

		return tokenHeader;
	}

	// Function to create a retriever for the JWT signing key
	private createKeyRetriever(res: Response): jwt.GetPublicKeyOrSecret {
		const jwkClient = jwks({ cache: true, jwksUri: this.jwksUri });
		return (header, callbackFn) => {
			if (!header.kid) {
				// eslint-disable-next-line @typescript-eslint/no-throw-literal
				throw this.handleJwtError(res, 'No JWT key found');
			}

			jwkClient.getSigningKey(header.kid, (error, key) => {
				if (error) {
					// eslint-disable-next-line @typescript-eslint/no-throw-literal
					throw this.handleJwtError(res, error.message);
				}
				callbackFn(null, key?.getPublicKey());
			});
		};
	}

	// Function to generate JWT verification options
	private getJwtVerifyOptions(): jwt.VerifyOptions {
		return {
			issuer: this.jwtIssuer || undefined,
			ignoreExpiration: false,
		};
	}

	// Function to handle JWT authorization errors
	private handleJwtError(res: Response, message: string): void {
		jwtAuthAuthorizationError(res, message);
	}

	// Function to check if the tenant is allowed
	private isTenantAllowed(decodedToken: QpJwt): boolean {
		// Uncomment and modify the below logic if tenant validation is required
		// if (this.jwtNamespace && this.jwtAllowedTenantKey && this.jwtAllowedTenant) {
		//     const namespace = decodedToken[this.jwtNamespace];
		//     if (namespace) {
		//         return namespace[this.jwtAllowedTenantKey] === this.jwtAllowedTenant;
		//     }
		// }
		return true;
	}

	clearCookie(res: Response) {
		res.clearCookie(AUTH_COOKIE_NAME);
	}

	async invalidateToken(req: AuthenticatedRequest) {
		const token = req.cookies[AUTH_COOKIE_NAME];
		if (!token) return;
		try {
			const { exp } = this.jwtService.decode(token);
			if (exp) {
				await this.invalidAuthTokenRepository.insert({
					token,
					expiresAt: new Date(exp * 1000),
				});
			}
		} catch (e) {
			this.logger.warn('failed to invalidate auth token', { error: (e as Error).message });
		}
	}

	issueCookie(res: Response, user: User, browserId?: string) {
		// TODO: move this check to the login endpoint in AuthController
		// If the instance has exceeded its user quota, prevent non-owners from logging in
		const isWithinUsersLimit = this.license.isWithinUsersLimit();
		if (
			config.getEnv('userManagement.isInstanceOwnerSetUp') &&
			!user.isOwner &&
			!isWithinUsersLimit
		) {
			throw new ForbiddenError(RESPONSE_ERROR_MESSAGES.USERS_QUOTA_REACHED);
		}

		const token = this.issueJWT(user, browserId);
		res.cookie(AUTH_COOKIE_NAME, token, {
			maxAge: this.jwtExpiration * Time.seconds.toMilliseconds,
			httpOnly: true,
			sameSite: 'lax',
			secure: config.getEnv('secure_cookie'),
		});
	}

	issueJWT(user: User, browserId?: string) {
		const payload: AuthJwtPayload = {
			id: user.id,
			hash: this.createJWTHash(user),
			browserId: browserId && this.hash(browserId),
			email: user.email,
		};
		return this.jwtService.sign(payload, {
			expiresIn: this.jwtExpiration,
		});
	}

	async resolveJwt(token: string, req: AuthenticatedRequest, res: Response): Promise<User> {
		// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
		const jwtPayload: QpJwt = this.jwtService.verify(token, {
			algorithms: ['HS256', 'RS256', 'ES256'],
		});

		// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
		req.jwt = jwtPayload;
		// TODO: Use an in-memory ttl-cache to cache the User object for upto a minute
		const user = await this.userRepository.findOne({
			// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
			where: { id: jwtPayload.id },
		});

		// if (
		// 	// If not user is found
		// 	!user ||
		// 	// or, If the user has been deactivated (i.e. LDAP users)
		// 	user.disabled ||
		// 	// or, If the email or password has been updated
		// 	jwtPayload.hash !== this.createJWTHash(user)
		// ) {
		// 	throw new AuthError('Unauthorized');
		// }

		//// or, If the user has been deactivated (i.e. LDAP users)
		//user.disabled ||
		if (
			// If not user is found
			!user ||
			// or, If the email or password has been updated
			jwtPayload.email !== user.email
		) {
			throw new AuthError('Unauthorized');
		}

		// // Check if the token was issued for another browser session, ignoring the endpoints that can't send custom headers
		// const endpoint = req.route ? `${req.baseUrl}${req.route.path}` : req.baseUrl;
		// if (req.method === 'GET' && skipBrowserIdCheckEndpoints.includes(endpoint)) {
		// 	this.logger.debug(`Skipped browserId check on ${endpoint}`);
		// } else if (
		// 	jwtPayload.browserId &&
		// 	(!req.browserId || jwtPayload.browserId !== this.hash(req.browserId))
		// ) {
		// 	this.logger.warn(`browserId check failed on ${endpoint}`);
		// 	throw new AuthError('Unauthorized');
		// }

		// if (jwtPayload.exp * 1000 - Date.now() < this.jwtRefreshTimeout) {
		// 	this.logger.debug('JWT about to expire. Will be refreshed');
		// 	this.issueCookie(res, user, req.browserId);
		// }

		return user;
	}

	generatePasswordResetToken(user: User, expiresIn = '20m') {
		const payload: PasswordResetToken = { sub: user.id, hash: this.createJWTHash(user) };
		return this.jwtService.sign(payload, { expiresIn });
	}

	generatePasswordResetUrl(user: User) {
		const instanceBaseUrl = this.urlService.getInstanceBaseUrl();
		const url = new URL(`${instanceBaseUrl}/change-password`);

		url.searchParams.append('token', this.generatePasswordResetToken(user));
		url.searchParams.append('mfaEnabled', user.mfaEnabled.toString());

		return url.toString();
	}

	async resolvePasswordResetToken(token: string): Promise<User | undefined> {
		let decodedToken: PasswordResetToken;
		try {
			decodedToken = this.jwtService.verify(token);
		} catch (e) {
			if (e instanceof TokenExpiredError) {
				this.logger.debug('Reset password token expired', { token });
			} else {
				this.logger.debug('Error verifying token', { token });
			}
			return;
		}

		const user = await this.userRepository.findOne({
			where: { id: decodedToken.sub },
			relations: ['authIdentities'],
		});

		if (!user) {
			this.logger.debug(
				'Request to resolve password token failed because no user was found for the provided user ID',
				{ userId: decodedToken.sub, token },
			);
			return;
		}

		if (decodedToken.hash !== this.createJWTHash(user)) {
			this.logger.debug('Password updated since this token was generated');
			return;
		}

		return user;
	}

	createJWTHash({ email, password }: User) {
		return this.hash(email + ':' + password).substring(0, 10);
	}

	private hash(input: string) {
		return createHash('sha256').update(input).digest('base64');
	}

	/** How many **milliseconds** before expiration should a JWT be renewed */
	get jwtRefreshTimeout() {
		const { jwtRefreshTimeoutHours, jwtSessionDurationHours } = config.get('userManagement');
		if (jwtRefreshTimeoutHours === 0) {
			return Math.floor(jwtSessionDurationHours * 0.25 * Time.hours.toMilliseconds);
		} else {
			return Math.floor(jwtRefreshTimeoutHours * Time.hours.toMilliseconds);
		}
	}

	/** How many **seconds** is an issued JWT valid for */
	get jwtExpiration() {
		return config.get('userManagement.jwtSessionDurationHours') * Time.hours.toSeconds;
	}
}
