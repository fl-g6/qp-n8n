import { GlobalConfig } from '@n8n/config';
import { Container, Service } from '@n8n/di';
import { contains } from 'class-validator';
import { createHash } from 'crypto';
import type { NextFunction, Response } from 'express';
import { JsonWebTokenError, TokenExpiredError } from 'jsonwebtoken';
import { Logger } from 'n8n-core';
// eslint-disable-next-line import/no-extraneous-dependencies

import config from '@/config';
import { AUTH_COOKIE_NAME, RESPONSE_ERROR_MESSAGES, Time } from '@/constants';
import type { User } from '@/databases/entities/user';
import { InvalidAuthTokenRepository } from '@/databases/repositories/invalid-auth-token.repository';
import { UserRepository } from '@/databases/repositories/user.repository';
import { AuthError } from '@/errors/response-errors/auth.error';
import { ForbiddenError } from '@/errors/response-errors/forbidden.error';
import { License } from '@/license';
import type { QpJwt } from '@/middlewares/external-jwt-auth';
import type { AuthenticatedRequest } from '@/requests';
import { JwtService } from '@/services/jwt.service';
import { UrlService } from '@/services/url.service';

import { QPAuthService } from './qpauth.service';

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
export class AuthService {
	constructor(
		private readonly logger: Logger,
		private readonly license: License,
		private readonly jwtService: JwtService,
		private readonly urlService: UrlService,
		private readonly userRepository: UserRepository,
		private readonly invalidAuthTokenRepository: InvalidAuthTokenRepository,
		private jwtAuthHeader: string,
	) {
		// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
		this.authMiddleware = this.authMiddleware.bind(this);
	}

	async authMiddleware(req: AuthenticatedRequest, res: Response, next: NextFunction) {
		const token = req.cookies[AUTH_COOKIE_NAME];
		if (token) {
			try {
				const isInvalid = await this.invalidAuthTokenRepository.existsBy({ token });
				if (isInvalid) throw new AuthError('Unauthorized');
				req.user = await this.resolveJwt(token, req, res, next);
				if (req.user) next();
				else res.status(401).json({ status: 'error', message: 'Unauthorized' });
			} catch (error) {
				if (error instanceof JsonWebTokenError || error instanceof AuthError) {
					this.clearCookie(res);
				} else {
					throw error;
				}
			}
		}
		// this.jwtAuthHeader = process.env.JWT_AUTH_HEADER ?? '';
		// const tokenHeader = req.header(this.jwtAuthHeader) as string;
		// else if(tokenHeader){
		// 	next();
		// }
		else {
			res.status(401).json({ status: 'error', message: 'Unauthorized' });
		}
		// else if (tokenHeader){
		// 	const isInvalid = await this.invalidAuthTokenRepository.existsBy({ token });
		// 	if (isInvalid) throw new AuthError('Unauthorized');
		// 		await Container.get(QPAuthService).qpAuthMiddleware(req as QpJwtRequest,res, next);
		// 		// next();
		// 		//req.user = await this.resolveJwt(tokenHeader, req, res);

		// }
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

	async resolveJwt(
		token: string,
		req: AuthenticatedRequest,
		res: Response,
		next: NextFunction,
	): Promise<User> {
		// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
		const jwtPayload: QpJwt = this.jwtService.verify(token, {
			algorithms: ['HS256', 'RS256', 'ES256'],
		});

		if (contains(req.baseUrl, '/rest/quickplay')) {
			// Set JWT Payload

			req.jwt = await Container.get(QPAuthService).verifyJwtToken(token, res);
			// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
			// await Container.get(QPAuthService).qpAuthMiddleware(req as QpJwtRequest,res, next);
			// next();
		}

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

		// Check if the token was issued for another browser session, ignoring the endpoints that can't send custom headers
		const endpoint = req.route ? `${req.baseUrl}${req.route.path}` : req.baseUrl;
		if (req.method === 'GET' && skipBrowserIdCheckEndpoints.includes(endpoint)) {
			this.logger.debug(`Skipped browserId check on ${endpoint}`);
		} else if (
			jwtPayload.browserId &&
			(!req.browserId || jwtPayload.browserId !== this.hash(req.browserId))
		) {
			this.logger.warn(`browserId check failed on ${endpoint}`);
			throw new AuthError('Unauthorized');
		}

		if ((jwtPayload.exp as number) * 1000 - Date.now() < this.jwtRefreshTimeout) {
			this.logger.debug('JWT about to expire. Will be refreshed');
			this.issueCookie(res, user, req.browserId);
		}

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
