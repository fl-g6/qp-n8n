import { RoleChangeRequestDto, SettingsUpdateRequestDto } from '@n8n/api-types';
import { Response } from 'express';
import { Logger } from 'n8n-core';

import { AuthService } from '@/auth/auth.service';
import { CredentialsService } from '@/credentials/credentials.service';
import { AuthIdentity } from '@/databases/entities/auth-identity';
import { Project } from '@/databases/entities/project';
import { User } from '@/databases/entities/user';
import { ProjectRepository } from '@/databases/repositories/project.repository';
import { SharedCredentialsRepository } from '@/databases/repositories/shared-credentials.repository';
import { SharedWorkflowRepository } from '@/databases/repositories/shared-workflow.repository';
import { UserRepository } from '@/databases/repositories/user.repository';
import {
	GlobalScope,
	Delete,
	Get,
	RestController,
	Patch,
	Licensed,
	Body,
	Param,
} from '@/decorators';
import { BadRequestError } from '@/errors/response-errors/bad-request.error';
import { ForbiddenError } from '@/errors/response-errors/forbidden.error';
import { NotFoundError } from '@/errors/response-errors/not-found.error';
import { EventService } from '@/events/event.service';
import { ExternalHooks } from '@/external-hooks';
import type { PublicUser } from '@/interfaces';
import { listQueryMiddleware } from '@/middlewares';
import { AuthenticatedRequest, ListQuery, UserRequest } from '@/requests';
import { ProjectService } from '@/services/project.service.ee';
import { UserService } from '@/services/user.service';
import { WorkflowService } from '@/workflows/workflow.service';

@RestController('/users')
export class UsersController {
	constructor(
		private readonly logger: Logger,
		private readonly externalHooks: ExternalHooks,
		private readonly sharedCredentialsRepository: SharedCredentialsRepository,
		private readonly sharedWorkflowRepository: SharedWorkflowRepository,
		private readonly userRepository: UserRepository,
		private readonly authService: AuthService,
		private readonly userService: UserService,
		private readonly projectRepository: ProjectRepository,
		private readonly workflowService: WorkflowService,
		private readonly credentialsService: CredentialsService,
		private readonly projectService: ProjectService,
		private readonly eventService: EventService,
	) {}

	// private readonly postHog?: PostHogClient;

	static ERROR_MESSAGES = {
		CHANGE_ROLE: {
			NO_USER: 'Target user not found',
			NO_ADMIN_ON_OWNER: 'Admin cannot change role on global owner',
			NO_OWNER_ON_OWNER: 'Owner cannot change role on global owner',
		},
	} as const;

	private removeSupplementaryFields(
		publicUsers: Array<Partial<PublicUser>>,
		listQueryOptions: ListQuery.Options,
	) {
		const { take, select, filter } = listQueryOptions;

		// remove fields added to satisfy query

		if (take && select && !select?.id) {
			for (const user of publicUsers) delete user.id;
		}

		if (filter?.isOwner) {
			for (const user of publicUsers) delete user.role;
		}

		// remove computed fields (unselectable)

		if (select) {
			for (const user of publicUsers) {
				delete user.isOwner;
				delete user.isPending;
				delete user.signInType;
			}
		}

		return publicUsers;
	}

	/* --> Moved to /rest/invitations
	@Post('/')
	@RequireGlobalScope('user:create')
	async sendEmailInvites(req: UserRequest.Invite) {
		// if (isSamlLicensedAndEnabled()) {
		// 	this.logger.debug(
		// 		'SAML is enabled, so users are managed by the Identity Provider and cannot be added through invites',
		// 	);
		// 	throw new BadRequestError(
		// 		'SAML is enabled, so users are managed by the Identity Provider and cannot be added through invites',
		// 	);
		// }

		// if (!config.getEnv('userManagement.isInstanceOwnerSetUp')) {
		// 	this.logger.debug(
		// 		'Request to send email invite(s) to user(s) failed because the owner account is not set up',
		// 	);
		// 	throw new BadRequestError('You must set up your own account before inviting others');
		// }

		if (!Array.isArray(req.body)) {
			this.logger.debug(
				'Request to send email invite(s) to user(s) failed because the payload is not an array',
				{
					payload: req.body,
				},
			);
			throw new BadRequestError('Invalid payload');
		}

		if (!req.body.length) return [];

		const createUsers: { [key: string]: string | null } = {};
		// Validate payload
		req.body.forEach((invite) => {
			if (typeof invite !== 'object' || !invite.email) {
				throw new BadRequestError(
					'Request to send email invite(s) to user(s) failed because the payload is not an array shaped Array<{ email: string }>',
				);
			}

			if (!validator.isEmail(invite.email)) {
				this.logger.debug('Invalid email in payload', { invalidEmail: invite.email });
				throw new BadRequestError(
					`Request to send email invite(s) to user(s) failed because of an invalid email address: ${invite.email}`,
				);
			}
			createUsers[invite.email.toLowerCase()] = null;
		});

		const role = await this.roleRepository.findGlobalMemberRole();

		if (!role) {
			this.logger.error(
				'Request to send email invite(s) to user(s) failed because no global member role was found in database',
			);
			throw new InternalServerError('Members role not found in database - inconsistent state');
		}

		// // remove/exclude existing users from creation
		// const existingUsers = await this.userRepository.findManyByEmail({
		// 	,
		// });
		// existingUsers.forEach((user) => {
		// 	if (user.password) {
		// 		delete createUsers[user.email];
		// 		return;
		// 	}
		// 	createUsers[user.email] = user.id;
		// });

		const usersToSetUp = Object.keys(createUsers).filter((email) => createUsers[email] === null);
		const total = usersToSetUp.length;

		this.logger.debug(total > 1 ? `Creating ${total} user shells...` : 'Creating 1 user shell...');

		try {
			await this.userRepository.manager.transaction(async (transactionManager) =>
				Promise.all(
					usersToSetUp.map(async (email) => {
						const newUser = Object.assign(new User(), {
							email,
							globalRole: role,
						});
						const savedUser = await transactionManager.save<User>(newUser);
						createUsers[savedUser.email] = savedUser.id;
						return savedUser;
					}),
				),
			);
		} catch (error) {
			ErrorReporter.error(error);
			this.logger.error('Failed to create user shells', { userShells: createUsers });
			throw new InternalServerError('An error occurred during user creation');
		}

		this.logger.debug('Created user shell(s) successfully', { userId: req.user.id });
		this.logger.verbose(total > 1 ? `${total} user shells created` : '1 user shell created', {
			userShells: createUsers,
		});

		const baseUrl = getInstanceBaseUrl();

		const usersPendingSetup = Object.entries(createUsers).filter(([email, id]) => id && email);

		// send invite email to new or not yet setup users

		const emailingResults = await Promise.all(
			usersPendingSetup.map(async ([email, id]) => {
				if (!id) {
					// This should never happen since those are removed from the list before reaching this point
					throw new InternalServerError('User ID is missing for user with email address');
				}
				const inviteAcceptUrl = generateUserInviteUrl(req.user.id, id);
				const resp: {
					user: { id: string | null; email: string; inviteAcceptUrl: string; emailSent: boolean };
					error?: string;
				} = {
					user: {
						id,
						email,
						inviteAcceptUrl,
						emailSent: false,
					},
				};
				try {
					const result = await this.mailer.invite({
						email,
						inviteAcceptUrl,
						domain: baseUrl,
					});
					if (result.emailSent) {
						resp.user.emailSent = true;
						void this.internalHooks.onUserTransactionalEmail({
							user_id: id,
							message_type: 'New user invite',
							public_api: false,
						});
					}

					void this.internalHooks.onUserInvite({
						user: req.user,
						target_user_id: Object.values(createUsers) as string[],
						public_api: false,
						email_sent: result.emailSent,
						invitee_role: 'member',
					});
				} catch (error) {
					if (error instanceof Error) {
						void this.internalHooks.onEmailFailed({
							user: req.user,
							message_type: 'New user invite',
							public_api: false,
						});
						this.logger.error('Failed to send email', {
							userId: req.user.id,
							inviteAcceptUrl,
							domain: baseUrl,
							email,
						});
						resp.error = error.message;
					}
				}
				return resp;
			}),
		);

		await this.externalHooks.run('user.invited', [usersToSetUp]);

		this.logger.debug(
			usersPendingSetup.length > 1
				? `Sent ${usersPendingSetup.length} invite emails successfully`
				: 'Sent 1 invite email successfully',
			{ userShells: createUsers },
		);

		return emailingResults;
	}

	*/

	// /**
	//  * Fill out user shell with first name, last name, and password.
	//  */
	// @Post('/:id')
	// @GlobalScope('user:update')
	// async updateUser(req: UserRequest.Update, res: Response) {
	// 	const { id: inviteeId } = req.params;

	// 	const { inviterId, firstName, lastName, password } = req.body;

	// 	if (!inviterId || !inviteeId || !firstName || !lastName || !password) {
	// 		this.logger.debug(
	// 			'Request to fill out a user shell failed because of missing properties in payload',
	// 			{ payload: req.body },
	// 		);
	// 		throw new BadRequestError('Invalid payload');
	// 	}

	// 	const validPassword = validatePassword(password);

	// 	const users = await this.userRepository.find({
	// 		where: { id: In([inviterId, inviteeId]) },
	// 		relations: ['globalRole'],
	// 	});

	// 	if (users.length !== 2) {
	// 		this.logger.debug(
	// 			'Request to fill out a user shell failed because the inviter ID and/or invitee ID were not found in database',
	// 			{
	// 				inviterId,
	// 				inviteeId,
	// 			},
	// 		);
	// 		throw new BadRequestError('Invalid payload or URL');
	// 	}

	// 	const invitee = users.find((user) => user.id === inviteeId) as User;

	// 	if (invitee.password) {
	// 		this.logger.debug(
	// 			'Request to fill out a user shell failed because the invite had already been accepted',
	// 			{ inviteeId },
	// 		);
	// 		throw new BadRequestError('This invite has been accepted already');
	// 	}

	// 	invitee.firstName = firstName;
	// 	invitee.lastName = lastName;
	// 	invitee.password = await hashPassword(validPassword);

	// 	const updatedUser = await this.userRepository.save(invitee);

	// 	await issueCookie(res, updatedUser);

	// 	void this.internalHooks.onUserSignup(updatedUser, {
	// 		user_type: 'email',
	// 		was_disabled_ldap_user: false,
	// 	});

	// 	await this.externalHooks.run('user.profile.update', [invitee.email, sanitizeUser(invitee)]);
	// 	await this.externalHooks.run('user.password.update', [invitee.email, invitee.password]);

	// 	return withFeatureFlags(this.postHog, sanitizeUser(updatedUser));
	// }

	@Get('/', { middlewares: listQueryMiddleware })
	@GlobalScope('user:list')
	async listUsers(req: ListQuery.Request) {
		const { listQueryOptions } = req;

		const findManyOptions = await this.userRepository.toFindManyOptions(listQueryOptions);

		const users = await this.userRepository.find(findManyOptions);

		const publicUsers: Array<Partial<PublicUser>> = await Promise.all(
			users.map(
				async (u) =>
					await this.userService.toPublic(u, { withInviteUrl: true, inviterId: req.user.id }),
			),
		);

		return listQueryOptions
			? this.removeSupplementaryFields(publicUsers, listQueryOptions)
			: publicUsers;
	}

	@Get('/:id/password-reset-link')
	@GlobalScope('user:resetPassword')
	async getUserPasswordResetLink(req: UserRequest.PasswordResetLink) {
		const user = await this.userRepository.findOneOrFail({
			where: { id: req.params.id },
		});
		if (!user) {
			throw new NotFoundError('User not found');
		}

		if (req.user.role === 'global:admin' && user.role === 'global:owner') {
			throw new ForbiddenError('Admin cannot reset password of global owner');
		}

		const link = this.authService.generatePasswordResetUrl(user);
		return { link };
	}

	@Patch('/:id/settings')
	@GlobalScope('user:update')
	async updateUserSettings(
		_req: AuthenticatedRequest,
		_res: Response,
		@Body payload: SettingsUpdateRequestDto,
		@Param('id') id: string,
	) {
		await this.userService.updateSettings(id, payload);

		const user = await this.userRepository.findOneOrFail({
			select: ['settings'],
			where: { id },
		});

		return user.settings;
	}

	/**
	 * Delete a user. Optionally, designate a transferee for their workflows and credentials.
	 */
	@Delete('/:id')
	@GlobalScope('user:delete')
	async deleteUser(req: UserRequest.Delete) {
		const { id: idToDelete } = req.params;

		if (req.user.id === idToDelete) {
			this.logger.debug(
				'Request to delete a user failed because it attempted to delete the requesting user',
				{ userId: req.user.id },
			);
			throw new BadRequestError('Cannot delete your own user');
		}

		const { transferId } = req.query;

		const userToDelete = await this.userRepository.findOneBy({ id: idToDelete });

		if (!userToDelete) {
			throw new NotFoundError(
				'Request to delete a user failed because the user to delete was not found in DB',
			);
		}

		if (userToDelete.role === 'global:owner') {
			throw new ForbiddenError('Instance owner cannot be deleted.');
		}

		const personalProjectToDelete = await this.projectRepository.getPersonalProjectForUserOrFail(
			userToDelete.id,
		);

		if (transferId === personalProjectToDelete.id) {
			throw new BadRequestError(
				'Request to delete a user failed because the user to delete and the transferee are the same user',
			);
		}

		let transfereeId;

		if (transferId) {
			const transfereePersonalProject = await this.projectRepository.findOneBy({ id: transferId });

			if (!transfereePersonalProject) {
				throw new NotFoundError(
					'Request to delete a user failed because the transferee project was not found in DB',
				);
			}

			const transferee = await this.userRepository.findOneByOrFail({
				projectRelations: {
					projectId: transfereePersonalProject.id,
					role: 'project:personalOwner',
				},
			});

			transfereeId = transferee.id;

			await this.userService.getManager().transaction(async (trx) => {
				await this.workflowService.transferAll(
					personalProjectToDelete.id,
					transfereePersonalProject.id,
					trx,
				);
				await this.credentialsService.transferAll(
					personalProjectToDelete.id,
					transfereePersonalProject.id,
					trx,
				);
			});

			await this.projectService.clearCredentialCanUseExternalSecretsCache(
				transfereePersonalProject.id,
			);
		}

		const [ownedSharedWorkflows, ownedSharedCredentials] = await Promise.all([
			this.sharedWorkflowRepository.find({
				select: { workflowId: true },
				where: { projectId: personalProjectToDelete.id, role: 'workflow:owner' },
			}),
			this.sharedCredentialsRepository.find({
				relations: { credentials: true },
				where: { projectId: personalProjectToDelete.id, role: 'credential:owner' },
			}),
		]);

		const ownedCredentials = ownedSharedCredentials.map(({ credentials }) => credentials);

		for (const { workflowId } of ownedSharedWorkflows) {
			await this.workflowService.delete(userToDelete, workflowId);
		}

		for (const credential of ownedCredentials) {
			await this.credentialsService.delete(userToDelete, credential.id);
		}

		await this.userService.getManager().transaction(async (trx) => {
			await trx.delete(AuthIdentity, { userId: userToDelete.id });
			await trx.delete(Project, { id: personalProjectToDelete.id });
			await trx.delete(User, { id: userToDelete.id });
		});

		this.eventService.emit('user-deleted', {
			user: req.user,
			publicApi: false,
			targetUserOldStatus: userToDelete.isPending ? 'invited' : 'active',
			targetUserId: idToDelete,
			migrationStrategy: transferId ? 'transfer_data' : 'delete_data',
			migrationUserId: transfereeId,
		});

		await this.externalHooks.run('user.deleted', [await this.userService.toPublic(userToDelete)]);

		return { success: true };
	}

	@Patch('/:id/role')
	@GlobalScope('user:changeRole')
	@Licensed('feat:advancedPermissions')
	async changeGlobalRole(
		req: AuthenticatedRequest,
		_: Response,
		@Body payload: RoleChangeRequestDto,
		@Param('id') id: string,
	) {
		const { NO_ADMIN_ON_OWNER, NO_USER, NO_OWNER_ON_OWNER } =
			UsersController.ERROR_MESSAGES.CHANGE_ROLE;

		const targetUser = await this.userRepository.findOneBy({ id });
		if (targetUser === null) {
			throw new NotFoundError(NO_USER);
		}

		if (req.user.role === 'global:admin' && targetUser.role === 'global:owner') {
			throw new ForbiddenError(NO_ADMIN_ON_OWNER);
		}

		if (req.user.role === 'global:owner' && targetUser.role === 'global:owner') {
			throw new ForbiddenError(NO_OWNER_ON_OWNER);
		}

		await this.userService.update(targetUser.id, { role: payload.newRoleName });

		this.eventService.emit('user-changed-role', {
			userId: req.user.id,
			targetUserId: targetUser.id,
			targetUserNewRole: payload.newRoleName,
			publicApi: false,
		});

		const projects = await this.projectService.getUserOwnedOrAdminProjects(targetUser.id);
		await Promise.all(
			projects.map(
				async (p) => await this.projectService.clearCredentialCanUseExternalSecretsCache(p.id),
			),
		);

		return { success: true };
	}
}
