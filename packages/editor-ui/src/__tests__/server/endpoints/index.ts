<<<<<<< HEAD
import type { Server } from 'miragejs';
import { routesForUsers } from './user';
import { routesForCredentials } from './credential';
import { routesForCredentialTypes } from './credentialType';
import { routesForVariables } from './variable';
import { routesForSettings } from './settings';
=======
import { routesForUsers } from './user';
import { routesForCredentials } from './credential';
import { Server } from 'miragejs';
import { routesForCredentialTypes } from '@/__tests__/server/endpoints/credentialType';
>>>>>>> master

const endpoints: Array<(server: Server) => void> = [
	routesForCredentials,
	routesForCredentialTypes,
	routesForUsers,
<<<<<<< HEAD
	routesForVariables,
	routesForSettings,
=======
>>>>>>> master
];

export { endpoints };
