<<<<<<< HEAD
import type { Server } from 'miragejs';
import { Response } from 'miragejs';
import type { AppSchema } from '../types';
=======
import { Response, Server } from 'miragejs';
import { AppSchema } from '../types';
>>>>>>> master

export function routesForCredentials(server: Server) {
	server.get('/rest/credentials', (schema: AppSchema) => {
		const { models: data } = schema.all('credential');

		return new Response(200, {}, { data });
	});
}
