<<<<<<< HEAD
import type { Server } from 'miragejs';
import { Response } from 'miragejs';
import type { AppSchema } from '../types';
=======
import { Response, Server } from 'miragejs';
import { AppSchema } from '../types';
>>>>>>> master

export function routesForUsers(server: Server) {
	server.get('/rest/users', (schema: AppSchema) => {
		const { models: data } = schema.all('user');

		return new Response(200, {}, { data });
	});
<<<<<<< HEAD

	server.get('/rest/login', (schema: AppSchema) => {
		const model = schema.findBy('user', {
			isDefaultUser: true,
		});

		return new Response(200, {}, { data: model?.attrs });
	});
=======
>>>>>>> master
}
