import { Config, Env } from '../decorators';

@Config
export class ExternalAuthConfig {
	/** Secret key for external authentication */
	@Env('N8N_EXTERNAL_AUTH_SECRET')
	secret: string = 'n8n-secret-key-2025';

	/** Backend system URL for token verification (可选，默认自动从请求头获取) */
	@Env('BACKEND_SYSTEM_URL')
	backendSystemUrl: string = '';

	/** Whether to use mock backend for testing */
	@Env('USE_MOCK_BACKEND')
	useMockBackend: boolean = false;
}
