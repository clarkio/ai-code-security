import { config } from './config';
import { createApp } from './app';
import { logger } from './logger';

const app = createApp();

app.listen(config.PORT, () => {
  logger.info({ port: config.PORT }, 'server listening');
});
