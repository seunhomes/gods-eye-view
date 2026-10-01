import { createHash, timingSafeEqual } from 'node:crypto';

const digest = (value) => createHash('sha256').update(value).digest();

/**
 * HTTP Basic Auth gate for hosted deployments. Active only when SITE_PASSWORD
 * is set; any username is accepted. Must be the first plugin so it runs before
 * static assets and provider proxies.
 */
export function sitePasswordPlugin(password = process.env.SITE_PASSWORD) {
  const middleware = (req, res, next) => {
    const header = req.headers.authorization || '';
    const [scheme, encoded] = header.split(' ');
    if (scheme === 'Basic' && encoded) {
      const decoded = Buffer.from(encoded, 'base64').toString();
      const supplied = decoded.slice(decoded.indexOf(':') + 1);
      if (timingSafeEqual(digest(supplied), digest(password))) return next();
    }
    res.statusCode = 401;
    res.setHeader('WWW-Authenticate', 'Basic realm="God\'s Eye View", charset="UTF-8"');
    res.end('Authentication required');
  };
  return {
    name: 'gev-site-password',
    enforce: 'pre',
    configureServer(server) {
      if (password) server.middlewares.use(middleware);
    },
    configurePreviewServer(server) {
      if (password) server.middlewares.use(middleware);
    },
  };
}
