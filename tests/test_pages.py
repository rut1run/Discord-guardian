import unittest
from types import SimpleNamespace as NS
from aiohttp.test_utils import TestClient, TestServer
from core import Store
from server import make_app
from deploy.nginx_patch import patch, INCLUDE


class NginxTests(unittest.TestCase):
    config='''server {
 listen 80;
 server_name entry-systems.duckdns.org;
 return 301 https://$host$request_uri;
}
server {
 listen 443 ssl;
 listen [::]:443 ssl;
 server_name entry-systems.duckdns.org;
 location /api/ { proxy_pass http://127.0.0.1:8000; }
 location / { return 200 "{ text }"; } # } comment
}
'''

    def test_preserves_entry_routes_and_only_inserts_once(self):
        output=patch(self.config,'entry-systems.duckdns.org')
        self.assertEqual(output.count(INCLUDE),1)
        self.assertEqual(patch(output,'entry-systems.duckdns.org'),output)
        self.assertEqual(output.replace('\n    '+INCLUDE+'\n',''),self.config)
        self.assertLess(output.index('listen 443'),output.index(INCLUDE))

    def test_wrong_host_and_ambiguous_config_refused(self):
        with self.assertRaises(ValueError):patch(self.config,'another.example.com')
        with self.assertRaises(ValueError):patch(self.config+self.config,'entry-systems.duckdns.org')

    def test_conflicting_location_refused(self):
        config=self.config.replace('location /api/', 'location /radius-guard/api/')
        with self.assertRaises(ValueError):patch(config,'entry-systems.duckdns.org')

    def test_commented_include_is_not_active(self):
        output=patch(self.config.replace('listen 443 ssl;', 'listen 443 ssl;\n # '+INCLUDE), 'entry-systems.duckdns.org')
        self.assertEqual(output.count(INCLUDE),2)


class PagesTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.store=Store(':memory:')
        bot=NS(is_ready=lambda:True,guilds=[],store=self.store)
        self.client=TestClient(TestServer(make_app(bot,'pages-password-12345678','https://entry-systems.duckdns.org',
             pages_origin='https://rut1run.github.io',trusted_proxy=True)))
        await self.client.start_server()
        self.headers={'Host':'entry-systems.duckdns.org','Origin':'https://rut1run.github.io'}

    async def asyncTearDown(self):
        await self.client.close()
        self.store.db.close()

    async def login(self,extra=None):
        return await self.client.post('/api/login',headers=self.headers|(extra or {}),json={'password':'pages-password-12345678'})

    async def test_pages_preflight_before_login(self):
        response=await self.client.options('/api/login',headers=self.headers|{'Access-Control-Request-Method':'POST'})
        self.assertEqual(response.status,204)
        self.assertEqual(response.headers['Access-Control-Allow-Origin'],'https://rut1run.github.io')
        self.assertIn('Authorization',response.headers['Access-Control-Allow-Headers'])
        self.assertNotIn('Access-Control-Allow-Credentials',response.headers)

    async def test_bearer_session_without_cross_site_cookies(self):
        login=await self.login()
        self.assertEqual(login.status,200)
        data=await login.json()
        self.assertIn('token',data)
        self.client.session.cookie_jar.clear()
        headers=self.headers|{'Authorization':'Bearer '+data['token']}
        response=await self.client.get('/api/me',headers=headers)
        self.assertEqual(response.status,200)
        denied=await self.client.post('/api/logout',headers=headers,json={})
        self.assertEqual(denied.status,403)
        response=await self.client.post('/api/logout',headers=headers|{'X-CSRF-Token':data['csrf']},json={})
        self.assertEqual(response.status,200)
        denied=await self.client.get('/api/me',headers=headers)
        self.assertEqual(denied.status,401)

    async def test_foreign_origin_receives_no_cors(self):
        headers=self.headers|{'Origin':'https://evil.example'}
        for method in ('get','options'):
            response=await getattr(self.client,method)('/api/me',headers=headers)
            self.assertEqual(response.status,403)
            self.assertNotIn('Access-Control-Allow-Origin',response.headers)

    async def test_proxy_preserves_per_client_login_limit(self):
        for _ in range(10):
            response=await self.client.post('/api/login',headers=self.headers|{'X-Real-IP':'192.0.2.1'},json={'password':'wrong'})
            self.assertEqual(response.status,401)
        blocked=await self.login({'X-Real-IP':'192.0.2.1'})
        self.assertEqual(blocked.status,429)
        allowed=await self.login({'X-Real-IP':'192.0.2.2'})
        self.assertEqual(allowed.status,200)

    async def test_health_exposes_no_server_data(self):
        response=await self.client.get('/api/health',headers={'Host':'entry-systems.duckdns.org'})
        self.assertEqual(await response.json(),{'ok':True,'discord':True})
