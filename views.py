import tornado.ioloop
import tornado.web
import Settings
import tornado.httpserver
import tornado.httputil

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils

class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", IndexHandler)
            (r"/attrs", AttrsHandler)
            (r"/metadata",MetadataHandler)
        ]
        settings = {
            "template_path": Settings.TEMPLATE_PATH,
            "saml_path": Settings.SAML_PATH,
        }
        tornado.web.Application.__init__(self, handlers, **settings)


class IndexHandler(tornado.web.RequestHandler):
    def get(self):
        req = prepare_tornado_request(self.request)
        auth = init_saml_auth(req)
        errors = []
        not_auth_warn = False
        success_slo = False
        attributes = False
        paint_logout = False

        if 'sso' in req['get_data']:
            return self.redirect(auth.login())
            # If AuthNRequest ID need to be stored in order to later validate it, do instead
            # sso_built_url = auth.login()
            # request.session['AuthNRequestID'] = auth.get_last_request_id()
            # return self.redirect(sso_built_url)
        elif 'sso2' in req['get_data']:
            return_to = OneLogin_Saml2_Utils.get_self_url(req) + reverse('attrs')
            return self.redirect(auth.login(return_to))
        elif 'slo' in req['get_data']:
            name_id = None
            session_index = None
            if 'samlNameId' in request.session:
                name_id = request.session['samlNameId']
            if 'samlSessionIndex' in request.session:
                session_index = request.session['samlSessionIndex']

            return self.redirect(auth.logout(name_id=name_id, session_index=session_index))

            # If LogoutRequest ID need to be stored in order to later validate it, do instead
            # slo_built_url = auth.logout(name_id=name_id, session_index=session_index)
            # request.session['LogoutRequestID'] = auth.get_last_request_id()
            #return HttpResponseRedirect(slo_built_url)
        elif 'acs' in req['get_data']:
            request_id = None
            if 'AuthNRequestID' in request.session:
                request_id = request.session['AuthNRequestID']

            auth.process_response(request_id=request_id)
            errors = auth.get_errors()
            not_auth_warn = not auth.is_authenticated()
            if not errors:
                if 'AuthNRequestID' in request.session:
                    del request.session['AuthNRequestID']
                request.session['samlUserdata'] = auth.get_attributes()
                request.session['samlNameId'] = auth.get_nameid()
                request.session['samlSessionIndex'] = auth.get_session_index()
                if 'RelayState' in req['post_data'] and OneLogin_Saml2_Utils.get_self_url(req) != req['post_data']['RelayState']:
                    return self.redirect(auth.redirect_to(req['post_data']['RelayState']))
        elif 'sls' in req['get_data']:
            request_id = None
            if 'LogoutRequestID' in request.session:
                request_id = request.session['LogoutRequestID']
            dscb = lambda: request.session.flush()
            url = auth.process_slo(request_id=request_id, delete_session_cb=dscb)
            errors = auth.get_errors()
            if len(errors) == 0:
                if url is not None:
                    return self.redirect(url)
                else:
                    success_slo = True

        if 'samlUserdata' in request.session:
            paint_logout = True
            if len(request.session['samlUserdata']) > 0:
                attributes = request.session['samlUserdata'].items()

        self.render('index.html',errors=errors,not_auth_warn=not_auth_warn,success_slo=success_slo,attributes=attributes,paint_logout=paint_logout)

class AttrsHandler(tornado.web.RequestHandler):
    def get(request):
        paint_logout = False
        attributes = False

        if 'samlUserdata' in request.session:
            paint_logout = True
            if len(request.session['samlUserdata']) > 0:
                attributes = request.session['samlUserdata'].items()

        self.render('attrs.html',paint_logout=paint_logout,attributes=attributes)

class MetadataHandler(tornado.web.RequestHandler):
    # req = prepare_django_request(request)
    # auth = init_saml_auth(req)
    # saml_settings = auth.get_settings()
    saml_settings = OneLogin_Saml2_Settings(settings=None, custom_base_path=settings.SAML_FOLDER, sp_validation_only=True)
    metadata = saml_settings.get_sp_metadata()
    errors = saml_settings.validate_metadata(metadata)

    if len(errors) == 0:
        resp = HttpResponse(content=metadata, content_type='text/xml')
    else:
        resp = HttpResponseServerError(content=', '.join(errors))
    return resp

def prepare_tornado_request(request):
    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
    #print tornado.httputil.split_host_and_port(request.host)[0]
    result = {
        'https': 'on' if request == 'https' else 'off',
        'http_host': tornado.httputil.split_host_and_port(request.host)[0],
        'script_name': request.path,
        'server_port': tornado.httputil.split_host_and_port(request.host)[1],
        'get_data': request.arguments,
        'post_data': request.arguments,
        # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
        # 'lowercase_urlencoding': True,
        'query_string': request.query
    }
    return result

def init_saml_auth(req):
    auth = OneLogin_Saml2_Auth(req, custom_base_path=Settings.SAML_PATH)
    return auth

if __name__ == "__main__":
    app = Application()
    http_server = tornado.httpserver.HTTPServer(app)
    http_server.listen(8000)
    tornado.ioloop.IOLoop.instance().start()
