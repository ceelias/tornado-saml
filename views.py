import tornado.ioloop
import tornado.web
import Settings
import tornado.httpserver

class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", MainHandler)
        ]
        settings = {
            "template_path": Settings.TEMPLATE_PATH,
            "saml_path": Settings.SAML_PATH,
        }
        tornado.web.Application.__init__(self, handlers, **settings)


class MainHandler(tornado.web.RequestHandler):
     def get(self):
        self.render("index.html")

if __name__ == "__main__":
    app = Application()
    http_server = tornado.httpserver.HTTPServer(app)
    http_server.listen(8000)
    tornado.ioloop.IOLoop.instance().start()
