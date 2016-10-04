import os
import tornado.ioloop
import tornado.web

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
SAML_FOLDER = os.path.join(BASE_DIR, 'saml')

class MainHandler(tornado.web.RequestHandler):

     def get(self):
        self.render("base.html")

def make_app():
    return tornado.web.Application([
        (r"/", MainHandler),
    ])

if __name__ == "__main__":
    app = make_app()

    application.listen(8000)
    tornado.ioloop.IOLoop.current().start()
