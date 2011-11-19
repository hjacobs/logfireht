"""A Jinja Handler and tool.  This code is in the public domain.

Usage:
@cherrypy.expose
@cherrypy.tools.jinja(tpl='index.html')
def controller(**kwargs):
    return {

    } # This dict is the template context

"""
import os
thisdir = os.path.join(os.path.dirname(__file__))

import cherrypy
import json as _json
import time
import urllib

import jinja2

def jinja_render(tpl, context):

    context.update({
        'request': cherrypy.request,
        'app_url': cherrypy.request.app.script_name,
    })

    cherrypy.request.template = tmpl = cherrypy.request.jinja_env.get_template(tpl)
    output = tmpl.render(**context)
    return output

class JinjaHandler(cherrypy.dispatch.LateParamPageHandler):
    """Callable which sets response.body."""

    def __init__(self, env, template_name, next_handler):
        self.env = env
        self.template_name = template_name
        self.next_handler = next_handler

    def __call__(self, *args, **kwargs):
        context = {}
        cherrypy.request.jinja_env = self.env
        r = self.next_handler(*args, **kwargs)
        try:
            context.update(r)
        except ValueError, e:
            cherrypy.log('%s (handler for "%s" returned "%s")\n' % (
                e, self.template_name, repr(r)), traceback=True)

        # We wait until this point to do any tasks related to template
        # loading or context building, as it may not be necessary if
        # the first handler causes a response and we never render
        # the template. (Minor Optimization)
        if cherrypy.config.get('template.show_errors', False):
            self.env.undefined = jinja2.DebugUndefined

        return jinja_render(self.template_name, context)

class JinjaLoader(object):
    """A CherryPy 3 Tool for loading Jinja templates."""

    def __init__(self):
        self.template_dir_list = []
        self.env = jinja2.Environment(loader=jinja2.ChoiceLoader(self.template_dir_list),
            line_statement_prefix='#',
            line_comment_prefix='##')
        self.add_template_dir(os.path.join(thisdir, '../templates'))

    def __call__(self, tpl):
        cherrypy.request.handler = JinjaHandler(self.env, tpl, cherrypy.request.handler)

    def add_template_dir(self, directory):
        """Used to add a template directory to the jinja source path."""
        ldr = jinja2.FileSystemLoader(directory)
        self.template_dir_list.insert(0, ldr)
        self.env.loader = jinja2.ChoiceLoader(self.template_dir_list)

    def add_filter(self, func):
        """Decorator which adds the given function to jinja's filters."""
        self.env.filters[func.__name__] = func
        return func

    def add_global(self, func):
        """Decorator which adds the given function to jinja's globals."""
        self.env.globals[func.__name__] = func
        return func



# FIXME: if templates grow more settings, we should consider using a namespace
cherrypy._cpconfig.environments['production']['template.show_errors'] = False
cherrypy._cpconfig.environments['staging']['template.show_errors'] = True
cherrypy._cpconfig.environments['test_suite']['template.show_errors'] = False

loader = JinjaLoader()
cherrypy.tools.jinja = cherrypy.Tool('on_start_resource', loader)

@loader.add_filter
def url(s):
    if type(s) in (str, unicode):
        u = s
    else:
        u = '/'.join(map(lambda x: urllib.quote_plus(x.replace('/', '-.-')), s))
    return cherrypy.url(u)

@loader.add_filter
def msformat(d):
    return '%d ms' % (d * 1000,)

@loader.add_filter
def dtformat(d):
    return d.strftime('%Y-%m-%d %H:%M')

@loader.add_filter
def timeformat(ts):
    return time.strftime('%H:%M:%S', time.localtime(ts))

@loader.add_filter
def bytesizeformat(s):
    if s >= 1000000:
        return '{0:.1f} MB'.format(s * 1.0 / 1000000)
    elif s >= 1000:
        return '{0:.1f} kB'.format(s * 1.0 / 1000)
    return '{0} B'.format(s)

@loader.add_filter
def bitrateformat(s):
    if s >= 1000000:
        return '{0:.1f} Mbit/s'.format(s * 1.0 / 1000000)
    elif s >= 1000:
        return '{0:.1f} kbit/s'.format(s * 1.0 / 1000)
    return '{0:.0f} bit/s'.format(s)

@loader.add_filter
def json(v):
    return _json.dumps(v)

