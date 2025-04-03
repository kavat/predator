from setuptools import setup, Extension

modsecurity_module = Extension(
    '_modsecurity',
    sources=['modsecurity_wrap.c'],
    libraries=['modsecurity'],
    include_dirs=['/usr/include/modsecurity'],
    library_dirs=['/usr/lib/x86_64-linux-gnu']
)

setup(
    name='modsecurity',
    version='1.0',
    author='Tuonome',
    description='Python wrapper per ModSecurity 3.0.9',
    ext_modules=[modsecurity_module],
    py_modules=['modsecurity'],
)
