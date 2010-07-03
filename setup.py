from distutils.core import setup, Extension

setup(name="log_reader", version="1.1",
      ext_modules=[Extension("log_reader", ["log_reader.cpp"],
                             libraries=["stdc++"])])
