#include <Python.h>
#include <structmember.h>
#include <time.h>
#include <string>
#include <cstdio>

typedef struct {
  PyObject_HEAD
  PyObject *curline;
  PyObject *pyiterable;
  PyObject *iter;
  std::string *format;
} ApacheReader;

const char *kCOMBINED = \
"%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"";
const char *kCOMMON = "%h %l %u %t \"%r\" %>s %b";

// Ctor expects either a filename or a file object.  Second argument is an
// optional string describing the log file format.  Default format is apache
// combined.
static int
ApacheReader_init(ApacheReader *self, PyObject *args)
{
  char *filename;
  PyObject *pyiterable;
  char *format = NULL;

  // first arg is a string
  if (PyArg_ParseTuple(args, "s|s", &filename, &format)) {
    self->pyiterable = PyFile_FromString(filename, (char*)"r");
  } else {
    PyErr_Clear();
    // maybe first arg is a file object
    if (PyArg_ParseTuple(args, "O|s", &pyiterable, &format)) {
      if (PyIter_Check(pyiterable)) {
        self->pyiterable = pyiterable;
        Py_INCREF(self->pyiterable);
      }
    }
  }

  if (NULL == self->pyiterable) {
    PyErr_SetString(PyExc_TypeError, "expected filename or iterable object");
    return -1;
  }

  self->curline = PyString_FromString("");
  self->iter = PyObject_GetIter(self->pyiterable);
  // default format is apached combined if not provided
  if (format != NULL) {
    self->format = new std::string(format);
  } else {
    self->format = new std::string(kCOMBINED);
  }
  return 0;
}

// When the object is deleted, we need to clean up member vars.
static void
ApacheReader_dealloc(ApacheReader *self)
{
  Py_XDECREF(self->curline);
  Py_XDECREF(self->pyiterable);
  Py_XDECREF(self->iter);
  delete self->format;
  self->ob_type->tp_free((PyObject*)self);
}

// Allow iteration of the object.
static PyObject*
ApacheReader_getiter(ApacheReader *self)
{
  Py_INCREF(self);
  return (PyObject *)self;
}

// Helper method to grab a sequence of characters up to end_token.
// returns the number of characters consumed
int parse_string_token(const char *line, char end_token, std::string *buf) {
  int pos = 0;
  int buf_pos = 0;

  while (line[pos] != '\n' && line[pos] != '\0') {
    // Handle double quote escaped char (e.g., 'foo""bar'). It should be
    // safe to check line[pos + 1] since it shouldn't be pointing past the
    // end of the line.
    if (end_token == '"' && line[pos] == '"' && line[pos + 1] == '"') {
      ++pos;
    } else if (line[pos] == end_token) {
      // Now check to see if the current position is our end token.
      break;
    }
    
    // handle escaped characters
    if (line[pos] == '\\') {
      ++pos;
    }
    buf->append(1, line[pos]);
    ++buf_pos; ++pos;
  }
  return pos;
}

// parse ip addresses
// returns the number of characters consumed
int parse_ips(const char *line, PyObject *ret) {
  PyObject *ips = PyList_New(0);
  std::string temp;
  int offset = parse_string_token(line, ' ', &temp);
  int last_offset = offset;
  while (',' == temp[temp.length() - 1]) {
    PyObject *ip = PyString_FromString(temp.substr(0, temp.length() - 1).c_str());
    PyList_Append(ips, ip);
    Py_DECREF(ip);
    // std::string.clear doesn't work in gcc 2.95
    temp.assign("");
    last_offset = parse_string_token(line + offset + 1, ' ', &temp);
    offset += last_offset + 1;
  }

  // add the final ip address
  PyObject *ip = PyString_FromString(temp.c_str());
  PyList_Append(ips, ip);
  Py_DECREF(ip);

  // add to ret
  PyObject *key = PyString_FromString("ips");
  PyDict_SetItem(ret, key, ips);
  Py_DECREF(key); Py_DECREF(ips);
  return offset;
}

// returns the number of characters consumed
int parse_datetime(const char *line, PyObject *ret) {
  std::string timestamp, timezone;
  int offset = parse_string_token(line + 1, ' ', &timestamp);
  offset += parse_string_token(line + offset + 2, ']', &timezone);

  PyObject *key = PyString_FromString("time");
  PyObject *value;

  tm time_struct;
  if (NULL == strptime(timestamp.c_str(), "%d/%b/%Y:%H:%M:%S", &time_struct)) {
    // invalid format
    PyDict_SetItem(ret, key, Py_None);
  } else {
    // convert to a python datetime object
    PyObject *datetime_mod = PyImport_AddModule("datetime");
    PyObject *datetime_cls = PyObject_GetAttrString(datetime_mod, "datetime");

    // call datetime constructor
    value = PyObject_CallFunction(datetime_cls, (char*)"iiiiii",
                                  time_struct.tm_year + 1900,
                                  time_struct.tm_mon + 1,
                                  time_struct.tm_mday,
                                  time_struct.tm_hour,
                                  time_struct.tm_min,
                                  time_struct.tm_sec);
    Py_XDECREF(datetime_cls);
    PyDict_SetItem(ret, key, value);
    Py_XDECREF(value);
  }
  Py_XDECREF(key);

  key = PyString_FromString("tz");
  value = PyString_FromString(timezone.c_str());
  PyDict_SetItem(ret, key, value);
  Py_XDECREF(key); Py_XDECREF(value);

  // +3 to include [] brackets and space
  return offset + 3;
}

// parse the http request and break it up into separate tokens
int parse_request(const char *line, PyObject *ret, bool escaped) {
  std::string req;
  char end_token = escaped ? '"' : ' ';

  int offset = parse_string_token(line, end_token, &req);
  PyObject *key, *val;
  int first_sp = req.find(" ");
  int second_sp = req.find(" ", first_sp + 1);
  if (first_sp > -1) {
    // GET or POST
    key = PyString_FromString("method");
    val = PyString_FromString(req.substr(0, first_sp).c_str());
    PyDict_SetItem(ret, key, val);
    Py_DECREF(key); Py_DECREF(val);
    if (second_sp == -1) {
      // request path, protocol is missing
      key = PyString_FromString("path");
      val = PyString_FromString(req.substr(first_sp + 1).c_str());

      PyDict_SetItem(ret, key, val);
      Py_DECREF(key); Py_DECREF(val);
    } else {
      // request path and protocol version
      key = PyString_FromString("path");
      val = PyString_FromString(req.substr(first_sp + 1,
                                           second_sp - first_sp - 1).c_str());
      PyDict_SetItem(ret, key, val);
      Py_DECREF(key); Py_DECREF(val);

      key = PyString_FromString("protocol");
      val = PyString_FromString(req.substr(second_sp + 1).c_str());
      PyDict_SetItem(ret, key, val);
      Py_DECREF(key); Py_DECREF(val);
    }
  } else {
    key = PyString_FromString("bad_request");
    val = PyString_FromString(req.c_str());
    PyDict_SetItem(ret, key, val);
    Py_DECREF(key); Py_DECREF(val);
  }

  return offset;
}

// parse the next string token and assign it to name
// returns the number of characters consumed
int parse_string(const char *line, PyObject *ret, const char *name, bool escaped) {
  std::string temp;
  char end_token = escaped ? '"' : ' ';
  int pos = parse_string_token(line, end_token, &temp);
  PyObject *key = PyString_FromString(name);
  PyObject *val = PyString_FromString(temp.c_str());
  PyDict_SetItem(ret, key, val);
  Py_DECREF(key); Py_DECREF(val);

  return pos;
}

// parse the next int token and assign it to name
// returns the number of characters consumed
int parse_int(const char *line, PyObject *ret, const char *name, bool escaped) {
  std::string temp;
  char end_token = escaped ? '"' : ' ';
  int pos = parse_string_token(line, end_token, &temp);
  PyObject *val;
  val = PyInt_FromString(const_cast<char*>(temp.c_str()), NULL, 10);
  if (NULL == val) {
    // failed to cast as int, use -1 instead
    PyErr_Clear();
    val = PyInt_FromLong(-1);
  }
  PyObject *key = PyString_FromString(name);
  PyDict_SetItem(ret, key, val);
  Py_DECREF(key); Py_DECREF(val);

  return pos;
}

// The actual work of parsing a log line.
static PyObject *
parse_line(char *line, const int length, const std::string &format)
{
  // the return dictionary
  PyObject *ret = PyDict_New();

  // parse the format string
  int line_pos = 0, end;
  bool escaped = false; // keep track of whether we're inside quotes or not
  for (unsigned int i = 0; i < format.length(); ++i) {
    // debugging
    //fprintf(stderr, "\nformat:|%s|\n", format.c_str() + i);
    //fprintf(stderr, "    lf:|%s|\n", line + line_pos);
    char f = format[i];
    if ('%' == f) {
      // handle special escapes
      ++i;
      f = format[i];
      int offset = 0;

      switch(f) {
        case 'h': // hostnames (ips)
          offset = parse_ips(line + line_pos, ret);
          break;

        case 'l': // ident
          offset = parse_string(line + line_pos, ret, "ident", escaped);
          break;

        case 'u': // username
          offset = parse_string(line + line_pos, ret, "username", escaped);
          break;

        case 't': // time
          offset = parse_datetime(line + line_pos, ret);
          break;

        case 'r': // request
          offset = parse_request(line + line_pos, ret, escaped);
          break;

        case 'b': // size
          offset = parse_int(line + line_pos, ret, "size", escaped);
          break;

        case 'D': // elapsed time
          offset = parse_int(line + line_pos, ret, "elapsed", escaped);
          break;

        case '>':
          ++i;
          f = format[i];
          switch (f) {
            case 's': // http status code
              offset = parse_int(line + line_pos, ret, "status", escaped);
              break;

            default:
              //sprintf("unknown format char: %c\n", f);
              PyErr_SetString(PyExc_ValueError, "Unknown format char after >");
              return NULL;
              break;
          }
          break;

        case '{': // named format
          ++i;
          end = format.find("}i", i);
          if (end > -1) {
            std::string named_format = format.substr(i, end - i);
            if ("Referer" == named_format) {
              offset = parse_string(line + line_pos, ret, "referer", escaped);
            } else if ("User-Agent" == named_format) {
              offset = parse_string(line + line_pos, ret, "user-agent",
                                    escaped);
            } else if ("Host" == named_format) {
              offset = parse_string(line + line_pos, ret, "host",
                                    escaped);
            } else {
              offset = parse_string(line + line_pos, ret, named_format.c_str(),
                                    escaped);
            }
            // skip }i at the end of the format string
            i = end + 1;
          } else {
            PyErr_SetString(PyExc_ValueError, "closing token not found }i");
            return NULL;
          }
          break;

        default:
          //sprintf("unknown format char: %c\n", f);
          PyErr_SetString(PyExc_ValueError, "Unknown format char");
          return NULL;
          break;
      }
      line_pos += offset;
    } else {
      // match token exactly
      if (line[line_pos] != f) {
        char err[1024];
        sprintf(err, "Input doesn't match format string: %c != %c", f,
                line[line_pos]);
        PyErr_SetString(PyExc_ValueError, err);
        return NULL;
      }
      if ('"' == line[line_pos]) {
        escaped = !escaped;
      }
      ++line_pos;
    }
  }

  return ret;
}

static PyObject *
ApacheReader_iternext(ApacheReader *self)
{
  PyObject *pyline;

  // read the next line
  pyline = PyIter_Next(self->iter);
  if (NULL == pyline) {
    return NULL;
  }

  char *line;
  Py_ssize_t length;
  if (-1 == PyString_AsStringAndSize(pyline, &line, &length)) {
    // null character in string; give up
    return NULL;
  }

  // skip blank lines
  while (length == 1 && line[0] == '\n') {
    pyline = PyIter_Next(self->iter);
    if (NULL == pyline) {
      return NULL;
    }
    if (-1 == PyString_AsStringAndSize(pyline, &line, &length)) {
      // null character in string; give up
      return NULL;
    }
  }

  // assign the raw text to curline
  Py_XDECREF(self->curline);
  self->curline = pyline;

  return parse_line(line, length, *self->format);
}

PyDoc_STRVAR(log_reader_parse_line_doc,
"parse_line(log_line, format = COMBINED) -> dict\n\
    Parse the supplied 'log_line' using the optional 'format'.\n\
    Returns a dictionary of log fields");

// This is a static method for parsing a single line.
static PyObject *
ApacheReader_parse_line(PyObject *null_self, PyObject *args, PyObject *kw_args)
{
  static char *keywords[] = { (char*)"log_line", (char*)"format", NULL };
  char *line = NULL, *fmt = NULL;
  int llen = -1;
  std::string format;
  PyObject *ret;


  if (!PyArg_ParseTupleAndKeywords(args, kw_args, "s#|s", keywords,
      &line, &llen, &fmt))
    return NULL;

  if (0 == llen) {
    Py_INCREF(Py_None);
    return Py_None;
  }

  if (fmt == NULL)
    format = std::string(kCOMBINED);
  else
    format = std::string(fmt);

  ret = parse_line(line, llen, format);

  return ret;
}

static PyMemberDef ApacheReader_members[] = {
  {(char*)"curline", T_OBJECT_EX, offsetof(ApacheReader, curline), 0,
   (char*)"the last line that was read"},
  {NULL}  /* Sentinel */
};

static PyMethodDef ApacheReader_methods[] = {
  { "parse_line",
    (PyCFunction)ApacheReader_parse_line,
    METH_VARARGS|METH_KEYWORDS|METH_STATIC,
    log_reader_parse_line_doc },
  {NULL}
};

static PyTypeObject ApacheReaderType = {
  PyObject_HEAD_INIT(NULL)
  0,				/* ob_size           */
  "log_reader.ApacheReader",			/* tp_name           */
  sizeof(ApacheReader),		/* tp_basicsize      */
  0,				/* tp_itemsize       */
  /* methods */
  (destructor)ApacheReader_dealloc,				/* tp_dealloc        */
  0,				/* tp_print          */
  0,				/* tp_getattr        */
  0,				/* tp_setattr        */
  0,				/* tp_compare        */
  0,				/* tp_repr           */
  0,				/* tp_as_number      */
  0,				/* tp_as_sequence    */
  0,				/* tp_as_mapping     */
  0,				/* tp_hash           */
  0,				/* tp_call           */
  0,				/* tp_str            */
  0,				/* tp_getattro       */
  0,				/* tp_setattro       */
  0,				/* tp_as_buffer      */
  Py_TPFLAGS_DEFAULT,		/* tp_flags          */
  "A fast Apache log parser.\n\n",			/* tp_doc            */
  0,				/* tp_traverse       */
  0,				/* tp_clear          */
  0,				/* tp_richcompare    */
  0,				/* tp_weaklistoffset */
  (getiterfunc)ApacheReader_getiter,				/* tp_iter           */
  (getiterfunc)ApacheReader_iternext,				/* tp_iternext       */
  ApacheReader_methods,	     		/* tp_methods        */
  ApacheReader_members,			    /* tp_members        */
  0,				/* tp_getset         */
  0,				/* tp_base           */
  0,				/* tp_dict           */
  0,				/* tp_descr_get      */
  0,				/* tp_descr_set      */
  0,  			/* tp_dictoffset     */
  (initproc)ApacheReader_init,		/* tp_init           */
};

PyMODINIT_FUNC
initlog_reader(void)
{
  PyObject *m;

  ApacheReaderType.tp_new = PyType_GenericNew;
  if (PyType_Ready(&ApacheReaderType) < 0)
    return;

  // module name, methods, doc string
  m = Py_InitModule3("log_reader", NULL,
         "fast processing of apache log files");
  if (m == NULL) {
    printf("failed to load log_reader module\n");
    return;
  }

  Py_INCREF(&ApacheReaderType);
  PyModule_AddObject(m, "ApacheReader", (PyObject *)&ApacheReaderType);
  PyObject *datetime = PyImport_ImportModule("datetime");
  PyModule_AddObject(m, "datetime", datetime);

  // add class/static variables to the object
  PyObject *attrs = ApacheReaderType.tp_dict;
  PyDict_SetItemString(attrs, "COMMON", PyString_FromString(kCOMMON));
  PyDict_SetItemString(attrs, "COMBINED", PyString_FromString(kCOMBINED));
}
