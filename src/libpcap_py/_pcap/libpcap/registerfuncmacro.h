#define DECLARE_PYCAP_METHOD(kind, name, _doc) DECLARE_PYCAP_METHOD_##kind(name, _doc)

#define DECLARE_PYCAP_METHOD_VARARGS(name, _doc)                                                   \
    static PyObject* pycap_##name(PyObject* self, PyObject* args);

#define DECLARE_PYCAP_METHOD_KEYWORDS(name, _doc)                                                  \
    static PyObject* pycap_##name(PyObject* self, PyObject* args, PyObject* kwargs);

#define DECLARE_PYCAP_METHOD_FAST_KEYWORDS(name, _doc)                                             \
    static PyObject* pycap_##name(                                                                 \
        PyObject* self, PyObject* const* args, Py_ssize_t nargs, PyObject* kwnames);

#define DECLARE_PYCAP_METHOD_NOARGS(name, _doc)                                                    \
    static PyObject* pycap_##name(PyObject* self, PyObject* args);

#define REGISTER_PYCAP_METHOD(kind, name, doc) REGISTER_PYCAP_METHOD_##kind(name, doc)

#define REGISTER_PYCAP_METHOD_VARARGS(name, doc)                                                   \
    {#name, (PyCFunction)pycap_##name, METH_VARARGS, doc},

#define REGISTER_PYCAP_METHOD_KEYWORDS(name, doc)                                                  \
    {#name, (PyCFunction)pycap_##name, METH_VARARGS | METH_KEYWORDS, doc},

#define REGISTER_PYCAP_METHOD_FAST_KEYWORDS(name, doc)                                             \
    {#name, (PyCFunction)pycap_##name, METH_FASTCALL | METH_KEYWORDS, doc},

#define REGISTER_PYCAP_METHOD_NOARGS(name, doc)                                                    \
    {#name, (PyCFunction)pycap_##name, METH_NOARGS, doc},