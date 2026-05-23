#define DECLARE_PYCAP_METHOD(impl, kind, name, _doc)                                               \
    DECLARE_PYCAP_METHOD_IMPL_##impl(kind, name, _doc)

#define DECLARE_PYCAP_METHOD_IMPL_0(kind, name, _doc)                                              \
    static PyObject* pycap_##name(PyObject* self, PyObject* args)                                  \
    {                                                                                              \
        PyErr_SetString(PyExc_NotImplementedError, "pcap_" #name " is not implemented yet");       \
        return NULL;                                                                               \
    }

#define DECLARE_PYCAP_METHOD_IMPL_1(kind, name, _doc)

#define REGISTER_PYCAP_METHOD(impl, kind, name, doc)                                               \
    REGISTER_PYCAP_METHOD_IMPL_##impl(kind, name, doc)

#define REGISTER_PYCAP_METHOD_IMPL_0(kind, name, doc) REGISTER_PYCAP_METHOD_VARARGS(name, doc)

#define REGISTER_PYCAP_METHOD_IMPL_1(kind, name, doc) REGISTER_PYCAP_METHOD_##kind(name, doc)

#define REGISTER_PYCAP_METHOD_VARARGS(name, doc)                                                   \
    {#name, (PyCFunction)pycap_##name, METH_VARARGS, doc},

#define REGISTER_PYCAP_METHOD_KEYWORDS(name, doc)                                                  \
    {#name, (PyCFunction)pycap_##name, METH_VARARGS | METH_KEYWORDS, doc},

#define REGISTER_PYCAP_METHOD_FAST_KEYWORDS(name, doc)                                             \
    {#name, (PyCFunction)pycap_##name, METH_FASTCALL | METH_KEYWORDS, doc},

#define REGISTER_PYCAP_METHOD_NOARGS(name, doc)                                                    \
    {#name, (PyCFunction)pycap_##name, METH_NOARGS, doc},