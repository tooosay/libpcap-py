/* This program is a C extension that simplifies the usage of libpcap in Python.
 * Repository: https://github.com/tooosay/libpcap-py
 * Author: Tooosay
 * Free to use, copy, modify, and distribute.
 * Distributed under the terms of BSD-2clause license
 * (c) 2023 Tooosay
 */

#define THIS_VERSION " python wrapper version 0.1.0"
#define THIS_MODULE_NAME "libpcap-py"
#define PY_SSIZE_T_CLEAN
#include <python3.10/Python.h>
#include <python3.10/structmember.h>
// #include <python3.10/object.h>
#include <pcap.h>

/* type declaration */
// types
typedef struct{
    PyObject_HEAD
    pcap_t *pcap;
}PcapObject;

static void PcapObject_dealloc(PyObject* self);
// define PcapObject
static PyTypeObject PcapObjectType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "pcap_t",
    .tp_doc = "pcap struct wrapper",
    .tp_basicsize = sizeof(PcapObject),
    .tp_itemsize = 0,
    .tp_new = PyType_GenericNew,
    .tp_alloc = PyType_GenericAlloc,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_dealloc = PcapObject_dealloc,
};

static PyObject* PcapObject_New(pcap_t* pcap){
    PcapObject *obj = (PcapObject*)PcapObjectType.tp_alloc(&PcapObjectType, 0);
    if (!obj) return NULL;
    obj->pcap = pcap;
    return (PyObject*)obj;
}

static void PcapObject_dealloc(PyObject* self) {
    PcapObject *tp =(PcapObject*)self;
    if (tp->pcap) {
        pcap_close(tp->pcap);
    }
    Py_TYPE(tp)->tp_free((PyObject*)tp);
}

typedef struct{
    PyObject_HEAD
    //struct pcap_pkthdr* pkthdr;
    PyObject *tv_sec;
    PyObject *tv_usec;
    PyObject *len;
    PyObject *caplen;
}HeaderObject;
static PyMemberDef HeaderObject_members[] = {
    {"tv_sec", T_OBJECT_EX, offsetof(HeaderObject, tv_sec), 0,"timestamp second"},
    {"tv_usec", T_OBJECT_EX, offsetof(HeaderObject, tv_usec), 0,"timestamp microsecond"},
    {"len", T_OBJECT_EX, offsetof(HeaderObject, len), 0,"packet length"},
    {"caplen", T_OBJECT_EX, offsetof(HeaderObject,caplen), 0, "proportional length"},
    {NULL}  /* Sentinel */
};

static void HeaderObject_dealloc(PyObject* self);
static PyTypeObject HeaderObjectType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "packetHeader",
    .tp_doc = "pcap_pkhdr struct wrapper",
    .tp_basicsize = sizeof(HeaderObject),
    .tp_itemsize = 0,
    .tp_new = PyType_GenericNew,
    .tp_alloc = PyType_GenericAlloc,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_dealloc = HeaderObject_dealloc,
    .tp_members = HeaderObject_members,
};

static PyObject* HeaderObject_New(struct pcap_pkthdr* header){
    HeaderObject *obj = (HeaderObject*)HeaderObjectType.tp_alloc(&HeaderObjectType, 0);
    if (!obj) return NULL;
    obj->tv_sec = PyLong_FromLong(header->ts.tv_sec);
    obj->tv_usec = PyLong_FromLong(header->ts.tv_usec);
    obj->len = PyLong_FromLong(header->len);
    obj->caplen = PyLong_FromLong(header->caplen);
    return (PyObject*)obj;
}

static void HeaderObject_dealloc(PyObject* self){
    HeaderObject *tp =(HeaderObject*)self;
    Py_TYPE(tp)->tp_free(tp->tv_sec);
    Py_TYPE(tp)->tp_free(tp->tv_usec);
    Py_TYPE(tp)->tp_free(tp->caplen);
    Py_TYPE(tp)->tp_free(tp->len);
    Py_TYPE(tp)->tp_free((PyObject*)tp);
}

typedef struct {
    PyObject_HEAD
    unsigned int recv;
    unsigned int drop;
    unsigned int ifdrop;
#ifdef _WIN32
    unsigned int capt;
    unsigned int sent;
    unsigned int netdrop;
#endif
} PcapStatObject;

static PyMemberDef PcapStat_members[] = {
    {"recv", T_UINT, offsetof(PcapStatObject, recv), READONLY, "Number of packets received"},
    {"drop", T_UINT, offsetof(PcapStatObject, drop), READONLY, "Number of packets dropped"},
    {"ifdrop", T_UINT, offsetof(PcapStatObject, ifdrop), READONLY, "Drops by interface"},
#ifdef _WIN32
    {"capt", T_UINT, offsetof(PcapStatObject, capt), READONLY, "Number of packets that reach the application"},
    {"sent", T_UINT, offsetof(PcapStatObject, sent), READONLY, "Number of packets sent by the server on the network"},
    {"netdrop", T_UINT, offsetof(PcapStatObject, netdrop), READONLY, "Number of packets lost on the network"},
#endif
    {NULL}
};

static PyTypeObject PcapStatObjectType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "PcapStat",
    .tp_basicsize = sizeof(PcapStatObject),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_members = PcapStat_members,
};

static PyObject* PcapStatObject_New(struct pcap_stat *stat){
    PcapStatObject *obj = (PcapStatObject*)PcapStatObjectType.tp_alloc(&PcapStatObjectType, 0);
    obj->recv = stat->ps_recv;
    obj->drop = stat->ps_drop;
    obj->ifdrop = stat->ps_ifdrop;
#ifdef _WIN32
    obj->capt = stat->ps_capt;
    obj->sent = stat->ps_sent;
    obj->netdrop = stat->ps_netdrop;
#endif
    return (PyObject*)obj;
}

typedef struct {
    PyObject_HEAD
    struct bpf_program *fp;
}BpfProgramObject;

static PyTypeObject BpfProgramObjectType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "bpf_program",
    .tp_doc = "bpf_program wrapper",
    .tp_basicsize = sizeof(BpfProgramObject),
    .tp_itemsize = 0,
    .tp_new = PyType_GenericNew,
    .tp_alloc = PyType_GenericAlloc,
    .tp_flags = Py_TPFLAGS_DEFAULT,
};

static PyObject* BpfProgramObject_New(struct bpf_program* fp){
    BpfProgramObject *obj = (BpfProgramObject*)BpfProgramObjectType.tp_alloc(&BpfProgramObjectType, 0);
    if (!obj) return NULL;
    obj->fp = fp;
    return (PyObject*)obj;
}


static PyStructSequence_Field lookupnetTupleFields[] = {
    {"address", "network interface address (netp)"},
    {"mask", "network mask"},
    {NULL}
};

// Create the type object for the named tuple
static PyStructSequence_Desc lookupnetTupleDesc = {
    "lookupnetTuple",
    NULL,
    lookupnetTupleFields,
    2, // Number of fields
};

static PyStructSequence_Field packetTupleFields[] = {
    {"packet", "original packet"},
    {"tv_sec", "timestamp -- seconds"},
    {"tv_usec", "timestamp -- micro seconds"},
    {"len", "length this packet (off wire)"},
    {"caplen", "lenght of portion present"},
    {NULL}
};

static PyStructSequence_Desc packetTupleDesc = {
    "packetTuple",
    NULL,
    packetTupleFields,
    5,
};

static PyStructSequence_Field argTupleFields[] = {
    {"args", "arguments passed by user"},
    {"header", "packetHeader object passed implicitly"},
    {"packet", "packet data passed implicitly"},
    {NULL}
};

static PyStructSequence_Desc argTupleDesc = {
    "argTuple",
    NULL,
    argTupleFields,
    3,
};

static PyTypeObject lookupnetTupleType;
static PyTypeObject packetTupleType;
static PyTypeObject argTupleType;



/* Methods */
/* lookupfunctions */

// pcap_lookupdev (pcap_findalldevs)
// ‘pcap_lookupdev’ is deprecated: use 'pcap_findalldevs' and use the first device [-Wdeprecated-declarations]
// this function mocks pcap_lookupdev just by returning firsrt device name of pcap_findalldevs
static PyObject* pycap_lookupdev(PyObject* self, PyObject* args){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs = NULL;
    if (pcap_findalldevs(&alldevs, errbuf) < 0){
        PyErr_SetString(PyExc_RuntimeError, errbuf);
        return NULL;
    }
    PyObject *device_name = PyUnicode_FromString(alldevs->name);
    pcap_freealldevs(alldevs);
    return device_name;
}

//pcap_findalldevs
static PyObject* pycap_findalldevs(PyObject* self, PyObject* args){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs = NULL;
    struct sockaddr *tmp;
    PyObject *list = PyList_New(0);

    if (pcap_findalldevs(&alldevs, errbuf) < 0){
        PyErr_SetString(PyExc_RuntimeError, errbuf);
        return NULL;
    }else{
        for (pcap_if_t *dev = alldevs; dev != NULL; dev = dev->next){
            PyObject *dev_dict = PyDict_New();
            PyObject *dev_dict_inner = PyDict_New();
            PyDict_SetItemString(dev_dict,"name",PyUnicode_FromString(dev->name));
            PyObject *description = (dev->description != NULL) ? PyUnicode_FromString(dev->description) : Py_None;
            PyDict_SetItemString(dev_dict,"description",description);
            PyDict_SetItemString(dev_dict, "flags", PyLong_FromUnsignedLong(dev->flags));
            PyObject *addresses = (dev->addresses != NULL) ? dev_dict_inner : Py_None;
            PyDict_SetItemString(dev_dict, "addresses", addresses);
            if (dev->addresses){
                tmp = dev->addresses->addr;
                if (tmp){
                    PyObject *_dict = PyDict_New();
                    PyDict_SetItemString(dev_dict_inner, "addr", _dict);
                    PyDict_SetItemString(_dict, "sa_family", PyLong_FromUnsignedLong(tmp->sa_family));
                    PyDict_SetItemString(_dict, "sa_data", PyUnicode_FromString(tmp->sa_data));
                }else{
                    PyDict_SetItemString(dev_dict_inner, "addr", Py_None);
                }
                tmp = dev->addresses->broadaddr;
                if (tmp){
                    PyObject *_dict = PyDict_New();
                    PyDict_SetItemString(dev_dict_inner, "broadaddr", _dict);
                    PyDict_SetItemString(_dict, "sa_family", PyLong_FromUnsignedLong(tmp->sa_family));
                    PyDict_SetItemString(_dict, "sa_data", PyUnicode_FromString(tmp->sa_data));
                }else{
                    PyDict_SetItemString(dev_dict_inner, "broadaddr", Py_None);
                }
                tmp = dev->addresses->dstaddr;
                if (tmp){
                    PyObject *_dict = PyDict_New();
                    PyDict_SetItemString(dev_dict_inner, "dstaddr", _dict);
                    PyDict_SetItemString(_dict, "sa_family", PyLong_FromUnsignedLong(tmp->sa_family));
                    PyDict_SetItemString(_dict, "sa_data", PyUnicode_FromString(tmp->sa_data));
                }else{
                    PyDict_SetItemString(dev_dict_inner, "dstaddr", Py_None);
                }
                tmp = dev->addresses->netmask;
                if (tmp){
                    PyObject *_dict = PyDict_New();
                    PyDict_SetItemString(dev_dict_inner, "netmask", _dict);
                    PyDict_SetItemString(_dict, "sa_family", PyLong_FromUnsignedLong(tmp->sa_family));
                    PyDict_SetItemString(_dict, "sa_data", PyUnicode_FromString(tmp->sa_data));
                }else{
                    PyDict_SetItemString(dev_dict_inner, "netmask", Py_None);
                }
            }
            PyList_Append(list, dev_dict);
            Py_DECREF(dev_dict);
        }
    }
    pcap_freealldevs(alldevs);
    return list;
}

//pcap_lookupnet
static PyObject* pycap_lookupnet(PyObject *self, PyObject *args){
    bpf_u_int32 netp;     /* ip address of interface */
    bpf_u_int32 maskp;    /* subnet mask of interface */
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *device;
    PyObject *namedTuple = PyStructSequence_New(&lookupnetTupleType);

    if (!PyArg_ParseTuple(args,"s",&device))
        return NULL;
    if (pcap_lookupnet (device, &netp, &maskp, errbuf) == -1){
        PyErr_SetString(PyExc_RuntimeError, errbuf);
        return NULL;
    }

    PyTuple_SetItem(namedTuple, 0,PyLong_FromLong(netp));
    PyTuple_SetItem(namedTuple, 1,PyLong_FromLong(maskp));
    return namedTuple;
}

// pcap_freealldevs will not be implemented

/* Packet-Capture functions */

// pcap_open_live
static PyObject* pycap_open_live(PyObject *self, PyObject *args, PyObject *kwargs) {
    const char *device;
    int snaplen = 65535;
    int promisc = 0; // 0 for false in promiscuous mode
    int to_ms = 0; // snif until error
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = NULL;
    static char *keywords[] = {"device", "snapshot_len", "promiscuous_mode", "timeout_ms", NULL };
    if(!PyArg_ParseTupleAndKeywords(args, kwargs,"s|ipi", keywords, &device, &snaplen, &promisc, &to_ms))
        return NULL;
    pcap = pcap_open_live(device, snaplen, promisc, to_ms, errbuf);
    if(!pcap){
        PyErr_SetString(PyExc_RuntimeError, errbuf);
        return NULL;
    }
    PyObject *result = PcapObject_New(pcap);
    return result;
}

// pcap_next
static PyObject* pycap_next(PyObject *self, PyObject *args, PyObject *kwargs) {
    static char *keywords[] = {"pcap", NULL };
    PcapObject* pcap;
    struct pcap_pkthdr h;
    PyObject *namedTuple = PyStructSequence_New(&packetTupleType);

    if(!PyArg_ParseTupleAndKeywords(args,kwargs,"O!",keywords,&PcapObjectType,&pcap))
        return NULL;

    const char *packet = (const char*)pcap_next(pcap->pcap,&h);
    if(!packet){
        PyErr_SetString(PyExc_RuntimeError, "Could not grub packet");
        return NULL;
    }
    PyObject *packetobj = Py_BuildValue("y#", packet, h.len); //bytes like object
    PyObject *sec = PyLong_FromLong(h.ts.tv_sec);
    PyObject *usec = PyLong_FromLong(h.ts.tv_usec);
    PyObject *len = PyLong_FromLong(h.len);
    PyObject *caplen = PyLong_FromLong(h.caplen);
    PyTuple_SetItem(namedTuple, 0, packetobj);
    PyTuple_SetItem(namedTuple, 1, sec);
    PyTuple_SetItem(namedTuple, 2, usec);
    PyTuple_SetItem(namedTuple, 3, len);
    PyTuple_SetItem(namedTuple, 4, caplen);
    // Py_DECREF(packetobj);
    // Py_DECREF(sec);
    // Py_DECREF(usec);
    // Py_DECREF(len);
    // Py_DECREF(caplen);
    return namedTuple;
}


// this is not implemented yet
// pcap_next_ex
// static PyObject* pycap_next_ex(PyObject *self, PyObject *args, PyObject *kwargs){} 

// pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
// callback functions
// callback function stored
PyObject *py_callback = NULL;
PyObject *callback_args = NULL;
void callback(PyObject *header, PyObject *packet){
    PyObject *args = PyStructSequence_New(&argTupleType);
    PyTuple_SetItem(args, 0, callback_args);
    PyTuple_SetItem(args, 1, header);
    PyTuple_SetItem(args, 2, packet);

    PyObject_CallOneArg(py_callback, args);

    // Py_DECREF(callback_arglist);
    // Py_DECREF(result);
    // Py_DECREF(arglist);
    // Py_DECREF(py_callback);
    // Py_INCREF(Py_None);
}
void callback_function(u_char *user, const struct pcap_pkthdr *header,const u_char * packet){
    PyObject *hdr = HeaderObject_New((struct pcap_pkthdr*)header);
    PyObject *pckt;
    if (packet == NULL){
        Py_INCREF(Py_None);
        pckt = Py_None;
    }else{
        pckt = Py_BuildValue("y#",(const char*)packet,header->len);
    }
    Py_INCREF(pckt);
    Py_INCREF(hdr);
    callback(hdr, pckt);
    Py_DECREF(pckt);
    Py_DECREF(hdr);    
}
static PyObject* pycap_loop(PyObject *self, PyObject *args, PyObject *kwargs){
    static char *keywords[] = {"pcap","callback", "args", "count",NULL};
    int cnt = -1; //negative value is loop forever
    PyObject *user = NULL;
    PyObject *func;
    PcapObject *pcap;
    if(!PyArg_ParseTupleAndKeywords(args, kwargs, "OO|Oi", keywords,/* &PcapObjectType,*/ &pcap, &func, &user, &cnt)){
        return NULL;
    }
    if (!PyCallable_Check(func)) {
            PyErr_SetString(PyExc_TypeError, "parameter must be callable");
            return NULL;
    }
    Py_XINCREF(func);
    // Py_XDECREF(py_callback);
    py_callback = func;
    Py_XINCREF(py_callback);
    Py_XDECREF(callback_args);
    if(user == NULL){
        callback_args = Py_None;
    }else{
        callback_args = user;
    }
    Py_XINCREF(callback_args);
    int result = pcap_loop(pcap->pcap, cnt, callback_function, NULL);
    Py_XDECREF(py_callback);
    Py_XDECREF(callback_args);
    return PyLong_FromLong(result);
}

//pcap_dispatch
static PyObject *pycap_dispatch(PyObject *self, PyObject *args, PyObject *kwargs){
    static char *keywords[] = {"pcap","callback", "args", "count",NULL};
    int cnt = -1; //negative value is loop forever
    PyObject *user = NULL;
    PyObject *func;
    PcapObject *pcap;
    if(!PyArg_ParseTupleAndKeywords(args, kwargs, "OO|Oi", keywords,/* &PcapObjectType,*/ &pcap, &func, &user, &cnt)){
        return NULL;
    }
    if (!PyCallable_Check(func)) {
            PyErr_SetString(PyExc_TypeError, "parameter must be callable");
            return NULL;
    }
    Py_XINCREF(func);
    // Py_XDECREF(py_callback);
    py_callback = func;
    Py_XINCREF(py_callback);
    Py_XDECREF(callback_args);
    if(user == NULL){
        callback_args = Py_None;
    }else{
        callback_args = user;
    }
    Py_XINCREF(callback_args);
    int result = pcap_dispatch(pcap->pcap, cnt, callback_function, NULL);
    Py_XDECREF(py_callback);
    Py_XDECREF(callback_args);
    return PyLong_FromLong(result);
}

// pcap_setnonblock
static PyObject *pycap_setnonblock(PyObject *self, PyObject *args){
    PcapObject *pcap_obj;
    int nonblock = 1;
    char errbuf[PCAP_ERRBUF_SIZE];
    if(!PyArg_ParseTuple(args, "O!|p", &PcapObjectType, &pcap_obj,&nonblock)){
        return NULL;
    }
    if(pcap_setnonblock(pcap_obj->pcap, nonblock, errbuf)<0){
        PyErr_SetString(PyExc_RuntimeError, errbuf);
        return NULL;
    }
    if(Py_REFCNT(pcap_obj) > 1){
        Py_INCREF(pcap_obj);
        return (PyObject*) pcap_obj;
    }
    Py_RETURN_NONE;    
}

// pcap_getnonblock
static PyObject *pycap_getnonblock(PyObject *self, PyObject *args){
    PcapObject *pcap_obj;
    char errbuf[PCAP_ERRBUF_SIZE];
    if(!PyArg_ParseTuple(args, "O!", &PcapObjectType, &pcap_obj)){
        return NULL;
    }
    int result = pcap_getnonblock(pcap_obj->pcap, errbuf);
    if(result < 0){
        PyErr_SetString(PyExc_RuntimeError, errbuf);
        return NULL;    
    }
    return PyBool_FromLong(result);
}

// pcap_set_datalink
// returns boolean representing success or failure
static PyObject *pycap_set_datalink(PyObject *self, PyObject *args){
    PcapObject *pcap_obj;
    int dlt;
    if(!PyArg_ParseTuple(args, "O!i", &PcapObjectType, &pcap_obj, &dlt)){
        return NULL;
    }
    int result = pcap_set_datalink(pcap_obj->pcap, dlt); // 0 success -1 fail
    return PyBool_FromLong(result+1); // 1 True 0 False
}

// pcap_compile
static PyObject *pycap_compile(PyObject *self, PyObject *args, PyObject *kwards){
    PcapObject *pcap_obj;
    char *filter;
    int optimize = 0;
    PyObject *optbool = Py_False;
    bpf_u_int32 netmask;
    struct bpf_program *fp = (struct bpf_program*)calloc(1, sizeof(struct bpf_program));
    char *keywords[] = {"pcap","filter", "netmask", "optimize",NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwards, "O!si|O!", keywords, &PcapObjectType, &pcap_obj, &filter, &netmask, &PyBool_Type, &optimize)){
        return NULL;
    }
    optimize = PyObject_IsTrue(optbool);
    if (pcap_compile(pcap_obj->pcap, fp, filter, optimize, netmask)<0){
        PyErr_SetString(PyExc_RuntimeError, pcap_geterr(pcap_obj->pcap));
        return NULL;
    }
    PyObject *result = BpfProgramObject_New(fp);
    return result;
}

// pcap_compile_nopcap
static PyObject *pycap_compile_nopcap(PyObject *self, PyObject *args, PyObject *kwards){
    int snaplen;
    int linktype;
    char *filter;
    int optimize = 0;
    PyObject *optbool = Py_False;
    bpf_u_int32 netmask;
    struct bpf_program fp;
    char *keywords[] = {"snaplen","linktype","filter", "netmask", "optimize",NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwards, "O!si|O!", keywords, &snaplen, &linktype, &filter, &netmask, &PyBool_Type, &optimize)){
        return NULL;
    }
    optimize = PyObject_IsTrue(optbool);
    if (pcap_compile_nopcap(snaplen, linktype, &fp, filter, optimize, netmask)<0){
        PyErr_SetString(PyExc_RuntimeError, "failed to compile to BPF filter");
        return NULL;
    }
    PyObject *result = BpfProgramObject_New(&fp);
    return result;
}

// pcap_setfilter
static PyObject *pycap_setfilter(PyObject *self, PyObject *args){
    PcapObject *pcap_obj;
    BpfProgramObject *bpf_obj;
    if(!PyArg_ParseTuple(args, "O!O!", &PcapObjectType, &pcap_obj, &BpfProgramObjectType, &bpf_obj)){
        return NULL;
    }
    if(pcap_setfilter(pcap_obj->pcap, bpf_obj->fp)<0){
        PyErr_SetString(PyExc_RuntimeError, pcap_geterr(pcap_obj->pcap));
        return NULL;
    }
    if(Py_REFCNT(pcap_obj) > 1){
        Py_INCREF(pcap_obj);
        return (PyObject*) pcap_obj;
    }
    Py_RETURN_NONE;  
}

// pcap_freecode
static PyObject *pycap_freecode(PyObject *self, PyObject *args){
    BpfProgramObject *bpf_obj;
    if(!PyArg_ParseTuple(args, "O!", &BpfProgramObjectType, &bpf_obj)){
        return NULL;
    }
    pcap_freecode(bpf_obj->fp);
    Py_XDECREF(bpf_obj);
    Py_RETURN_NONE;
}

// pcap_breakloop
static PyObject *pycap_breakloop(PyObject *self, PyObject *args){
    PcapObject *pcap_obj;
    if(!PyArg_ParseTuple(args, "O!", &PcapObjectType, &pcap_obj)){
        return NULL;
    }
    pcap_breakloop(pcap_obj->pcap);
    Py_RETURN_NONE;
}

// pcap_fileno
static PyObject *pycap_fileno(PyObject *self, PyObject *args){
    PcapObject *pcap_obj;
    if(!PyArg_ParseTuple(args, "O!", &PcapObjectType, &pcap_obj)){
        return NULL;
    }
    int result = pcap_fileno(pcap_obj->pcap);
    if(result < 0){
        PyErr_SetString(PyExc_RuntimeError, pcap_geterr(pcap_obj->pcap));
        return NULL;
    }
    return PyLong_FromLong(result);
}
// pcap_close
static PyObject *pycap_close(PyObject *self, PyObject *args){
    PcapObject *pcap_obj;
    if(!PyArg_ParseTuple(args, "O!", &PcapObjectType, &pcap_obj)){
        return NULL;
    }
    pcap_close(pcap_obj->pcap);
    Py_XDECREF(pcap_obj);
    Py_RETURN_NONE;
}
// pcap_open_dead
static PyObject *pycap_open_dead(PyObject *self, PyObject *args, PyObject *kwargs){
    char *keywords[] = {"linktype", "snaplen", NULL};
    int linktype;
    int snaplen;
    pcap_t *pcap;
    if(!PyArg_ParseTupleAndKeywords(args, kwargs, "ii", keywords, &linktype, &snaplen)){
        return NULL;
    }
    pcap = pcap_open_dead(linktype, snaplen);
    if(pcap == NULL){
        Py_RETURN_NONE;
    }
    PyObject *result = PcapObject_New(pcap);
    return result;
}

/* Status Functions */
// pcap_datalink
static PyObject *pycap_datalink(PyObject *self, PyObject *args){
    PcapObject *pcap_obj;
    if(!PyArg_ParseTuple(args,"O!", &PcapObjectType, &pcap_obj))
        return NULL;
    int dlt = pcap_datalink(pcap_obj->pcap);
    if(dlt < 0){
        PyErr_SetString(PyExc_RuntimeError, "coulud not find data type supported by the device");
        return NULL;
    }
    return PyLong_FromLong(dlt);
}

// pcap_list_datalinks
static PyObject *pycap_list_datalinks(PyObject *self, PyObject *args){
    PcapObject *pcap_obj;
    int *dlt_buf;
    int len;
    if(!PyArg_ParseTuple(args, "O!", &PcapObjectType, &pcap_obj))
        return NULL;
    len = pcap_list_datalinks(pcap_obj->pcap, &dlt_buf);
    if(len < 0){
        PyErr_SetString(PyExc_RuntimeError, "coulud not find data types supported by the device");
        return NULL;
    }
    PyObject *list = PyList_New(len);
    for(int i = 0; i < len; i++){
        PyList_SetItem(list, i, PyLong_FromLong(dlt_buf[i]));
    }
    return list;
}

// pcap_snapshot
static PyObject *pycap_snapshot(PyObject *self, PyObject *args){
    PcapObject *pcap_obj;
    if(!PyArg_ParseTuple(args, "O!", &PcapObjectType, &pcap_obj))
        return NULL;
    int num_of_bytes = pcap_snapshot(pcap_obj->pcap);
    return PyLong_FromLong(num_of_bytes);
}

// pcap_stats
static PyObject *pycap_stats(PyObject *self, PyObject *args){
    PcapObject *pcap_obj;
    struct pcap_stat stat;
    if(!PyArg_ParseTuple(args, "O!", &PcapObjectType, &pcap_obj))
        return NULL;
    if(pcap_stats(pcap_obj->pcap,&stat)<0){
        PyErr_SetString(PyExc_RuntimeError, "Error collecting stats");
        return NULL;
    }
    PyObject *result = PcapStatObject_New(&stat);
    return result;
}

// pcap_lib_version
static PyObject *pycap_lib_version(PyObject *self, PyObject *args){
    const char* version = pcap_lib_version();
    PyObject *vlib = PyUnicode_FromString(version);
    PyObject *thisv = PyUnicode_FromString(THIS_VERSION);
    PyUnicode_AppendAndDel(&vlib, thisv); // refer to https://github.com/python/cpython/blob/main/Objects/unicodeobject.c
    return vlib;
}
//pcap_datalink_name_to_val
static PyObject *pycap_datalink_name_to_val(PyObject *self, PyObject *args){
    const char *name;
    if(!PyArg_ParseTuple(args, "s", &name)){
        return NULL;
    }
    int dlt = pcap_datalink_name_to_val(name);
    if(dlt < 0){
        // PyErr_SetString(PyExc_RuntimeError, "coulud not find data type for the name");
        return Py_None;
    }
    return PyLong_FromLong(dlt);
}

// pcap_datalink_val_to_name
static PyObject *pycap_datalink_val_to_name(PyObject *self, PyObject *args){
    int dlt;
    if(!PyArg_ParseTuple(args, "i", &dlt))
        return NULL;
    
    const char* name = pcap_datalink_val_to_name(dlt);
    
    if(name == NULL){
        // PyErr_WarnEx(PyExc_Warning, "could not grab name for the datalink value", 1);
        return Py_None;
    }
    return PyUnicode_FromString(name);
}
// pcap_datalink_val_to_description
static PyObject *pycap_datalink_val_to_description(PyObject *self, PyObject *args){
    int dlt;
    if(!PyArg_ParseTuple(args,"i",&dlt))
        return NULL;
    const char *desc = pcap_datalink_val_to_description(dlt);
    if (desc == NULL){
        // PyErr_WarnEx(PyExc_Warning, "could not grab description for the datalink value", 1);
        return Py_None;
    }
    return PyUnicode_FromString(desc);
}

/* error handling functions*/
// pcap_geterr
static PyObject *pycap_geterr(PyObject *self, PyObject *args){
    PcapObject *pcap_obj;
    if(!PyArg_ParseTuple(args, "O!", &PcapObjectType, &pcap_obj)){
        return NULL;
    }
    char *errbuf = pcap_geterr(pcap_obj->pcap);
    return PyUnicode_FromString(errbuf);
}

// pcap_strerror
static PyObject *pycap_strerror(PyObject *self, PyObject *args){
    int error;
    if(!PyArg_ParseTuple(args, "i", &error)){
        return NULL;
    }
    const char *msg = pcap_strerror(error);
    return PyUnicode_FromString(msg);
}

// pcap_perror
static PyObject *pycap_perror(PyObject *self, PyObject *args){
    PcapObject *pcap_obj;
    char *prefix;
    if(!PyArg_ParseTuple(args, "O!s", &PcapObjectType, &pcap_obj, &prefix)){
        return NULL;
    }
    pcap_perror(pcap_obj->pcap, prefix);
    Py_RETURN_NAN;
}

/* pcap setting funcitons */

// pcap_create
static PyObject *pycap_create(PyObject *self, PyObject *args){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap;
    const char *source = NULL;
    if(!PyArg_ParseTuple(args, "|s", &source)){
        return NULL;
    }
    pcap = pcap_create(source, errbuf);
    if(pcap == NULL){
        PyErr_SetString(PyExc_RuntimeError, errbuf);
        return NULL;
    }
    return PcapObject_New(pcap);
}
// pcap_activate
static PyObject *pycap_activate(PyObject *self, PyObject *args){
    PcapObject *pcap_obj;
    int result;
    if(!PyArg_ParseTuple(args, "O!", &PcapObjectType, &pcap_obj)){
        return NULL;
    }
    result = pcap_activate(pcap_obj->pcap);
    if(result < 0){
        PyErr_SetString(PyExc_RuntimeError, pcap_geterr(pcap_obj->pcap));
        return NULL;
    }
    if(result > 0){
        PyErr_SetString(PyExc_RuntimeError, pcap_geterr(pcap_obj->pcap));
        return NULL;
    }
    if(Py_REFCNT(pcap_obj) > 1){
        Py_INCREF(pcap_obj);
        return (PyObject*) pcap_obj;
    }
    Py_RETURN_NONE;  
}

/* pcap set functions */
// pcap_set_snaplen
// pcap_set_promisc
// pcap_set_protocol_linux
// pcap_set_rfmon
// pcap_set_timeout

/* template */

// enumerate function on method table
static PyMethodDef PcapMethods[] = {
    /* {"func_name_py", func_name, METH_VARARGS or METH_VARARGS|METH_KEYWORDS ,"description"} */
    /* lookup functions */
    {"lookupdev", pycap_lookupdev, METH_VARARGS, "pcap_lookupdev wrapper"},
    {"findalldevs", pycap_findalldevs, METH_VARARGS, "pcap_findalldevs wrapper"},
    {"lookupnet", pycap_lookupnet, METH_VARARGS, "pcap_lookupnet wrapper"},
    /* packet capture functions */
    {"open_live", (PyCFunction)pycap_open_live, METH_VARARGS|METH_KEYWORDS, "pcap_open_live wrapper"},
    {"next", (PyCFunction)pycap_next, METH_VARARGS|METH_KEYWORDS, "pcap_next wrapper"},
    {"loop", (PyCFunction)pycap_loop, METH_VARARGS|METH_KEYWORDS, "pcap_loop wrapper"},
    {"dispatch", (PyCFunction)pycap_dispatch, METH_VARARGS|METH_KEYWORDS, "pcap_dispatch wrapper"},
    {"setnonblock", pycap_setnonblock, METH_VARARGS, "pcap_setnonblock wrapper"},
    {"getnonblock", pycap_getnonblock, METH_VARARGS, "pcap_getnonblock wrapper"},
    {"set_datalink", pycap_set_datalink, METH_VARARGS, "pcap_set_datalink wrapper"},
    {"compile", (PyCFunction)pycap_compile, METH_VARARGS|METH_KEYWORDS, "pcap_compile wrapper"},
    {"compile_nopcap", (PyCFunction)pycap_compile_nopcap, METH_VARARGS|METH_KEYWORDS, "pcap_compile_nopcap wrapper"},
    {"setfilter", pycap_setfilter, METH_VARARGS, "pcap_setfilter wrapper"},
    {"freecode", pycap_freecode, METH_VARARGS, "pcap_freecode wrapper"},
    {"breakloop", pycap_breakloop, METH_VARARGS, "pcap_breakloop wrapper"},
    {"fileno", pycap_fileno, METH_VARARGS, "pcap_fileno wrapper"},
    {"close", pycap_close, METH_VARARGS, "pcap_close wrapper"},
    {"open_dead", (PyCFunction)pycap_open_dead, METH_VARARGS, "pcap_open_dead wrapper"},
    /* status functions */
    {"datalink", pycap_datalink, METH_VARARGS, "pcap_datalink wrapper"},
    {"list_datalinks", pycap_list_datalinks, METH_VARARGS, "pcap_list_datalinks wrapper"},
    {"snapshot", pycap_snapshot, METH_VARARGS,"pcap_snapshot wrapper"},
    {"stats", pycap_stats, METH_VARARGS, "pcap_stats wrapper"},
    {"lib_version", pycap_lib_version, METH_VARARGS,"pcap_lib_version wrappper"},
    {"datalink_name_to_val", pycap_datalink_name_to_val, METH_VARARGS, "pcap_datalink_name_to_val wrapper"},
    {"datalink_val_to_name", pycap_datalink_val_to_name, METH_VARARGS, "pcap_datalink_val_to_name wrapper"},
    {"datalink_val_to_description", pycap_datalink_val_to_description, METH_VARARGS, "pcap_datalink_val_to_description wrapper"},
    /* error handling fuctions */
    {"geterr", pycap_geterr, METH_VARARGS, "pcap_geterr wrapper"},
    {"strerror", pycap_strerror, METH_VARARGS, "pcap_strerror wrapper"},
    {"perror", pycap_perror, METH_VARARGS, "pcap_perror wrapper"},
    /* pcap setting functions */
    {"create", pycap_create, METH_VARARGS, "pcap_create wrapper"},
    {"activate", pycap_activate, METH_VARARGS, "pcap_activate wrapper"},
    {NULL, NULL, 0, NULL}
};

// module defeinition
static PyModuleDef pcapmodule = {
    PyModuleDef_HEAD_INIT,
    .m_name = THIS_MODULE_NAME,  // module name
    .m_doc = "libpcap wrapper module", // module documentation
    .m_size = -1, // size of per-interpreter state of the module
    PcapMethods, // method table 
};

// pyinit
PyMODINIT_FUNC PyInit_pppy(void) {
    // type initialization
    if (PyType_Ready(&PcapObjectType) < 0)
        return NULL;
    if (PyType_Ready(&HeaderObjectType) < 0)
        return NULL;
    if (PyType_Ready(&PcapStatObjectType) < 0)
        return NULL;
    if (PyType_Ready(&BpfProgramObjectType) < 0)
        return NULL;

    if(PyStructSequence_InitType2(&lookupnetTupleType, &lookupnetTupleDesc) < 0)
        return NULL;
    if(PyStructSequence_InitType2(&packetTupleType, &packetTupleDesc) < 0)
        return NULL;
    if(PyStructSequence_InitType2(&argTupleType, &argTupleDesc) < 0)
        return NULL;

    // module initialization
    PyObject *module = PyModule_Create(&pcapmodule);
    if (module == NULL) return NULL;
    return module;
}



/*
 * Copyright 2023 Tooosay
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, 
 *    this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, 
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, 
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */