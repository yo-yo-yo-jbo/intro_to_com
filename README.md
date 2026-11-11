# Windows COM and CVE-2026-97793
In this blogpost I'm going to discuss something I've been meaning to write about for a long time - Windows COM, in a nutshell.  
I will explain what COM is, how it works fundamentally, how attackers might use it and even discuss [CVE-2026-97793](https://nvd.nist.gov/vuln/detail/cve-2026-97793) which is a vulnerability I accidentally found (while looking for something else).  
Of course, this topic should not be confused with old DOS COM files, which I [have previously covered](https://github.com/yo-yo-yo-jbo/binary_golf_com/).

## History and motivation
The [Component Object Model (COM)](https://en.wikipedia.org/wiki/Component_Object_Model) is one of the oldest and most fundamental technologies in Windows.  
COM was introduced in the 1990s, and is integrated *deeply* into the Windows ecosystem, powering everything from Windows Explorer and Task Scheduler to WMI, Microsoft Office, and numerous system management components.  
Despite its age and widespread use, COM is often poorly understood. Developers frequently interact with COM objects without understanding how they are instantiated, where their code executes, or how communication between different processes works.  
From a security research perspective, these details are particularly important - COM is not merely a mechanism for sharing functionality between applications, but also provides a framework for communication across process and privilege boundaries, including the ability for applications to request operations from privileged system components.  
At its core, COM is a binary interface standard that allows software components to interact without requiring knowledge of each other's implementation.  
As an example, let's think of a simple C++ application. To invoke a [virtual method](https://en.wikipedia.org/wiki/Virtual_function) on an object, the compiler needs to understand the object's interface, including the layout of its virtual method table. For example:  

```c++
#include <iostream>

class Animal
{
public:
    virtual void makeSound() const
    {
        std::cout << "Generic animal sound (moo?).\n";
    }

    virtual ~Animal() = default;
};

int main()
{
    Animal* animal = new Animal();

    animal->makeSound();

    delete animal;

    return 0;
}
```

In memory, an `Animal` instance will have a `vptr` which points to a table.  
That table contains entries for all virtual functions, and may look like the following (architecture-dependent):

| Offset | Size (bytes) | Content   |
| ------ | ------------ | --------- |
| 0      | 8            | makeSound |
| 8      | 8            | d'tor     |

When we perform `animal.makeSound();`, the compiled code would perform an indirect call in offset 0. Here's how `main` looks like after compilation (Linux, x86_64):

```assembly
    11c9:       f3 0f 1e fa             endbr64
    11cd:       55                      push   rbp
    11ce:       48 89 e5                mov    rbp,rsp
    11d1:       53                      push   rbx
    11d2:       48 83 ec 18             sub    rsp,0x18
    11d6:       bf 08 00 00 00          mov    edi,0x8
    11db:       e8 d0 fe ff ff          call   10b0 <_Znwm@plt>
    11e0:       48 89 c3                mov    rbx,rax
    11e3:       48 c7 03 00 00 00 00    mov    QWORD PTR [rbx],0x0
    11ea:       48 89 df                mov    rdi,rbx
    11ed:       e8 d6 00 00 00          call   12c8 <_ZN6AnimalC1Ev>
    11f2:       48 89 5d e8             mov    QWORD PTR [rbp-0x18],rbx
    11f6:       48 8b 45 e8             mov    rax,QWORD PTR [rbp-0x18]     ; rax = animal
    11fa:       48 8b 00                mov    rax,QWORD PTR [rax]          ; rax = animal->vptr
    11fd:       48 8b 10                mov    rdx,QWORD PTR [rax]          ; rdx = vtable[0]
    1200:       48 8b 45 e8             mov    rax,QWORD PTR [rbp-0x18]     ; rax = animal
    1204:       48 89 c7                mov    rdi,rax                      ; this = animal
    1207:       ff d2                   call   rdx                          ; animal->makeSound(this)
    1209:       48 8b 45 e8             mov    rax,QWORD PTR [rbp-0x18]
    120d:       48 85 c0                test   rax,rax
    1210:       74 0f                   je     1221 <main+0x58>
    1212:       48 8b 10                mov    rdx,QWORD PTR [rax]
    1215:       48 83 c2 10             add    rdx,0x10
    1219:       48 8b 12                mov    rdx,QWORD PTR [rdx]
    121c:       48 89 c7                mov    rdi,rax
    121f:       ff d2                   call   rdx
    1221:       b8 00 00 00 00          mov    eax,0x0
    1226:       48 8b 5d f8             mov    rbx,QWORD PTR [rbp-0x8]
    122a:       c9                      leave
    122b:       c3                      ret
```

Look at offset `0x11f6` and the code after it - I've added remarks inline:
- In `0x11f6` we obtain `animal`.
- At `0x11fa`, we dereference `animal`'s `vptr`, which is in offset 0 in the `animal` instance.
- At `0x11fd`, we acquire the first entry in the `vtable` - that will be our `makeSound` function pointer.
- At `0x1200`, we get `animal` again, and at `0x1204` we set `rdi` to point to it - that's because in C++ the first parameter to a function (unless `static`) is `this`, which is the object that the method operates on, and since this is `x86_64` - the calling convention dictates `rdi` is the first parameter.
- Finally, we call `rdx` at `0x1207` - this is exactly the indirect call we were expecting.

Now imagine our amazing `Animal` class should be exported as a dynamic library - both sides would now have to agree to an **interface** - for instance, that `makeSound` is `virtual`, that the destructor is `virtual` - and more than that - that the order, parameter list etc. all match perfectly - otherwise we'd end up with weird crashes or worse.

That is the main motivation behind COM, and is not just a C++ problem - it exists in C too (and in fact, in any system that has any sort of dynamic library code execution).

## COM fundementals
Instead of exposing implementation-specific C++ classes, COM components expose interfaces: collections of methods with well-defined signatures and calling conventions.

### IUnknown
Every COM interface ultimately derives from a base class called `IUnknown`, which defines three methods:  

```c++
struct IUnknown {
    virtual HRESULT QueryInterface(
        REFIID riid,
        void** ppvObject) = 0;

    virtual ULONG AddRef() = 0;
    virtual ULONG Release() = 0;
};
```

These methods serve three fundamental purposes:
- `QueryInterface` allows a caller to discover and obtain other interfaces supported by an object.
- `AddRef` increments the reference count.
- `Release` decrements the reference count, allowing an object to be destroyed when no longer referenced.

Note the relatively straightforward implementation: we have a pointer to an interface (`IUnknown`) whose first pointer points to a table of function pointers (`QueryInterface`).
COM therefore does not require a particular source language, only agreement on the binary layout of an interface.  
Security remark: we will mostly be focusing here on `QueryInterface`, but there are interesting use-after-free vulnerabilities in case someone forgets to call `AddRef` or has assumptions about the reference count of the object (e.g. if someone can call `Release` from some functionality in another exported function). I will not be discussing that today, but ref-counting miscalculations leading to use-after-free are very common scenarios.

### GUIDs
COM relies heavily on [globally unique identifiers (GUIDs)](https://en.wikipedia.org/wiki/Universally_unique_identifier).  
Two identifiers are particularly important:
- **CLSID (Class Identifier)**: Identifies a COM class, effectively describing which component should be instantiated.
- **IID (Interface Identifier)**: Identifies a particular interface implemented by a COM object.

A single COM class can implement multiple interfaces, and an interface can be implemented by multiple COM classes.  
A client generally requests an object by its `CLSID` but interacts with it through one or more `IIDs`.  
For example:

```c++
HRESULT hr = CoCreateInstance(
    CLSID_Example,
    nullptr,
    CLSCTX_INPROC_SERVER,
    IID_IExample,
    reinterpret_cast<void**>(&obj)
);
```

Here, `CLSID_Example` identifies the class to instantiate, while `IID_IExample` identifies the interface we want to receive.  
If the `HRESULT` indicates a success, `obj` is expected to be populated, and because we know it inherits from `IUnknown` - we'd also be able to call those three methods on it.  
I purposely skipped explaining the `CLSCTX_INPROC_SERVER` argument, but it deserves special attention - it determines where the implementation is allowed to execute.  
COM supports several execution contexts:

| Execution context    | Description                                               |
| -------------------- | --------------------------------------------------------- |
| CLSCTX_INPROC_SERVER | DLL hosted inside the calling process                     |
| CLSCTX_LOCAL_SERVER  | A server executing in another process on the same machine |
| CLSCTX_REMOTE_SERVER | A server executing on another machine                     |
| CLSCTX_ALL           | Allows COM to select among supported contexts             |

### In-process COM servers
An in-process COM server is typically implemented as a DLL.  
When an application activates an in-process COM object, Windows loads the DLL into the application's address space. Its implementation therefore executes as part of the calling process.  
Because the implementation shares the same address space, calls can often be dispatched directly through the COM interface's `vtable`.
This makes in-process COM relatively efficient, but it also means the DLL executes with the privileges of the hosting process - it doesn't have an independent security identity or access token.
Therefore, a malicious or compromised in-process COM server is effectively malicious code executing within its client's process. This becomes particularly interesting when discussing [COM hijacking](https://attack.mitre.org/techniques/T1546/015/).

### Out-of-process COM servers
An out-of-process COM server, also sometimes referred to as a "local server", executes in a separate process.  
Instead of loading a DLL into the client, COM activates or connects to a server process and provides the client with an interface through which it can communicate with the server.  
From the client's perspective, invoking a method might still look like an ordinary C++ method call, but internally, the call can involve argument marshaling, interprocess communication, dispatching the request in the server process, and marshaling the results back to the client.  
On Windows, local COM communication is built on [RPC](https://en.wikipedia.org/wiki/Remote_procedure_call) infrastructure, commonly using local RPC transport mechanisms backed by [ALPC](https://en.wikipedia.org/wiki/Local_Inter-Process_Communication).  
Crucially, **the server is not required to execute with the same privileges as its caller** - its security context is determined by how the server was launched or configured, including its process identity and activation settings.  
For example, a COM server running as SYSTEM, might be accessible to a client running as a standard user, provided the relevant permissions allow it. Of course, this is very interesting from a security research perspective - IPC were always a weak link, and if the server does not validate the client well and performs sensitive operations on its behalf, the results could be quite bad (e.g. a local privilege escalation vulnerability).

### DLL surrogates
The distinction between DLL-based and executable-based COM servers is not absolute - COM can be hosted in any executable, but traditionally you'd see many more cases of COM DLLs, due to how convenient it is to load a DLL to an appropriate process and benefiting from the natural security of process separation.  
However, what happens if we have a COM server implemented in a DLL, and it should be loaded as an out-of-process COM server?  
For that purpose, Windows supports **DLL surrogates**, which provide a process in which a COM DLL can execute without being loaded into the original client.  
The most recognizable example is `dllhost.exe` - in modern Windows system would have several of these running at any given moment.
