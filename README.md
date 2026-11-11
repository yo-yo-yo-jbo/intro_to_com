# Windows COM and CVE-2026-97793
In this blogpost I'm going to discuss something I've been meaning to write about for a long time - Windows COM, in a nutshell.  
I will explain what COM is, how it works fundamentally, how attackers might use it and even discuss [CVE-2026-97793](https://nvd.nist.gov/vuln/detail/cve-2026-97793) which is a vulnerability I accidentally found (while looking for something else).  
Of course, this topic should not be confused with old DOS COM files, which I [have previously covered](https://github.com/yo-yo-yo-jbo/binary_golf_com/).  
Note that I will also not talk about COM from a pure developer perspective - there are numerous heavy books on the subject, and I don't claim to know everything about COM myself.

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

## COM activation
Now that we understand the execution models, let's look at how Windows identifies and activates a COM class.  
Most traditional COM classes are registered in the Windows Registry. For example:

```
HKEY_CLASSES_ROOT
  CLSID
    {1423dadc-7fcf-41de-8219-5b28eb52860d}
      InprocServer32
        (Default) = C:\Example\Server.dll
        ThreadingModel = Both
```

This entry tells COM that `C:\Example\Server.dll` implements the class with the GUID CLSID of `{1423dadc-7fcf-41de-8219-5b28eb52860d}` (this is just a random GUID I created).  
An out-of-process server might instead be registered as:  

```
HKEY_CLASSES_ROOT
  CLSID
    {f1ea609d-cb6d-4fa8-a316-10a2f93db2f5}
      LocalServer32
        (Default) = C:\Example\Server.exe
```

Note, as I mentioned, that an out-of-process COM server can live happily in its own executable too.

### In-process activation
When a client calls [CoCreateInstance](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance) requesting an in-process server, COM generally performs the following operations:
1. Resolves the `CLSID` to determine the server implementing the class.
2. Locates the corresponding DLL.
3. Loads the DLL into the calling process if necessary.
4. Obtains its [DllGetClassObject](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-dllgetclassobject) export (this is a traditional DLL export, not a COM interface).
5. Retrieves an [IClassFactory](https://learn.microsoft.com/en-us/windows/win32/api/unknwnbase/nn-unknwnbase-iclassfactory) (there's a well-known `IID_IClassFactory` for it).
6. Invokes [IClassFactory::CreateInstance](https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iclassfactory-createinstance).
7. Returns the requested interface to the caller.

Note the class factory - COM separates locating a class from constructing an instance of that class.

### Out-of-process activation
With an out-of-process server, things become more interesting.  
Rather than loading the implementation directly, COM may need to launch an executable or communicate with an existing process.  
The activation infrastructure, including the RPCSS/DCOM service infrastructure, helps resolve the class and arrange a connection to the server.  
Registration can happen through common APIs such as [CoRegisterClassObject](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coregisterclassobject), and once the server is ready, COM can marshal the requested interface back to the client. At that point, the client would generally receive a proxy representing the remote object, rather than a direct pointer to its implementation.

### AppIDs
A `CLSID` identifies a COM class, while an `AppID` groups configuration associated with a COM server application.  
AppID configuration may specify:  
- Server identity and activation behavior.
- Launch and activation permissions.
- Access permissions.
- DLL surrogate configuration.
- Authentication settings.

Understanding a COM server therefore frequently requires examining both its `CLSID` registration and the associated `AppID`.

## COM and the registry
When we examine COM registration, we typically look under `HKEY_CLASSES_ROOT\CLSID` in the [Windows Registry](https://en.wikipedia.org/wiki/Windows_Registry).  
However, `HKEY_CLASSES_ROOT` (`HKCR` for short) is not a standalone registry hive, but it's a **merge result** of two registry locations:  
- `HKEY_CURRENT_USER\Software\Classes`
- `HKEY_LOCAL_MACHINE\Software\Classes`

The machine-wide registration exists under `HKLM`, while the user-specific registration exists under `HKCU`. Note that this also means every user has its own (perhaps unique) `HKCR`, due to being affected by `HKCU` (which is really a link to some user SID under `HKU`).  
Also note that the order matters - per-user registrations generally **take precedence** over machine-wide registrations when the same entry exists in both locations.  
This is intentional, as `HKLM` registrations form a "baseline" in which each user can deviate from, but it also creates security issues, especially since generally high privileges are not required to write arbitrary keys and data under `HKCU` (unlike `HKLM` writes).  
Let's take an example - suppose we have a class registered as:  
```
HKLM\Software\Classes\CLSID\
  {11111111-1111-1111-1111-111111111111}
    InprocServer32
      (Default) = C:\Program Files\Example\server.dll
```

Now suppose the following registry write (notice it's under `HKCU`!):  
```
HKCU\Software\Classes\CLSID\
  {11111111-1111-1111-1111-111111111111}
    InprocServer32
      (Default) = C:\Users\mal\malicious.dll
```

When activating `CLSID` of `{11111111-1111-1111-1111-111111111111}` under the current user, `malicious.dll` will be loaded!  
This can be used for various malicious purposes:
- Persistence: if that COM class is being used when the user logs in (e.g. by `explorer.exe`), then `malicious.dll` persists and runs after reboots.
- DLL injection: any program that activates that COM class and runs under the user - will have `malicious.dll` injected into it.

Note, however, that processes elevated through UAC do not normally use the per-user COM class registrations for COM activation - Microsoft explicitly documents that such processes use the machine-wide registration instead. This protection prevents the simplistic attack of overriding an elevated COM server's class registration in `HKCU` and expecting elevated COM activation to load an arbitrary user-controlled DLL.

## Marshaling, Proxies and Apartments
So far, we've treated out-of-process communication as a straightforward RPC mechanism.  
COM introduces an additional layer of complexity through its `apartment` model.  
Every thread using COM must initialize it, typically using [CoInitializeEx](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coinitializeex), e.g.:  
```c
CoInitializeEx(MULL, COINIT_MULTITHREADED);
```

This initializes the thread for the **multithreaded apartment (MTA)**.  
Alternatively, `COINIT_APARTMENTTHREADED` initializes a **single-threaded apartment (STA)**.  
- An STA generally relies on a message loop to dispatch incoming calls.
- An MTA permits objects to receive calls from different threads, subject to their synchronization requirements.

That's quite interesting, since even objects **within the same process** might require marshaling when communicating across apartment boundaries (e.g. SLA to MTA).  
When a COM interface crosses an apartment or process boundary, the caller generally receives a proxy, while COM uses the corresponding marshaling machinery to dispatch calls to the object. Depending on the interface, this can involve type-library-based marshaling, generated proxy/stub code, or custom marshaling implementations.  
For vulnerability researchers, these mechanisms introduce several areas worth examining:
- Serialization and deserialization of attacker-controlled arguments.
- Incorrect assumptions about interface or object lifetimes.
- Reentrancy during cross-apartment calls.
- Incorrect validation of data crossing process boundaries.
- Vulnerabilities in custom marshaling implementations.

I won't elaborate on any of those for now - maybe in a future blogpost.

## COM security
COM security is more complicated than simply checking whether a caller is an administrator.  
At a high level, two different questions must be answered:
- Can the caller activate the COM server?
- Can the caller invoke methods on the resulting object?

Interestingly, these questions correspond to different security controls.

### Launch and activation permissions
COM can use launch and activation permissions to control which security principals are allowed to start or activate a particular server.  
These permissions are typically associated with `AppID` configuration.  
A server might allow ordinary users to activate its classes even though the server runs under a privileged account.

### Access permissions
Separately, COM access permissions control whether callers can make calls into the server.  
An application can establish process-wide security settings using [CoInitializeSecurity](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coinitializesecurity), and, in fact, clients can also configure security on individual COM proxies using [CoSetProxyBlanket](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cosetproxyblanket).  
These settings influence authentication, impersonation, and access checks for applicable COM calls.

### Impersonation
COM allows servers to impersonate their clients.  
For example, let's imagine a privileged server that receives a request from an unprivileged process.  
Rather than performing the operation under its own privileged identity, the server may impersonate the caller while accessing a resource:

```c++
CoImpersonateClient();

// Perform an operation under the impersonated client's security context

CoRevertToSelf();
```

The ability to impersonate depends on the negotiated security settings and impersonation level.  
However, impersonation is not automatic for every COM method, nor does it replace explicit authorization.  
A privileged server performing sensitive operations under its own identity must ensure callers are authorized to request those operations.  
This becomes especially important when examining elevated COM objects.

## Elevated COM objects
Normally, when an application running with a medium-integrity token needs administrator privileges, Windows uses [User Account Control (UAC)](https://en.wikipedia.org/wiki/User_Account_Control) to arrange elevation.  
COM provides a mechanism for elevating an individual server without elevating the entire client application, and that mechanism is called the **COM elevation moniker**.  
Instead of starting the entire application with administrator privileges, a medium-integrity process can request that a particular COM class be activated with an elevated token.  
COM recognizes moniker syntax such as `Elevation:Administrator!new:{CLSID}`. There's also another supported form: `Elevation:Highest!new:{CLSID}`.  
A client can use CoGetObject to bind to such a moniker:  

```c++
HRESULT hrResult = E_UNEXPECTED;
BIND_OPTS3 tOpts = { 0 };

tOpts.cbStruct = sizeof(opts);
tOpts.dwClassContext = CLSCTX_LOCAL_SERVER;

hr = CoGetObject(
    L"Elevation:Administrator!new:"
    L"{11111111-1111-1111-1111-111111111111}",
    &tOpts,
    IID_IUnknown,
    reinterpret_cast<void**>(&obj)
);
```

The caller must initialize COM, and the selected class must support elevation. Also notice the use of `CLSCTX_LOCAL_SERVER` - elevating an in-process DLL inside the calling process would not provide the intended privilege separation, so, an elevated COM component must execute out of process.  
One other important note is that a COM class cannot arbitrarily request elevation simply because the client uses an elevation moniker. Instead, the class must explicitly support elevation. This is done declaratively in the registry, e.g.:

```
HKLM\Software\Classes\CLSID\{CLSID}
    LocalizedString = ...

    Elevation
        Enabled = 1
```

The `LocalizedString` value is the string that represents the text for the elevation UI, and `Elevation\Enabled` specifies that the class supports the elevation mechanism.  
Also, note the COM class must be registered under `HKLM` - this does not work under normal `HKCU` registrations, for obvious security reasons.  
Once the server is instantiated and passes all the UAC checks (and potentially, prompts) - the client can stay in a Medium integrity level, while the server can run in High integrity level, intercept requests and act on the client's behalf.  
As I previously mentioned - while this architecture allows for a great separation of functionality (only the things that need to run privileged - run privileged) - it's also an opportunity for various security issues.

