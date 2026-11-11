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
Instead of exposing implementation-specific C++ classes, COM components expose interfaces: collections of methods with well-defined signatures and calling conventions.  
Every COM interface ultimately derives from IUnknown, which defines three methods:  

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

Note that there are interesting use-after-free vulnerabilities in case someone forgets to call `AddRef`. These cases also include cases where someone can call `Release` from some functionality in another exported function - I will not be discussing that today, but ref-counting miscalculations leading to use-after-free are very common scenarios.
