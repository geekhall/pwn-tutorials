# pwn-tutorials
CTF pwn tutorials and some challenges collection.

## checksec

### RELRO（Relocation Read-Only）
分成三种
* Disabled： .got/.got.plt 都可写
* Partial（default）： .got 无plt指向的GOT是只读的。
* Fulled： RELRO保护下，会在load time时将全部function resolve完毕。


```bash
# Partial
gcc -o test test.c # 默认部分开启
gcc -Wl,-z,relro -o test test.c # 开启部分RELRO
gcc -z lazy -o test test.c # 部分开启

# Full
gcc -Wl,-z,relro,-z,now -o test test.c # 开启Full RELRO
gcc -z now -o test test.c # 全部开启
```
### Stack

### NX（Windows中的DEP）

* NX：No-eXecute
* DEP：Data Execute Prevention
* 可写的不写可以执行，可执行的不可写
```bash
gcc -o test test.c      # 默认情况下，开启NX保护
gcc -z execstack -o test test.c  # 禁用NX保护
gcc -z noexecstack -o test test.c  # 开启NX保护
```

* 绕过方法

```
使用 ROP绕过 (如ret2data、ret2libc、ret2strcpy、ret2gets、ret2syscall)
gadget：virtualprotect、jmp esp、mona.py
```

### ASLR（Address Space Layout Randomization）

地址空间随机化
* 内存位置随机变化，每次执行程序时，stack、heap、library位置都不一样
* 查看：`cat /proc/sys/kernel/randomize_va_space`

![](https://gitee.com/geekhall/pic/raw/main/img/20220702215205.png)

可使用ldd来查看执行时载入的library及其位置，每次address都会变化。


### PIE(Position Independent Execution)

可执行程序的基址随机，为ASLR的编译选项，是ASLR的一部分

* gcc在默认情况下不会开启，编译时加上 -fPIC -pie就可以开启
* 在没开启的情况下程序的data段及code段会是固定的
* 开启之后data及code段也会跟着ALSR，因此return2shellcode没有固定位置可以跳，变得困难很多。
* 查看：使用`objdump`查看时，code address会变成只剩下offset，执行时加上code base的地址才是真正内存中的位置。

```bash
gcc -fpie -pie -o test test.c    # 开启PIE
gcc -fPIE -pie -o test test.c    # 开启PIE
gcc -fpic -o test test.c         # 开启PIC
gcc -fPIC -o test test.c         # 开启PIC
gcc -no-pie -o test test.c       # 关闭PIE
```

### RWX

### Return to Library

一般情况下程序中很难会有system等，可以直接获得shell的function
在DEP/NX的保护下我们也无法直接填入shellcode去执行我们的代码。
而在Dynamilic Linking的情况下，大部分程序都会载入libc，libc中有非常多好用的function可以利用
比如system、execve等，但一般情况下都会因为ALSR的关系，导致每次Libc载入位置不固定
所以我们通常都需要information leak的漏洞来获取libc的base address，进而算出system等函数的位置，
再讲程序导过去执行。

通常可以获得libc位置的地方：
* GOT
* stack上的残留值：function return后不会将stack中的内容清除
* heap上的残留值： free完之后再malloc，也不会将heap中的内容清空

可以使用`objdump -T libc.so.6| grep function` 来找到想要的function在libc中的offset
比如如果能够获得printf的位置，可以找到printf在libc中的offset以及想要利用的function的offset
那么：system= printf - printf_offset + system_offset

* 如何查找libc的base address：

gdb运行后使用`vmmap`查看

查看对应函数的offset：使用`ldd`查看libc位置后，使用

```
objdump -T /lib/i386-linux-gnu/libc.so.6 |grep system

0003adb0  w   DF .text	00000037  GLIBC_2.0   system
00049680 g    DF .text	0000002a  GLIBC_2.0   printf
```


获得system位置后，可以覆盖return address跳到system上，要注意的是参数也要一起放上。
此时也要注意多空一格，因为我们是利用ret而不是call，一般call之后会push一个return address
到stack中，function取参数会空一格再取

![](https://gitee.com/geekhall/pic/raw/main/img/20220703104313.png)


使用patchelf替换libc.so
```
cd /lib64/
sudo ln -s /home/zzq/shanshi/game/2021/dianfengjike/ghost/ld.so.2 ./15_ld_.so.2
patchelf --set-interpreter /lib64/15_ld_.so.2 ./pwn
patchelf --replace-needed libc.so.6 ./libc.so.6 ./pwn
```
### StackGuard/Canary

gcc提供栈溢出保护机制，即默认编译时 -fstack-protector选项为开。
在该保护机制下，如果程序中有栈溢出，会有以下报错信息，程序异常终止：

* 在程序执行时随机生成一个数值，在function call时塞入satck中，
* 在function return时会检查是否该值有被改动，如果发现变动则程序结束。
* 非常有效地阻挡了stack overflow的攻击
* 目前默认情况下是开放的
* canary的值在执行期间都会先放在一个叫做tls的区段中的tcbhead_t结构中，在x86/x64架构下一直有一个
  寄存器指向tls段的tcbhead_t结构：
  - x86： gs
  - x64： fs
  因此程序在取canary值的时候都会直接以fs/gs做存取

* 检测到canary被覆盖的事后会提示如下内容：

```
*** stack smashing detected ***: /home/giantbranch/ctf/HITCON-Training/LAB/extlab-01-bof/bof terminated
```

若要关闭栈溢出保护，在gcc编译选项中增加-fno-stack-protector即可。

### Lazy binding

* Dynamic linking 的程序在执行过程中，有些library中的函数可能到结束都不会执行，
所以ELF采用Lazy binding的机制，在第一次call library函数时，才会去寻找函数真正的位置进行binding。
* library的位置在载入之后才决定，因此无法在compile后就知道library中的function在哪，该跳去哪里。
* GOT（Global Offset Table）为一个函数指针数组，存储其他library中function的位置，但因为Lazy binding机制，并不会一开始就把正确的位置填上，而是填上一段plt位置的code。
* 当执行到library的function时，才会真正去寻找function，最后再把GOT中的位置填上真正function的位置。

![](https://gitee.com/geekhall/pic/raw/main/img/20220703090913.png)

* GOT 分成两部分
  - .got 保存全局变量引用位置
  - .got.plt 保存函数引用位置，前三项有特别用途
    - address of .dynamic
    - link_map: 一个将有引用道德library所串成的linked list
    - dl_runtime_resolve: 用于找出函数位置的函数
    - 后面则是程序中.so函数引用位置。

* How to find the GOT

```bash
objdump -R elf
# or
readelf -r elf
```
* GOT Hijacking: 如果程序有存在任意更改位置的漏洞，便可以改写GOT，造成程序流程的改变，也就控制了eip
  前提：GOT位置必须是可以写入的。




![](https://gitee.com/geekhall/pic/raw/main/img/20220703091821.png)

## 生成shellcode

use pwntools:

```
shellcode = asm(shellcraft.sh())
```

or

```
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80
```

## Test shellcode

```bash
gcc -m32 -z execstack test.c -o test
```


## 本地测试环境

可以使用`ncat`命令在本地启动一个监听执行特定binary程序：
```bash
ncat -ve ./bof -kl 8888
```
kl表示keep listen

## 查看函数地址

gdb中使用 `info function`查看


```bash
objdump -t buffer-overflow|grep l33t
```

## 查看全局变量地址

```
nm binaryfile | grep name
```
或者，gdb中执行：
```
x/x &name
```

## 调试
gdb attach

gdb$r < exp



CTF-pwn-tips
# Catalog
* [Overflow](#overflow)
* [Find string in gdb](#find-string-in-gdb)
* [Binary Service](#binary-service)
* [Find specific function offset in libc](#find-specific-function-offset-in-libc)
* [Find '/bin/sh' or 'sh' in library](#find-binsh-or-sh-in-library)
* [Leak stack address](#leak-stack-address)
* [Fork problem in gdb](#fork-problem-in-gdb)
* [Secret of a mysterious section - .tls](#secret-of-a-mysterious-section---tls)
* [Predictable RNG(Random Number Generator)](#predictable-rngrandom-number-generator)
* [Make stack executable](#make-stack-executable)
* [Use one-gadget-RCE instead of system](#use-one-gadget-rce-instead-of-system)
* [Hijack hook function](#hijack-hook-function)
* [Use printf to trigger malloc and free](#use-printf-to-trigger-malloc-and-free)
* [Use execveat to open a shell](#use-execveat-to-open-a-shell)


## Overflow

Assume that: `char buf[40]` and `signed int num`

### scanf

* `scanf("%s", buf)`
    * `%s` doesn't have boundary check.
    * **pwnable**

* `scanf("%39s", buf)`
    * `%39s` only takes 39 bytes from the input and puts NULL byte at the end of input.
    * **useless**

* `scanf("%40s", buf)`
    * At first sight, it seems reasonable.(seems)
    * It takes **40 bytes** from input, but it also **puts NULL byte at the end of input.**
    * Therefore, it has **one-byte-overflow**.
    * **pwnable**

* `scanf("%d", &num)`
    * Used with `alloca(num)`
        * Since `alloca` allocates memory from the stack frame of the caller, there is an instruction `sub esp, eax` to achieve that.
        * If we make num negative, it will have overlapped stack frame.
        * E.g. [Seccon CTF quals 2016 cheer_msg](https://github.com/ctfs/write-ups-2016/tree/master/seccon-ctf-quals-2016/exploit/cheer-msg-100)
    * Use num to access some data structures
        * In most of the time, programs only check the higher bound and forget to make num unsigned.
        * Making num negative may let us overwrite some important data to control the world!

### gets

* `gets(buf)`
    * No boundary check.
    * **pwnable**

* `fgets(buf, 40, stdin)`
    * It takes only **39 bytes** from the input and puts NULL byte at the end of input.
    * **useless**

### read

* `read(stdin, buf, 40)`
    * It takes **40 bytes** from the input, and it doesn't put NULL byte at the end of input.
    * It seems safe, but it may have **information leak**.
    * **leakable**

E.g.

**memory layout**
```
0x7fffffffdd00: 0x4141414141414141      0x4141414141414141
0x7fffffffdd10: 0x4141414141414141      0x4141414141414141
0x7fffffffdd20: 0x4141414141414141      0x00007fffffffe1cd
```

* If there is a `printf` or `puts` used to output the buf, it will keep outputting until reaching NULL byte.
* In this case, we can get `'A'*40 + '\xcd\xe1\xff\xff\xff\x7f'`.

* `fread(buf, 1, 40, stdin)`
    * Almost the same as `read`.
    * **leakable**

### strcpy

Assume that there is another buffer: `char buf2[60]`

* `strcpy(buf, buf2)`
    * No boundary check.
    * It copies the content of buf2(until reaching NULL byte) which may be longer than `length(buf)` to buf.
    * Therefore, it may happen overflow.
    * **pwnable**

* `strncpy(buf, buf2, 40)` && `memcpy(buf, buf2, 40)`
    * It copies 40 bytes from buf2 to buf, but it won't put NULL byte at the end.
    * Since there is no NULL byte to terminate, it may have **information leak**.
    * **leakable**

### strcat

Assume that there is another buffer: `char buf2[60]`

* `strcat(buf, buf2)`
    * Of course, it may cause **overflow** if `length(buf)` isn't large enough.
    * It puts NULL byte at the end, it may cause **one-byte-overflow**.
    * In some cases, we can use this NULL byte to change stack address or heap address.
    * **pwnable**

* `strncat(buf, buf2, n)`
    * Almost the same as `strcat`, but with size limitation.
    * **pwnable**
    * E.g. [Seccon CTF quals 2016 jmper](https://github.com/ctfs/write-ups-2016/tree/master/seccon-ctf-quals-2016/exploit/jmper-300)


## Find string in gdb

In the problem of [SSP](http://j00ru.vexillium.org/blog/24_03_15/dragons_ctf.pdf), we need to find out the offset between `argv[0]` and the input buffer.

### gdb

* Use `p/x ((char **)environ)` in gdb, and the address of argv[0] will be the `output - 0x10`

E.g.

```
(gdb) p/x (char **)environ
$9 = 0x7fffffffde38
(gdb) x/gx 0x7fffffffde38-0x10
0x7fffffffde28: 0x00007fffffffe1cd
(gdb) x/s 0x00007fffffffe1cd
0x7fffffffe1cd: "/home/naetw/CTF/seccon2016/check/checker"
```

### [gdb peda](https://github.com/longld/peda)

* Use `searchmem "/home/naetw/CTF/seccon2016/check/checker"`
* Then use `searchmem $result_address`

```
gdb-peda$ searchmem "/home/naetw/CTF/seccon2016/check/checker"
Searching for '/home/naetw/CTF/seccon2016/check/checker' in: None ranges
Found 3 results, display max 3 items:
[stack] : 0x7fffffffe1cd ("/home/naetw/CTF/seccon2016/check/checker")
[stack] : 0x7fffffffed7c ("/home/naetw/CTF/seccon2016/check/checker")
[stack] : 0x7fffffffefcf ("/home/naetw/CTF/seccon2016/check/checker")
gdb-peda$ searchmem 0x7fffffffe1cd
Searching for '0x7fffffffe1cd' in: None ranges
Found 2 results, display max 2 items:
   libc : 0x7ffff7dd33b8 --> 0x7fffffffe1cd ("/home/naetw/CTF/seccon2016/check/checker")
[stack] : 0x7fffffffde28 --> 0x7fffffffe1cd ("/home/naetw/CTF/seccon2016/check/checker")
```

## Binary Service

Normal:

* `ncat -vc ./binary -kl 127.0.0.1 $port`

With specific library in two ways:

* `ncat -vc 'LD_PRELOAD=/path/to/libc.so ./binary' -kl 127.0.0.1 $port`
* `ncat -vc 'LD_LIBRARY_PATH=/path/of/libc.so ./binary' -kl 127.0.0.1 $port`

After this, you can connect to binary service by command `nc localhost $port`.

## Find specific function offset in libc

If we leaked libc address of certain function successfully, we could use get libc base address by subtracting the offset of that function.

### Manually

* `readelf -s $libc | grep ${function}@`

E.g.

```
$ readelf -s libc-2.19.so | grep system@
    620: 00040310    56 FUNC    GLOBAL DEFAULT   12 __libc_system@@GLIBC_PRIVATE
   1443: 00040310    56 FUNC    WEAK   DEFAULT   12 system@@GLIBC_2.0
```

### Automatically

* Use [pwntools](https://github.com/Gallopsled/pwntools), then you can use it in your exploit script.

E.g.

```python
from pwn import *

libc = ELF('libc.so')
system_off = libc.symbols['system']
```

## Find '/bin/sh' or 'sh' in library

Need libc base address first

### Manually

* `objdump -s libc.so | less` then search 'sh'
* `strings -tx libc.so | grep /bin/sh`

### Automatically

* Use [pwntools](https://github.com/Gallopsled/pwntools)

E.g.

```python
from pwn import *

libc = ELF('libc.so')
...
sh = base + next(libc.search('sh\x00'))
binsh = base + next(libc.search('/bin/sh\x00'))
```

## Leak stack address

**constraints**:

* Have already leaked libc base address
* Can leak the content of arbitrary address

There is a symbol `environ` in libc, whose value is the same as the third argument of `main` function, `char **envp`.
The value of `char **envp` is on the stack, thus we can leak stack address with this symbol.

```
(gdb) list 1
1       #include <stdlib.h>
2       #include <stdio.h>
3
4       extern char **environ;
5
6       int main(int argc, char **argv, char **envp)
7       {
8           return 0;
9       }
(gdb) x/gx 0x7ffff7a0e000 + 0x3c5f38
0x7ffff7dd3f38 <environ>:       0x00007fffffffe230
(gdb) p/x (char **)envp
$12 = 0x7fffffffe230
```

* `0x7ffff7a0e000` is current libc base address
* `0x3c5f38` is offset of `environ` in libc

This [manual](https://www.gnu.org/software/libc/manual/html_node/Program-Arguments.html) explains details about `environ`.

## Fork problem in gdb

When you use **gdb** to debug a binary with `fork()` function, you can use the following command to determine which process to follow (The default setting of original gdb is parent, while that of gdb-peda is child.):

* `set follow-fork-mode parent`
* `set follow-fork-mode child`

Alternatively, using `set detach-on-fork off`, we can then control both sides of each fork. Using `inferior X` where `X` is any of the numbers that show up for `info inferiors` will switch to that side of the fork. This is useful if both sides of the fork are necessary to attack a challenge, and the simple `follow` ones above aren't sufficient.

## Secret of a mysterious section - .tls

**constraints**:

* Need `malloc` function and you can malloc with arbitrary size
* Arbitrary address leaking

We make `malloc` use `mmap` to allocate memory(size 0x21000 is enough). In general, these pages will be placed at the address just before `.tls` section.

There is some useful information on **`.tls`**, such as the address of `main_arena`, `canary` (value of stack guard), and a strange `stack address` which points to somewhere on the stack but with a fixed offset.

**Before calling mmap:**

```
7fecbfe4d000-7fecbfe51000 r--p 001bd000 fd:00 131210         /lib/x86_64-linux-gnu/libc-2.24.so
7fecbfe51000-7fecbfe53000 rw-p 001c1000 fd:00 131210         /lib/x86_64-linux-gnu/libc-2.24.so
7fecbfe53000-7fecbfe57000 rw-p 00000000 00:00 0
7fecbfe57000-7fecbfe7c000 r-xp 00000000 fd:00 131206         /lib/x86_64-linux-gnu/ld-2.24.so
7fecc0068000-7fecc006a000 rw-p 00000000 00:00 0              <- .tls section
7fecc0078000-7fecc007b000 rw-p 00000000 00:00 0
7fecc007b000-7fecc007c000 r--p 00024000 fd:00 131206         /lib/x86_64-linux-gnu/ld-2.24.so
7fecc007c000-7fecc007d000 rw-p 00025000 fd:00 131206         /lib/x86_64-linux-gnu/ld-2.24.so
```

**After call mmap:**

```
7fecbfe4d000-7fecbfe51000 r--p 001bd000 fd:00 131210         /lib/x86_64-linux-gnu/libc-2.24.so
7fecbfe51000-7fecbfe53000 rw-p 001c1000 fd:00 131210         /lib/x86_64-linux-gnu/libc-2.24.so
7fecbfe53000-7fecbfe57000 rw-p 00000000 00:00 0
7fecbfe57000-7fecbfe7c000 r-xp 00000000 fd:00 131206         /lib/x86_64-linux-gnu/ld-2.24.so
7fecc0045000-7fecc006a000 rw-p 00000000 00:00 0              <- memory of mmap + .tls section
7fecc0078000-7fecc007b000 rw-p 00000000 00:00 0
7fecc007b000-7fecc007c000 r--p 00024000 fd:00 131206         /lib/x86_64-linux-gnu/ld-2.24.so
7fecc007c000-7fecc007d000 rw-p 00025000 fd:00 131206         /lib/x86_64-linux-gnu/ld-2.24.so
```

## Predictable RNG(Random Number Generator)

When the binary uses the RNG to make the address of important information or sth, we can guess the same value if it's predictable.

Assuming that it's predictable, we can use [ctypes](https://docs.python.org/2/library/ctypes.html) which is a build-in module in Python.

**ctypes** allows calling a function in DLL(Dynamic-Link Library) or Shared Library.

Therefore, if binary has an init_proc like this:

```c
srand(time(NULL));
while(addr <= 0x10000){
    addr = rand() & 0xfffff000;
}
secret = mmap(addr,0x1000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS ,-1,0);
if(secret == -1){
    puts("mmap error");
    exit(0);
}
```

Then we can use **ctypes** to get the same value of addr.

```python
import ctypes
LIBC = ctypes.cdll.LoadLibrary('/path/to/dll')
LIBC.srand(LIBC.time(0))
addr = LIBC.rand() & 0xfffff000
```

## Make stack executable

* [link1](http://radare.today/posts/defeating-baby_rop-with-radare2/)
* [link2](https://sploitfun.wordpress.com/author/sploitfun/)
* Haven't read yet orz

## Use one-gadget-RCE instead of system

**constraints**:

* Have libc base address
* Write to arbitrary address

Almost every pwnable challenge needs to call `system('/bin/sh')` in the end of the exploit, but if we want to call that, we have to manipulate the parameters and, of course, hijack some functions to `system`. What if we **can't** manipulate the parameter?

Use [one-gadget-RCE](http://j00ru.vexillium.org/blog/24_03_15/dragons_ctf.pdf)!

With **one-gadget-RCE**, we can just hijack `.got.plt` or something we can use to control eip to make program jump to **one-gadget**, but there are some constraints that need satisfying before using it.

There are lots of **one-gadgets** in libc. Each one has different constraints but those are similar. Each constraint is about the state of registers.

E.g.

* ebx is the address of `rw-p` area of libc
* [esp+0x34] == NULL

How can we get these constraints? Here is an useful tool [one_gadget](https://github.com/david942j/one_gadget) !!!!

So if we can satisfy those constraints, we can get the shell more easily.

## Hijack hook function

**constraints**:

* Have libc base address
* Write to arbitrary address
* The program uses `malloc`, `free` or `realloc`.

By manual:

> The GNU C Library lets you modify the behavior of `malloc`, `realloc`, and `free` by specifying appropriate hook functions. You can use these hooks to help you debug programs that use dynamic memory allocation, for example.

There are hook variables declared in malloc.h and their default values are `0x0`.

* `__malloc_hook`
* `__free_hook`
* ...

Since they are used to help us debug programs, they are writable during the execution.

```
0xf77228e0 <__free_hook>:       0x00000000
0xf7722000 0xf7727000 rw-p      mapped
```

Let's look into the [src](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#2917) of malloc.c. I will use `__libc_free` to demo.

```c
void (*hook) (void *, const void *) = atomic_forced_read (__free_hook);
if (__builtin_expect (hook != NULL, 0))
{
    (*hook)(mem, RETURN_ADDRESS (0));
    return;
}
```

It checks the value of `__free_hook`. If it's not NULL, it will call the hook function first. Here, we would like to use **one-gadget-RCE**. Since hook function is called in the libc, the constraints of **one-gadget** are usually satisfied.

## Use printf to trigger malloc and free

Look into the source of printf, there are several places which may trigger malloc. Take [vfprintf.c line 1470](https://code.woboq.org/userspace/glibc/stdio-common/vfprintf.c.html#1470) for example:

```c
#define EXTSIZ 32
enum { WORK_BUFFER_SIZE = 1000 };

if (width >= WORK_BUFFER_SIZE - EXTSIZ)
{
    /* We have to use a special buffer.  */
    size_t needed = ((size_t) width + EXTSIZ) * sizeof (CHAR_T);
    if (__libc_use_alloca (needed))
        workend = (CHAR_T *) alloca (needed) + width + EXTSIZ;
    else
    {
        workstart = (CHAR_T *) malloc (needed);
        if (workstart == NULL)
        {
            done = -1;
            goto all_done;
        }
        workend = workstart + width + EXTSIZ;
    }
}
```

We can find that `malloc` will be triggered if the width field is large enough.(Of course, `free` will also be triggered at the end of printf if `malloc` has been triggered.) However, WORK_BUFFER_SIZE is not large enough, since we need to go to **else** block. Let's take a look at `__libc_use_alloca` and see what exactly the minimum size of width we should give.

```c

/* Minimum size for a thread.  We are free to choose a reasonable value.  */
#define PTHREAD_STACK_MIN        16384

#define __MAX_ALLOCA_CUTOFF        65536

int __libc_use_alloca (size_t size)
{
    return (__builtin_expect (size <= PTHREAD_STACK_MIN / 4, 1)
        || __builtin_expect (__libc_alloca_cutoff (size), 1));
}

int __libc_alloca_cutoff (size_t size)
{
	return size <= (MIN (__MAX_ALLOCA_CUTOFF,
					THREAD_GETMEM (THREAD_SELF, stackblock_size) / 4
					/* The main thread, before the thread library is
						initialized, has zero in the stackblock_size
						element.  Since it is the main thread we can
						assume the maximum available stack space.  */
					?: __MAX_ALLOCA_CUTOFF * 4));
}
```

We have to make sure that:

1. `size > PTHREAD_STACK_MIN / 4`
2. `size > MIN(__MAX_ALLOCA_CUTOFF, THREAD_GETMEM(THREAD_SELF, stackblock_size) / 4 ?: __MAX_ALLOCA_CUTOFF * 4)`
    * I did not fully understand what exactly the function - THREAD_GETMEM do, but it seems that it mostly returns 0.
    * Therefore, the second condition is usually `size > 65536`

More details:

* [__builtin_expect](https://gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html)
* [THREAD_GETMEM](https://code.woboq.org/userspace/glibc/sysdeps/x86_64/nptl/tls.h.html#_M/THREAD_GETMEM)


### conclusion

* The minimum size of width to trigger `malloc` & `free` is 65537 most of the time.
* If there is a Format String Vulnerability and the program ends right after calling `printf(buf)`, we can hijack `__malloc_hook` or `__free_hook` with `one-gadget` and use the trick mentioned above to trigger `malloc` & `free` then we can still get the shell even there is no more function call or sth after `printf(buf)`.

## Use execveat to open a shell

When it comes to opening a shell with system call, `execve` always pops up in mind. However, it's not always easily available due to the lack of gadgets or others constraints.
Actually, there is a system call, `execveat`, with following prototype:

```c
int execveat(int dirfd, const char *pathname,
             char *const argv[], char *const envp[],
             int flags);
```

According to its [man page](http://man7.org/linux/man-pages/man2/execveat.2.html), it operates in the same way as `execve`. As for the additional arguments, it mentions that:

> If pathname is absolute, then dirfd is ignored.

Hence, if we make `pathname` point to `"/bin/sh"`, and set `argv`, `envp` and `flags` to 0, we can still get a shell whatever the value of `dirfd`.
