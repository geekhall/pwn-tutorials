import gdb
import subprocess
import re
import copy

main_arena = 0
main_arena_off = 0 #You need to modify it if libc is stripd
top = {}
_int_malloc_off = 0 # You need to modify it
_int_free_off = 0 # You need to modify it
malloc_off = 0 # You need to modify it
free_off = 0 # You need to modify it
last_remainder = {}
fastbinsize = 10
fastbin = []
freememoryarea = {} #using in parse
allocmemoryarea = {}
freerecord = {} # using in trace
unsortbin = []
smallbin = {}  #{size:bin}
largebin = {}
tracemode = False
tracelargebin = True
mallocbp = None
freebp = None
print_overlap = True
DEBUG = False  #debug msg (free and malloc) if you want
capsize = 0
word = ""
arch = ""

plt = {}

def init():
    global plt
    procname = getprocname()
    result = subprocess.check_output("file " + procname,shell=True).decode('utf8')
    if len(plt) == 0 and "statically" not in result :
        plt = getplt()

def showstack():
    pat = "\<.*\>"
    output = ""
    output += "\033[34m"
    data = gdb.execute('x/x $context_t ',to_string=True)[:-1]
    output += data.split(":")[0]
    output += ":"
    output += "\033[37m"
    output += data.split(":")[1]
    value = data.split(":")[1][1:]
    try :
        devalue = gdb.execute('x/wx ' + str(value),to_string=True)
        output += " --> "
        if re.search(pat,devalue):
            output += "<" + devalue.split("<")[1]
        else :
            output += devalue.split(":")[1][1:]
    except :
        output += "\n"
    print(output,end="")

def showreg(reg):
    pat = "\<.*\>"
    output = ""
    output += gdb.execute('printf " 0x%08X ", ' + reg,to_string=True)
    try :
        devalue = gdb.execute('x/wx ' + str(output),to_string=True)
        output += " --> "
        if re.search(pat,devalue) :
            output += "<" +  devalue.split("<")[1]
        else :
            output += devalue.split(":")[1][1:]
    except :
        output += "\n"
    print(output,end="")

def getprocname():
    data = gdb.execute("info proc exe",to_string=True)
    procname = re.search("exe.*",data).group().split("=")[1][2:-1]
    return procname

def procmap():
    data = gdb.execute('info proc exe',to_string = True)
    pid = re.search('process.*',data)
    if pid :
        pid = pid.group()
        pid = pid.split()[1]
        maps = open("/proc/" + pid + "/maps","r")
        infomap = maps.read()
        maps.close()
        return infomap
    else :
        return "error"

def vmmap():
    print(procmap(),end="")

def findstr(pat):
    infomap = procmap()
    mems = infomap.split('\n')
    for mem in mems[:-1] :
        start = int((mem.split()[0]).split("-")[0],16)
        end = int((mem.split()[0]).split("-")[1],16) - 0x1
        gdbcmd = "find " + hex(start) + "," + hex(end) + "," + "\"" + pat + "\""
        result = gdb.execute(gdbcmd ,to_string=True)
        if re.search("Pattern not found",result):
            continue
        else :
            for addr in result.split('\n')[:-2]:
                name = mem.split()[5]
                try :
                    content = (gdb.execute("x/s " + addr,to_string=True)).split()[1]
                    output = "\033[34m" + addr + "\033[37m"+ " --> " + content + "\033[32m" + " (" + name + ")"+"\033[37m" + '\n'
                    print(output,end="")
                except :
                    continue

def libcbase():
    infomap = procmap()
    data = re.search(".*libc.*\.so",infomap)
    if data :
        libcaddr = data.group().split("-")[0]
        return int(libcaddr,16)
    else :
        return 0

def ldbase():
    infomap = procmap()
    data = re.search(".*ld.*\.so",infomap)
    if data :
        ldaddr = data.group().split("-")[0]
        return int(ldaddr,16)
    else :
        return 0

def codebase():
    infomap = procmap()
    procname = getprocname()
    pat = ".*" + procname
    data = re.search(pat,infomap)
    if data :
        codeaddr = data.group().split("-")[0]
        return int(codeaddr,16)
    else :
        return 0


def putlibc():
    print("\033[34m" + "libc : " + "\033[37m" + hex(libcbase()))


def putld():
    print("\033[34m" + "ld : " + "\033[37m" + hex(ldbase()))


def putcodebase():
    print("\033[34m" + "code : " + "\033[37m" + hex(codebase()))


def ispie():
    procname = getprocname()
    result = subprocess.check_output("readelf -h " + procname,shell=True).decode('utf8')
    if re.search("DYN",result):
        return True
    else:
        return False


def off(sym):
    libc = libcbase()
    try :
        symaddr = int(sym,16)
        return symaddr-libc
    except :
        data = gdb.execute("x/x " + sym ,to_string=True)
        if "No symbol" in data:
            return 0
        else :
            data = re.search("0x.*[0-9a-f] ",data)
            data = data.group()
            symaddr = int(data[:-1] ,16)
            return symaddr-libc

def putoff(sym) :
    symaddr = off(sym)
    if symaddr == 0 :
        print("Not found the symbol")
    else :
        print("\033[34m" + sym  + ":" + "\033[37m" +hex(symaddr))


def abcd(bit):
    s = ""
    for i in range(0x7a-0x41):
        s += chr(0x41+i)*(int(int(bit)/8))
    print(s)

def length(bit,pat):
    off = (ord(pat) - 0x41)*(int(int(bit)/8))
    print(off)

def got():
    data = gdb.execute("info proc exe",to_string=True)
    procname = re.search("exe.*",data).group().split("=")[1][2:-1]
    got = subprocess.check_output("objdump -R " + procname,shell=True)[:-2]
    print(got.decode('utf8'))

def dyn():
    data = gdb.execute("info proc exe",to_string=True)
    procname = re.search("exe.*",data).group().split("=")[1][2:-1]
    dyn = subprocess.check_output("readelf -d " + procname,shell=True)
    print(dyn.decode('utf8'))

def getgotplt():
    gotplt = []
    procname = getprocname()
    result = subprocess.check_output("objdump -R " + procname +
            "|grep R_ARM_JUMP_SLOT",shell=True )
    result = result.decode('utf8')
    for element in result.split('\n')[:-1]:
        gotplt.append(element.split()[2])
    return gotplt

def getplt():
    plt = {}
    temp = []
    got_plt = ["plt0"]+getgotplt()
    procname = getprocname()
    result = subprocess.check_output("objdump -d -j .plt " + procname +
            "| grep -A 31337 .plt\>",shell=True).decode('utf8')
    pltentry = result.split('\n')[1:]

    if ispie():
        temp.append(hex(int(pltentry[0].split(":")[0].strip(),16) + codebase()))
        pltentry = pltentry[5:]
        for i in range(int(len(pltentry)/3)):
            temp.append(hex(int(pltentry[i*3].split(":")[0].strip(),16) + codebase()) )
    else :
        temp.append(pltentry[0].split(":")[0].strip())
        pltentry = pltentry[5:]
        for i in range(int(len(pltentry)/3)):
            temp.append(hex(int(pltentry[i*3].split(":")[0].strip(),16)) )
    plt = dict(zip(got_plt,temp))
    return plt

def putplt(sym):
    #plt = getplt()
    global plt
    if sym in plt :
        symplt = plt[sym]
        if sym is "plt0":
            result = gdb.execute("x/4i " + symplt,to_string=True)
        else :
            result = gdb.execute("x/3i" + symplt,to_string=True)
    else :
        result = "The symbol not found"
    print(result)

def findplt(addr):
    #plt = getplt()
    global plt
    resplt = dict(zip(plt.values(),plt.keys()))
    if addr in resplt :
        output = "the function is "
        output += "\033[33m"
        output += resplt[addr]
        output += "\033[37m"
    else :
        output = "Not found"
    print(output)

def elfsym():
    #plt = getplt()
    global plt
    for pltentry in plt :
        print("\033[33m" + pltentry + "@plt:" + "\033[37m" + hex(int(plt[pltentry],16)))

def callplt(data):
    resplt = dict(zip(plt.values(),plt.keys()))
    result =  re.search("bl.*0x.*",data)
    if result :
        addr = result.group().split("0x")[1]
        addr = "0x" + addr
        if addr in resplt:
            return data[:-1] + " <" + resplt[addr] + ">\n"
        return data
    else :
        return data

def showcurins() :
    ins = gdb.execute("x/i (unsigned int)$pc | (($cpsr >> 5) & 1)",to_string=True)
    print(callplt(ins),end="")

def showins():
    ins = gdb.execute("x/i",to_string=True)
    print(callplt(ins),end="")

def getarch():
    global capsize
    global word
    global arch
    data = gdb.execute('show arch',to_string = True)
    tmp = re.search("currently.*",data)
    if tmp :
        if "arm" in tmp.group():
            capsize = 4
            word = "wx "
            arch = "arm"
            return "arm"
    else :
        return "error"


def set_main_arena():
    global main_arena
    global main_arena_off
    offset = off("&main_arena")
    libc = libcbase()
    if offset :
        main_arena_off = offset
        main_arena = libc + main_arena_off
    elif main_arena_off :
        main_arena = libc + main_arena_off
    else :
        print("You need to set main arena address")


def check_overlap(addr,size,data = None):
    if data :
        for key,(start,end,chunk) in data.items() :
            if (addr >= start and addr < end) or ((addr+size) > start and (addr+size) < end ) or ((addr < start) and  ((addr + size) > end)):
                return chunk,"error"
    else :
        for key,(start,end,chunk) in freememoryarea.items() :
    #    print("addr 0x%x,start 0x%x,end 0x%x,size 0x%x" %(addr,start,end,size) )
            if (addr >= start and addr < end) or ((addr+size) > start and (addr+size) < end ) or ((addr < start) and  ((addr + size) > end)):
                return chunk,"freed"
        for key,(start,end,chunk) in allocmemoryarea.items() :
    #    print("addr 0x%x,start 0x%x,end 0x%x,size 0x%x" %(addr,start,end,size) )
            if (addr >= start and addr < end) or ((addr+size) > start and (addr+size) < end ) or ((addr < start) and  ((addr + size) > end)) :
                return chunk,"inused"
    return None,None

def get_top_lastremainder():
    global main_arena
    global fastbinsize
    global top
    global last_remainder
    chunk = {}
    if capsize == 0 :
        arch = getarch()
    #get top
    cmd = "x/" + word + hex(main_arena + fastbinsize*capsize + 8 )
    chunk["addr"] =  int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
    chunk["size"] = 0
    if chunk["addr"] :
        cmd = "x/" + word + hex(chunk["addr"]+capsize*1)
        try :
            chunk["size"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16) & 0xfffffffffffffff8
            if chunk["size"] > 0x21000 :
                chunk["memerror"] = "top is broken ?"
        except :
            chunk["memerror"] = "invaild memory"
    top = copy.deepcopy(chunk)
    #get last_remainder
    chunk = {}
    cmd = "x/" + word + hex(main_arena + (fastbinsize+1)*capsize + 8 )
    chunk["addr"] =  int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
    chunk["size"] = 0
    if chunk["addr"] :
        cmd = "x/" + word + hex(chunk["addr"]+capsize*1)
        try :
            chunk["size"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16) & 0xfffffffffffffff8
        except :
            chunk["memerror"] = "invaild memory"
    last_remainder = copy.deepcopy(chunk)

def get_fast_bin():
    global main_arena
    global fastbin
    global fastbinsize
    global freememoryarea
    fastbin = []
    #freememoryarea = []
    if capsize == 0 :
        arch = getarch()
    for i in range(fastbinsize-3):
        fastbin.append([])
        chunk = {}
        is_overlap = (None,None)
        cmd = "x/" + word  + hex(main_arena + i*capsize + 8)
        chunk["addr"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
        while chunk["addr"] and not is_overlap[0]:
            cmd = "x/" + word + hex(chunk["addr"]+capsize*1)
            try :
                chunk["size"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16) & 0xfffffffffffffff8
            except :
                chunk["memerror"] = "invaild memory"
                break
            is_overlap = check_overlap(chunk["addr"], (capsize*2)*(i+2))
            chunk["overlap"] = is_overlap
            freememoryarea[hex(chunk["addr"])] = copy.deepcopy((chunk["addr"],chunk["addr"] + (capsize*2)*(i+2) ,chunk))
            fastbin[i].append(copy.deepcopy(chunk))
            cmd = "x/" + word + hex(chunk["addr"]+capsize*2)
            chunk = {}
            chunk["addr"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
        if not is_overlap[0]:
            chunk["size"] = 0
            chunk["overlap"] = None
            fastbin[i].append(copy.deepcopy(chunk))


def trace_normal_bin(chunkhead):
    global main_arena
    global freememoryarea
    libc = libcbase()
    bins = []
    if capsize == 0 :
        arch = getarch()
    if chunkhead["addr"] == 0 : # main_arena not initial
        return None
    chunk = {}
    cmd = "x/" + word  + hex(chunkhead["addr"] + capsize*2) #fd
    chunk["addr"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16) #get fd chunk
    if (chunk["addr"] == chunkhead["addr"]) :  #no chunk in the bin
        if (chunkhead["addr"] > libc) :
            return bins
        else :
            try :
                cmd = "x/" + word + hex(chunk["addr"]+capsize*1)
                chunk["size"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16) & 0xfffffffffffffff8
                is_overlap = check_overlap(chunk["addr"],chunk["size"])
                chunk["overlap"] = is_overlap
                chunk["memerror"] = "\033[31mbad fd (" + hex(chunk["addr"]) + ")\033[37m"
            except :
                chunk["memerror"] = "invaild memory"
            bins.append(copy.deepcopy(chunk))
            return bins
    else :
        try :
            cmd = "x/" + word + hex(chunkhead["addr"]+capsize*3)
            bk = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
            cmd = "x/" + word + hex(bk+capsize*2)
            bk_fd = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
            if bk_fd != chunkhead["addr"]:
                chunkhead["memerror"] = "\033[31mdoubly linked list corruption {0} != {1} and \033[36m{2}\033[31m is broken".format(hex(chunkhead["addr"]),hex(bk_fd),hex(chunkhead["addr"]))
                bins.append(copy.deepcopy(chunkhead))
                return bins
            fd = chunkhead["addr"]
            chunkhead = {}
            chunkhead["addr"] = bk #bins addr
            chunk["addr"] = fd #first chunk
        except :
            chunkhead["memerror"] = "invaild memory"
            bins.append(copy.deepcopy(chunkhead))
            return bins
        while chunk["addr"] != chunkhead["addr"] :
            try :
                cmd = "x/" + word + hex(chunk["addr"])
                chunk["prev_size"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16) & 0xfffffffffffffff8
                cmd = "x/" + word + hex(chunk["addr"]+capsize*1)
                chunk["size"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16) & 0xfffffffffffffff8
            except :
                chunk["memerror"] = "invaild memory"
                break
            try :
                cmd = "x/" + word + hex(chunk["addr"]+capsize*2)
                fd = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
                if fd == chunk["addr"] :
                    chunk["memerror"] = "\033[31mbad fd (" + hex(fd) + ")\033[37m"
                    bins.append(copy.deepcopy(chunk))
                    break
                cmd = "x/" + word + hex(fd + capsize*3)
                fd_bk = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
                if chunk["addr"] != fd_bk :
                    chunk["memerror"] = "\033[31mdoubly linked list corruption {0} != {1} and \033[36m{2}\033[31m or \033[36m{3}\033[31m is broken".format(hex(chunk["addr"]),hex(fd_bk),hex(fd),hex(chunk["addr"]))
                    bins.append(copy.deepcopy(chunk))
                    break
            except :
                chunk["memerror"] = "invaild memory"
                bins.append(copy.deepcopy(chunk))
                break
            is_overlap = check_overlap(chunk["addr"],chunk["size"])
            chunk["overlap"] = is_overlap
            freememoryarea[hex(chunk["addr"])] = copy.deepcopy((chunk["addr"],chunk["addr"] + chunk["size"] ,chunk))
            bins.append(copy.deepcopy(chunk))
            cmd = "x/" + word + hex(chunk["addr"]+capsize*2) #find next
            chunk = {}
            chunk["addr"] = fd
    return bins


def get_unsortbin():
    global main_arena
    global unsortbin
    unsortbin = []
    if capsize == 0 :
        arch = getarch()
    chunkhead = {}
    cmd = "x/" + word + hex(main_arena + (fastbinsize+2)*capsize+8)
    chunkhead["addr"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
    unsortbin = trace_normal_bin(chunkhead)


def get_smailbin():
    global main_arena
    global smallbin
    smallbin = {}
    if capsize == 0 :
        arch = getarch()
    max_smallbin_size = 512*int(capsize/4)
    for size in range(capsize*4,max_smallbin_size,capsize*2):
        chunkhead = {}
        idx = int((size/(capsize*2)))-1
        cmd = "x/" + word + hex(main_arena + (fastbinsize+2)*capsize+8 + idx*capsize*2)  # calc the smallbin index
        chunkhead["addr"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
        bins = trace_normal_bin(chunkhead)
        if bins and len(bins) > 0 :
            smallbin[hex(size)] = copy.deepcopy(bins)


def largbin_index(size):
    if capsize == 0 :
        arch = getarch()
    if capsize == 8 :
        if (size >> 6) <= 48 :
            idx = 48 + (size >> 6)
        elif (size >> 9) <= 20 :
            idx = 91 + (size >> 9)
        elif (size >> 12) <= 10:
            idx = 110 + (size >> 12)
        elif (size >> 15) <= 4 :
            idx = 119 + (size >> 15)
        elif (size >> 18) <= 2:
            idx = 124 + (size >> 18)
        else :
            idx = 126
    else :
        if (size >> 6) <= 38 :
            idx = 56 + (size >> 6)
        elif (size >> 9) <= 20 :
            idx = 91 + (size >> 9)
        elif (size >> 12) <= 10:
            idx = 110 + (size >> 12)
        elif (size >> 15) <= 4 :
            idx = 119 + (size >> 15)
        elif (size >> 18) <= 2:
            idx = 124 + (size >> 18)
        else :
            idx = 126
    return idx


def get_largebin():
    global main_arena
    global largebin
    largebin = {}
    if capsize == 0 :
        arch = getarch()
    min_largebin = 512*int(capsize/4)
    for idx in range(64,128):
        chunkhead = {}
        cmd = "x/" + word + hex(main_arena + (fastbinsize+2)*capsize + idx*capsize*2)  # calc the largbin index
        chunkhead["addr"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
        bins = trace_normal_bin(chunkhead)
        if bins and len(bins) > 0 :
            largebin[idx] = copy.deepcopy(bins)

def get_heap_info():
    global main_arena
    global freememoryarea
    global top
    top = {}
    freememoryarea = {}
    set_main_arena()
    if main_arena :
        get_unsortbin()
        get_smailbin()
        if tracelargebin :
            get_largebin()
        get_fast_bin()
        get_top_lastremainder()


def get_reg(reg):
    cmd = "info register " + reg
    result = int(gdb.execute(cmd,to_string=True).split()[1].strip(),16)
    return result


def trace_malloc():
    global mallocbp
    global freebp
    libc = libcbase()
    if capsize == 0 :
        arch = getarch()
    if capsize == 8 :
        if _int_malloc_off != 0 :
            malloc_addr = libc + _int_malloc_off
            free_addr = libc + _int_free_off
        else :
            malloc_addr = libc + malloc_off
            free_addr = libc + free_off
    else :
        if _int_malloc_off_32 != 0 :
            malloc_addr = libc + _int_malloc_off_32
            free_addr = libc + _int_free_off_32
        else :
            malloc_addr = libc + malloc_off_32
            free_addr = libc + free_off_32

    mallocbp = Malloc_Bp_handler("*" + hex(malloc_addr))
    freebp = Free_Bp_handler("*" + hex(free_addr))
    get_heap_info()

def dis_trace_malloc():
    global mallocbp
    global freebp
    if mallocbp and freebp :
        mallocbp.delete()
        freebp.delete()
        mallocbp = None
        freebp = None
        allocmemoryarea = {}

def set_trace_mode(option="on"):
    global tracemode
    if option == "on":
        tracemode = True
        trace_malloc()
    else :
        tracemode = False
        dis_trace_malloc()

def find_overlap(chunk,bins):
    is_overlap = False
    count = 0
    for current in bins :
        if chunk["addr"] == current["addr"] :
            count += 1
    if count > 1 :
        is_overlap = True
    return is_overlap


def putfastbin():
    if capsize == 0 :
        arch = getarch()
    get_heap_info()
    for i,bins in enumerate(fastbin) :
        cursize = (capsize*2)*(i+2)
        print("\033[32m(0x%02x)     fastbin[%d]:\033[37m " % (cursize,i),end = "")
        for chunk in bins :
            if "memerror" in chunk :
                print("\033[31m0x%x (%s)\033[37m" % (chunk["addr"],chunk["memerror"]),end = "")
            elif chunk["size"] != cursize and chunk["addr"] != 0 :
                print("\033[36m0x%x (size error (0x%x))\033[37m" % (chunk["addr"],chunk["size"]),end = "")
            elif chunk["overlap"] and chunk["overlap"][0]:
                print("\033[31m0x%x (overlap chunk with \033[36m0x%x(%s)\033[31m )\033[37m" % (chunk["addr"],chunk["overlap"][0]["addr"],chunk["overlap"][1]),end = "")
            elif chunk == bins[0]  :
                print("\033[34m0x%x\033[37m" % chunk["addr"],end = "")
            else  :
                if print_overlap :
                    if find_overlap(chunk,bins):
                        print("\033[31m0x%x\033[37m" % chunk["addr"],end ="")
                    else :
                        print("0x%x" % chunk["addr"],end = "")
                else :
                    print("0x%x" % chunk["addr"],end = "")
            if chunk != bins[-1]:
                print(" --> ",end = "")
        print("")

def putheapinfo():
    if capsize == 0 :
        arch = getarch()
    putfastbin()
    if "memerror" in top :
        print("\033[35m %20s:\033[31m 0x%x \033[33m(size : 0x%x)\033[31m (%s)\033[37m " % ("top",top["addr"],top["size"],top["memerror"]))
    else :
        print("\033[35m %20s:\033[34m 0x%x \033[33m(size : 0x%x)\033[37m " % ("top",top["addr"],top["size"]))
    print("\033[35m %20s:\033[34m 0x%x \033[33m(size : 0x%x)\033[37m " % ("last_remainder",last_remainder["addr"],last_remainder["size"]))
    if unsortbin and len(unsortbin) > 0 :
        print("\033[35m %20s:\033[37m " % "unsortbin",end="")
        for chunk in unsortbin :
            if "memerror" in chunk :
                print("\033[31m0x%x (%s)\033[37m" % (chunk["addr"],chunk["memerror"]),end = "")
            elif chunk["overlap"] and chunk["overlap"][0]:
                print("\033[31m0x%x (overlap chunk with \033[36m0x%x(%s)\033[31m )\033[37m" % (chunk["addr"],chunk["overlap"][0]["addr"],chunk["overlap"][1]),end = "")
            elif chunk == unsortbin[-1]:
                print("\033[34m0x%x\033[37m \33[33m(size : 0x%x)\033[37m" % (chunk["addr"],chunk["size"]),end = "")
            else :
                print("0x%x \33[33m(size : 0x%x)\033[37m" % (chunk["addr"],chunk["size"]),end = "")
            if chunk != unsortbin[-1]:
                print(" <--> ",end = "")
        print("")
    else :
        print("\033[35m %20s:\033[37m 0x%x" % ("unsortbin",0)) #no chunk in unsortbin
    for size,bins in smallbin.items() :
        idx = int((int(size,16)/(capsize*2)))-2
        print("\033[33m(0x%03x)  %s[%2d]:\033[37m " % (int(size,16),"smallbin",idx),end="")
        for chunk in bins :
            if "memerror" in chunk :
                print("\033[31m0x%x (%s)\033[37m" % (chunk["addr"],chunk["memerror"]),end = "")
            elif chunk["size"] != int(size,16) :
                print("\033[36m0x%x (size error (0x%x))\033[37m" % (chunk["addr"],chunk["size"]),end = "")
            elif chunk["overlap"] and chunk["overlap"][0]:
                print("\033[31m0x%x (overlap chunk with \033[36m0x%x(%s)\033[31m )\033[37m" % (chunk["addr"],chunk["overlap"][0]["addr"],chunk["overlap"][1]),end = "")
            elif chunk == bins[-1]:
                print("\033[34m0x%x\033[37m" % chunk["addr"],end = "")
            else :
                print("0x%x " % chunk["addr"],end = "")
            if chunk != bins[-1]:
                print(" <--> ",end = "")
        print("")
    for idx,bins in largebin.items():
#        print("\033[33m(0x%03x-0x%03x)  %s[%2d]:\033[37m " % (int(size,16),int(maxsize,16),"largebin",idx),end="")
        print("\033[33m  %15s[%2d]:\033[37m " % ("largebin",idx),end="")
        for chunk in bins :
            if "memerror" in chunk :
                print("\033[31m0x%x (%s)\033[37m" % (chunk["addr"],chunk["memerror"]),end = "")
            elif chunk["overlap"] and chunk["overlap"][0]:
                print("\033[31m0x%x (overlap chunk with \033[36m0x%x(%s)\033[31m )\033[37m" % (chunk["addr"],chunk["overlap"][0]["addr"],chunk["overlap"][1]),end = "")
            elif largbin_index(chunk["size"]) != idx :
                print("\033[31m0x%x (incorrect bin size :\033[36m 0x%x\033[31m)\033[37m" % (chunk["addr"],chunk["size"]),end = "")
            elif chunk == bins[-1]:
                print("\033[34m0x%x\033[37m \33[33m(size : 0x%x)\033[37m" % (chunk["addr"],chunk["size"]),end = "")
            else :
                print("0x%x \33[33m(size : 0x%x)\033[37m" % (chunk["addr"],chunk["size"]),end = "")
            if chunk != bins[-1]:
                print(" <--> ",end = "")
        print("")


def putinused():
    print("\033[33m %s:\033[37m " % "inused ",end="")
    for addr,(start,end,chunk) in allocmemoryarea.items() :
        print("0x%x," % (chunk["addr"]),end="")
    print("")

def checksec():
    filename = gdb.objfiles()[0].filename
    result = {}
    result["RELRO"] = 0
    result["CANARY"] = 0
    result["NX"] = 1
    result["PIE"] = 0
    result["FORTIFY"] = 0
    if filename is None :
        print("Error")
        return 0
    data = subprocess.check_output("readelf -W -a " + filename,shell=True).decode('utf8')

    if re.search("GNU_RELRO",data):
        result["RELRO"] |= 2
    if re.search("BIND_NOW",data):
        result["RELRO"] |= 1
    if re.search("__stack_chk_fail",data):
        result["CANARY"] = 1
    if re.search(r"GNU_STACK.*RWE.*\n",data):
        result["NX"] = 0
    if re.search(r"DYN \(",data):
        result["PIE"] = 4
    if re.search(r"\(DEBUG\)",data) and result["PIE"] == 4 :
        result["PIE"] = 1
    if re.search("_chk@",data):
        result["FORTIFY"] = 1

    if result["RELRO"] == 1:
        result["RELRO"] = 0

    out = {
        0 : "\033[31mdisabled\033[37m",
        1 : "\033[32mENABLE\033[37m",
        2 : "\033[33mPartial\033[37m",
        3 : "\033[32mFULL\033[37m",
        4 : "\033[33mDynamic Shared Object\033[37m"
        }

    for (k,v) in sorted(result.items()):
        print("%s : %s" % (k.ljust(10), out[v]))
    return
