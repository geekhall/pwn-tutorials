from flag import a, b, c, d, flag
assert flag == "De1CTF{" + ''.join([hex(i)[2:] for i in [a, b, c, d]]) + "}"
assert [len(bin(i)[2:]) for i in [a, b, c, d]] == [19, 19, 13, 6]

ma, mb, mc, md = 0x505a1, 0x40f3f, 0x1f02, 0x31

def lfsr(r, m): return ((r << 1) & 0xffffff) ^ (bin(r & m).count('1') % 2)

def combine():
    global a, b, c, d
    a = lfsr(a, ma)
    b = lfsr(b, mb)
    c = lfsr(c, mc)
    d = lfsr(d, md)
    [ao, bo, co, do] = [i & 1 for i in [a, b, c, d]]
    return (ao*bo) ^ (bo*co) ^ (bo*do) ^ co ^ do

def genkey(nb):
    s = ''
    for i in range(nb*8):
        s += str(combine())
    open("data", "w+").write(s)

genkey(128*1024)
