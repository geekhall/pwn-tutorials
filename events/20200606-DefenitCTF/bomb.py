#-*- coding:utf-8 -*-
from pwn import *
import chardet
context(arch = 'i386' , os = 'linux', log_level='debug')
r = remote('minesweeper.ctf.defenit.kr','3333');
#r.send (asm(shellcraft.sh()))

def getpoint(aaa,lei,surelei):
    flg = True
    for iii in range(len(aaa)):
        for yyy in range(len(aaa[iii])):
            #print ("curr comule is ",aaa[iii][yyy],"iii =",iii, "  yyy= " ,yyy)
            fff = aaa[iii][yyy]
            maylei = []
            if len(re.findall(r"^[ ]*[0-9][ ]*",fff)) > 0:
                leinum2 = int(fff.strip())
                #print ("等于0退出 leinum2 == ",leinum2)
                if leinum2 == 0:
                    continue
                leinum = 0
                synum = 0
                for iiii in [iii-1,iii,iii+1]:
                    for yyyy in [yyy-1,yyy,yyy+1]:
                        if iiii < 0 or yyyy < 0 or iiii >15 or yyyy > 15:
                            pass
                        else:
                            if len(re.findall(r"^[ ]*[0-9fF][ ]*",aaa[iiii][yyyy])) > 0:
                                if len(re.findall(r"^[ ]*[fF][ ]*",aaa[iiii][yyyy])) > 0:
                                    leinum = leinum + 1
                                continue
                            else:
                                if  (str(iiii) + '-' + str(yyyy)) in lei:
                                    leinum = leinum +1
                                else:
                                    maylei.append(str(iiii) + '-' + str(yyyy))
                                    synum = synum +1
                #print("8888888888888888888888888888888888888 iii = ",iii,"yyy = ", yyy ,"leinum2 = " ,leinum2 , "leinum = ",leinum,"synum = " ,synum)
                if leinum2 == leinum and synum > 0:
                    for ii in maylei:
                        if ii in lei:
                            continue
                        else:
                            if  len(re.findall(r"^[ ]*[Ff][ ]*",aaa[int(ii.split("-")[0])][int(ii.split("-")[1])])) > 0:
                                maylei.remove(ii)
                            if( len(maylei) > 0 ):
                                #print("reutn 111 " )
                                return maylei
                            else:
                                continue
                elif leinum2 == (leinum + synum) :
                    for iiiii in maylei:
                        lei.append(iiiii)
                        lei = list(set(lei))
                    flg = False
                    for i in range(len(maylei)):
                        maylei[i]=maylei[i]+'-f'
                    if (len(maylei) > 0 ):
                        #print ( "return 222")
                        return maylei
                else:
                    surelei.append([maylei,leinum2 - leinum])

    lasttmp = ''
    for  iii in range(len(aaa)):
        for yyy in range(len(aaa[iii])):
            tmp = str(iii) + '-' + str(yyy)
            if tmp in lei:
                continue
            else:
                flg2 = True
                for i in surelei:
                    if tmp in i[0]:
                        flg2 = False
                    lasttmp = i[0][0]
                    #else:
                     #   # return [tmp]
                if flg2 == False:
                    continue
            if len(re.findall(r"^[ ]*[0-9Ff][ ]*",aaa[iii][yyy])) > 0:
                continue
            #print("return 444")
            #print([tmp])
            return [tmp]
    #print("return 555")
    return lasttmp

lei = []
surelei = []
eee = []
ii = 0;
while True:
    aaa = [];
    #print("=========")
    ccc = 0 
    while True:
        value = r.recvline()
        #print (value)
        #if i in [2,4,6,8,10,12,14,16,18,20,22,24,26,28,30,32]:
        if  len(re.findall(r"^[ ]*[0-9]",value.decode())) > 0:
            bbb=value.decode().split('|')
            aaa.append(bbb)
            ccc = ccc +1
            if(ccc == 16 ):
                break
    for aa in range(len(aaa)):
        aaa[aa].pop(0)
        aaa[aa].pop()
        #print (aaa[aa])

    #print("eeeljx == ",eee)
    if ( len(eee) == 0):
        #print ("走这里了")
        eee = getpoint(aaa,lei,surelei)
        if len(eee) == 0:
            #for iiiiii in range(len(aaa)):
             #   for yyyyyy in range(len(iiiii):
              #      if aaa[iiiii]
            #print ("end......")
            exit(0)

    #print( "eeeeeeeeeeeeeeee = " ,eee);
    tmp2 = ''
    try:
        tmp2 = eee.pop()
    except:
        for iii in range(len(aaa)):
            for yyy in  range(len(aaa[iii])):
                tmp2 = str(iii) + "-" + str(yyy) + "-f"
    #print( "eeeeeeeeeeeeeeee = " ,eee,tmp2);
    tmp3 = tmp2.split("-")
    tmp4 = int(tmp3[0]) + 1 ;
    tmp5 = ""
    try:
        if (tmp3[1] == '0'):
            tmp5 = 'a'
        if (tmp3[1] == '1'):
            tmp5 = 'b'
        if (tmp3[1] == '2'):
            tmp5 = 'c'
        if (tmp3[1] == '3'):
            tmp5 = 'd'
        if (tmp3[1] == '4'):
            tmp5 = 'e'
        if (tmp3[1] == '5'):
            tmp5 = 'f'
        if (tmp3[1] == '6'):
            tmp5 = 'g'
        if (tmp3[1] == '7'):
            tmp5 = 'h'
        if (tmp3[1] == '8'):
            tmp5 = 'i'
        if (tmp3[1] == '9'):
            tmp5 = 'j'
        if (tmp3[1] == '10'):
            tmp5 = 'k'
        if (tmp3[1] == '11'):
            tmp5 = 'l'
        if (tmp3[1] == '12'):
            tmp5 = 'm'
        if (tmp3[1] == '13'):
            tmp5 = 'n'
        if (tmp3[1] == '14'):
            tmp5 = 'o'
        if (tmp3[1] == '15'):
            tmp5 = 'p'
        if (len(tmp3) == 3):
            tmp4=str(tmp4)+"f"
    except:
        pass

    #print("点的是",tmp5+str(tmp4))
    r.sendline(tmp5+str(tmp4))
    #print("=========")

    #print(" ljx test  +++++++++++++++++++surelei ===",surelei)
    for i in surelei:
        num = 0
        for tmp in i[0]:
            if len(re.findall(r"^[ ]*[fF][ ]*",aaa[int(tmp.split("-")[0])][int(tmp.split("-")[1])])):
                num  = num +1 
        if num == int(i[1]):
            for tmp2 in i[0]:
                if len(re.findall(r"^[ ]*$",aaa[int(tmp2.split("-")[0])][int(tmp2.split("-")[1])])):
                    #print("新增了这个", tmp2.split("-")[0] ,tmp2.split("-")[1]);
                    eee.append(tmp2.split("-")[0] +"-" + tmp2.split("-")[1])
            surelei.remove(i)
    eee = list(set(eee))
    #print(" ljx test  +++++++++++++++++++surelei ===",surelei)

    ii =ii+1
    #if ii == 2:
     #   break

