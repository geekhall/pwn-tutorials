import pdb
str_start='A|B|C|D|E|F'
##########'d0d1d2d3d4d5d6'
#=d=d6<<5+d5<<4+d4<<3

def xor_str(str_x,str_y):
    str_z=str_y
    for i in str_x:
        if i in str_y:
            str_z=str_z.replace(i,'')
            if '0' not in str_z:
                str_z+='0'
        else:
            str_z+=i
    str_z="".join(sorted(str_z))
    return str_z
            

def turn_mask(mask):
    mask_list=[]
    for i in range(0,len(bin(mask))-2):
        if mask &1 ==1:
            mask_list.append(i)
        mask=mask>>1
    return mask_list

def lsfr(str_x,mask_list):
    str_x_list=str_x.split('|')
    last_bit=''
    for i in mask_list:
        last_bit=xor_str(str_x_list[i],last_bit)
    if len(str_x_list)>24:
        l=len(str_x_list[-1])
        str_x=str_x[0:0-l]
    str_z=last_bit+'|'+str_x
    return str_z

mask=0x31
mask_list=turn_mask(mask)
str_start='A|B|C|D|E|F'
for i in range(0,20):
    #pdb.set_trace()
    str_start=lsfr(str_start,mask_list)
    print(str_start)
