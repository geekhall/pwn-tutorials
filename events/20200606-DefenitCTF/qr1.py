# -*- coding:utf-8 -*-
from pwn import *
import argparse
from PIL import Image, ImageDraw, ImageFont
import time
import zxing

def qrdecode():
    file_path = './img/qr_resize.png'
    reader = zxing.BarCodeReader()
    barcode = reader.decode(file_path)
    return barcode.raw

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('host')
    ap.add_argument('port', type=int)
    args = ap.parse_args()
    r = remote(args.host, args.port)
    r.timeout = 20

    def check_recv(x):
        data = r.recvuntil(x)
        assert(x in data), ('Failed to recv {}'.format(repr(x)))
        return data

    check_recv(b"What is your Hero's name?")
    r.send(b'null2root\n')

    cnt = 0
    while(True):
        check_recv(b'< QR >')
        data = check_recv(b'\n\n')

        def t2qr(x,xx,xy):
            img = Image.new('RGB', (xx+40, xy+20), color = "white")
            d = ImageDraw.Draw(img)
            font = ImageFont.truetype('font/FreeMono.ttf')
            line_spacing = d.textsize('█', font=font)[1]
            text = x.decode('utf-8').replace(' ','').replace('1', '█').replace('0', ' ')
            lines = text.split("\n")
            y = 20
            for line in lines:
                d.text((20,y), line, fill="black", font=font)
                y += line_spacing
            img.save('./img/qr.png')
            im = Image.open('./img/qr.png')
            new_img = im.resize((350,350))
            new_img.save('./img/qr_resize.png')

        x = len(data.decode('utf-8').split('\n')[1]) * 3
        y = len(data.decode('utf-8').split('\n')) * 10
        t2qr(data,x,y)
        #print(cnt)
        data = qrdecode()
        r.sendline(data.encode('utf-8'))

        if(cnt>98):
            r.interactive() # for Enter
        cnt += 1

if __name__ == "__main__":
    main()
