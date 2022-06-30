#!/usr/bin/env python
# -*- coding:UTF-8 -*-

c = 'cbdb2c89f6800e6c93e1c1e541e1a89758f45fd988c6652fa955db2f00290da27' # 加密后的flag
# base64 自定义变化码表
import base64
# 直接用 nRKKAHzMrQzaqQzKpPHClX 解没出来。提示长度不对，补个=号试试。成功了。
cipher = 'nRKKAHzMrQzaqQzKpPHClX=='
my_base64chars = 'XYZFGHI2+/Jhi345jklmEnopuvwqrABCDKL6789abMNWcdefgstOPQRSTUVxyz01'
STD_BASE64CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
# base64chars = string.ascii_uppercase + string.ascii_lowercase + string.digits + '+/'
cipher = cipher.translate(str.maketrans(my_base64chars, STD_BASE64CHARS))
data = base64.b64decode(cipher)
print(data)
# What_is_go_a_A_H
# 拿回去输入key出flag了。
