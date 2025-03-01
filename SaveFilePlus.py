# -*- coding: utf-8 -*-
from tkinter import Tk
from tkinter import filedialog

import base64
import os
import struct
import sys
import traceback
import zlib
import re
import json
from xml.dom import minidom
from lxml import etree

# 真存档文件路径
SAVE_FILE_PATH = os.path.join(os.getenv('LocalAppData'), 'GeometryDash')
# 存档文件名
FILE_NAME = ['CCGameManager', 'CCLocalLevels']
# 音乐库
LIBRARY_NAME = ['musiclibrary', 'sfxlibrary']

# 默认选项
config = {
    "src": SAVE_FILE_PATH,
    "xml": ".",
    "dst": ".",
    "prettify": True,
    "simple": False
}

HELP = '''
    e    -> 加密一个文件
    d    -> 解密一个文件
    ecpt -> 加密多个文件
    dcpt -> 解密多个文件
    ptfy -> 开关xml文件整理
    smpl -> 开关导出xml时简化,不导出关卡内容字符串
    save -> 浏览实际游戏存档文件夹
    src  -> 浏览默认解密源路径
    xml  -> 浏览默认xml路径,即加密源路径或解密输出路径
    dst  -> 浏览默认加密输出路径
    exit -> 退出程序
    quit -> 也是退出
'''

def print_menu() -> None:
    os.system('cls')
    print(f'Geometry Dash Savefile Encrypter & Decrypter by WEGFan\n'
          'Enhancement by Naxrin\n'
          'Decryption code downloaded from https://pastebin.com/JakxXUVG by Absolute Gamer'
          '\n' + HELP)

def xor_bytes(data: bytes, key: int) -> bytes:
    return bytes(map(lambda x: x ^ key, data))

def xor(string: str, key: int) -> str:
    return ("").join(chr(ord(char) ^ key) for char in string)

def encrypt(decompressed_data: bytes) -> bytes:
    compressed_data = zlib.compress(decompressed_data)
    data_crc32 = zlib.crc32(decompressed_data)
    data_size = len(decompressed_data)
    compressed_data = (b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x0b' +  # gzip header
                        compressed_data[2:-4] +
                        struct.pack('I I', data_crc32, data_size))
    encoded_data = base64.b64encode(compressed_data, altchars=b'-_')
    return xor_bytes(encoded_data, 11)

def decrypt(encrypted_data: str, simple:bool, prettify:bool) -> bytes:
    decrypted_data = xor(encrypted_data, 11)
    decoded_data = base64.b64decode(decrypted_data, altchars=b'-_')
    decompressed_data = zlib.decompress(decoded_data[10:], -zlib.MAX_WBITS)
    if not simple and not prettify:
        return decompressed_data
    utf_text = decompressed_data.decode("utf-8", errors = "ignore")
    if simple:
        utf_text = re.sub(r'<k>k4</k><s>.+?</s>', '', utf_text)
    if prettify:
        try:
            xml_dom = minidom.parseString(utf_text)
            decompressed_data = xml_dom.toprettyxml(encoding='utf-8')
        except Exception as err:
            print(f'无法优化xml格式!将会原味输出...')
    else:
        decompressed_data = utf_text.encode("utf-8", errors = "ignore")
    return decompressed_data

def main():
    global config

    # 读配置
    try:
        with open("config.json", 'r', encoding = "utf-8") as f:
            config = {**config, **json.load(f)}
    except:
        pass
    # 输出菜单提示
    print_menu()

    root = Tk()
    root.withdraw()

    while True:
        answer = input('输入命令>>> ')

        # encrypt
        if answer == 'e':

            # 单选xml文件
            xml = filedialog.askopenfilename(initialdir = config["xml"], title="选择xml文本文件", filetypes=(("明文文件", "*.xml"),))
            if not xml:
                print("未选择xml文件，已中断")
                continue

            # 选择输出路径
            dst = filedialog.asksaveasfilename(initialdir = config["dst"], title="选择加密后文件输出路径及名字", filetypes=(("存档文件", "*.dat"),))
            if not dst:
                print("未给出文件输出路径，已中断")
                continue

            # 重设路径到配置
            config["xml"] = os.path.dirname(xml)
            config["dst"] = os.path.dirname(dst)

            # 加密
            try:
                print(f'正在加密: {xml}...')

                with open(xml, 'rb') as f:
                    decrypted_data = f.read()
                encrypted_data = encrypt(decrypted_data)
                with open(dst, 'wb') as f:
                    f.write(encrypted_data)
                print('完成!')
            except FileNotFoundError:
                print(f"当前路径没找到: {xml}")
            except Exception:
                print(f'原因不详但无法加密: {xml}')
                traceback.print_exc()

            continue

        # decrypt
        if answer == 'd':
            # 单选dat文件
            src = filedialog.askopenfilename(initialdir = config["src"], title="选择加密的存档文件", filetypes=(("存档文件", "*.dat"),))
            if not src:
                print("未选择dat文件，已中断")
                continue
            # 选择输出路径
            xml = filedialog.asksaveasfilename(initialdir = config["xml"], title="选择解密后文件输出路径", filetypes=(("明文文件", "*.xml"),))
            if not xml:
                print("未选择文件输出路径，已中断")
                continue

            config["src"] = os.path.dirname(src)
            config["xml"] = os.path.dirname(xml)

            try:
                print(f'正在解密: {src}...')
                with open(src, 'r') as f:
                    encrypted_data = f.read()
                decompressed_data = decrypt(encrypted_data, config["simple"], config["prettify"])

                with open(xml, 'wb') as f:
                    f.write(decompressed_data)
                print('完成!')
            except FileNotFoundError:
                print(f"当前路径没找到: {src}")
            except Exception:
                print(f'原因不详但无法解密: {src}')
                traceback.print_exc()

            continue

        # encrypt
        if answer == 'ecpt':

            # 多选xml文件
            xmls = filedialog.askopenfilenames(initialdir = config["xml"], title="选择xml文本文件", filetypes=(("明文文件", "*.xml"),))
            if not xmls:
                print("未选择xml文件，已中断")
                continue

            # 选择输出路径
            dst = filedialog.askdirectory(initialdir = config["dst"], title="选择加密后文件输出路径")
            if not dst:
                print("未选择文件输出路径，已中断")
                continue

            # 覆盖检查
            existing = []
            files = os.listdir(dst)
            for xml in xmls:
                if os.path.basename(xml)[:-4] + '.dat' in files:
                    existing.append(os.path.basename(xml)[:-4] + '.dat')
            if existing:
                print("当前输出路径下已有的以下文件将会被覆盖！请慎重确认后，输入任意文本继续，留空则中断！")
                for exist in existing:
                    print(exist)
                if not input('>>>'):
                    print('已中断')
                    continue

            # 重设路径到配置
            config["xml"] = os.path.dirname(xmls[0])
            config["dst"] = dst

            # 逐个加密
            for xml in xmls:
                try:
                    print(f'正在加密: {xml}...')

                    with open(xml, 'rb') as f:
                        decrypted_data = f.read()
                    encrypted_data = encrypt(decrypted_data)
                    with open(os.path.join(dst, os.path.basename(xml)[:-4] + '.dat'), 'wb') as f:
                        f.write(encrypted_data)
                    print('完成!')
                except FileNotFoundError:
                    print(f"当前路径没找到: {xml}")
                except Exception:
                    print(f'原因不详但无法加密: {xml}')
                    traceback.print_exc()

            continue

        # decrypt
        if answer == 'dcpt':
            # 多选xml文件
            srcs = filedialog.askopenfilenames(initialdir = config["src"], title="选择加密的存档文件", filetypes=(("存档文件", "*.dat"),))
            if not srcs:
                print("未选择dat文件，已中断")
                continue
            xml = filedialog.askdirectory(initialdir = config["xml"], title="选择解密后文件输出路径")
            if not xml:
                print("未选择文件输出路径，已中断")
                continue

            # 覆盖检查
            existing = []
            files = os.listdir(xml)
            for src in srcs:
                if os.path.basename(src)[:-4] + '.xml' in files:
                    existing.append(os.path.basename(src)[:-4] + '.xml')
            if existing:
                print("当前输出路径下已有的以下文件将会被覆盖！请慎重确认后，输入任意文本继续，留空则中断！")
                for exist in existing:
                    print(exist)
                if not input('>>>'):
                    print('已中断')
                    continue

            config["src"] = os.path.dirname(srcs[0])
            config["xml"] = xml

            for src in srcs:
                try:
                    print(f'正在解密{src}...')
                    with open(src, 'r') as f:
                        encrypted_data = f.read()
                    decompressed_data = decrypt(encrypted_data, config["simple"], config["prettify"])

                    with open(os.path.join(xml, os.path.basename(src)[:-4] + '.xml'), 'wb') as f:
                        f.write(decompressed_data)
                    print('完成!')
                except FileNotFoundError:
                    print(f"当前路径没找到: {src}")
                except Exception:
                    print(f'原因不详但无法解密: {src}')
                    traceback.print_exc()

            continue

        if answer == 'ptfy':
            config['prettify'] = not config['prettify']
            print("整理xml格式:" + ('OFF -> ON' if config['prettify'] else 'ON -> OFF'))
            continue

        if answer == 'smpl':
            config['simple'] = not config['simple']
            print("输出前省略关卡内容:" + ('OFF -> ON' if config['simple'] else 'ON -> OFF'))
            continue

        if answer == 'save':
            if os.path.exists(SAVE_FILE_PATH):
                os.startfile(SAVE_FILE_PATH)
            else:
                print("路径不存在：你真的安装游戏了吗")
            continue

        if answer == 'src':
            if os.path.exists(config['src']):
                os.startfile(config['src'])
            else:
                print(f"路径不存在：{config['src']}")
            continue

        if answer == 'xml':
            if os.path.exists(config['xml']):
                os.startfile(config['xml'])
            else:
                print(f"路径不存在：{config['xml']}")
            continue

        if answer == 'dst':
            if os.path.exists(config['dst']):
                os.startfile(config['dst'])
            else:
                print(f"路径不存在：{config['dst']}")
            continue

        # 退出
        if answer == 'exit' or answer == 'quit':
            break
        else:
            if answer:
                print("没有此命令！")
            continue

    # 保存配置
    with open('config.json', 'w', encoding = 'utf-8') as f:
        json.dump(config, f, ensure_ascii = False, indent = 4)

if __name__ == '__main__':
    try:
        main()
    except (EOFError, KeyboardInterrupt) as err:
        sys.exit()
