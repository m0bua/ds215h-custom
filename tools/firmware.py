"""Read-only Thumb firmware inspection. Offsets and addresses are explicit.

Install capstone into .tools/python or the active Python environment.
Examples: python tools/firmware.py disasm 0x28ac4 0x28b24
          python tools/firmware.py calls 0x0802fc24
"""
import argparse
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.tools/python'))
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS

BASE = 0x08007000
SOURCE = ROOT / 'docs/firmware/APP_DS215H_V0.0.5_250905.bin'
DATA = SOURCE.read_bytes()
MD = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
MD.skipdata = True

def offset(n):
    return n - BASE if n >= BASE else n

def listing(start, end):
    start, end = offset(start), offset(end)
    for ins in MD.disasm(DATA[start:end], BASE + start):
        yield f'{ins.address:08X} [{ins.address-BASE:06X}] {ins.bytes.hex():8} {ins.mnemonic:10} {ins.op_str}'

def calls():
    # Decode BL independently at halfword boundaries. Data may produce false hits.
    for off in range(0, len(DATA)-3, 2):
        h1, h2 = struct.unpack_from('<HH', DATA, off)
        if h1 & 0xF800 != 0xF000 or h2 & 0xD000 != 0xD000:
            continue
        s, j1, j2 = (h1>>10)&1, (h2>>13)&1, (h2>>11)&1
        imm = (s<<24) | ((1^(j1^s))<<23) | ((1^(j2^s))<<22) | ((h1&1023)<<12) | ((h2&2047)<<1)
        if s:
            imm -= 1<<25
        target = BASE+off+4+imm
        if BASE <= target < BASE+len(DATA):
            yield BASE+off, target

def movs():
    for off in range(0,len(DATA)-3,2):
        h1,h2=struct.unpack_from('<HH',DATA,off)
        op=h1&0xFBF0
        if op not in (0xF240,0xF2C0) or h2&0x8000:
            continue
        imm=((h1&15)<<12)|(((h1>>10)&1)<<11)|(((h2>>12)&7)<<8)|(h2&255)
        yield off, 'movw' if op==0xF240 else 'movt', (h2>>8)&15, imm

def refs(value):
    needle=struct.pack('<I',value)
    start=0
    while (start:=DATA.find(needle,start))>=0:
        yield f'word {BASE+start:08X} [{start:06X}]'
        start+=1
    recent={}
    for off,op,reg,imm in movs():
        if op=='movw':
            recent[reg]=(off,imm)
        elif reg in recent:
            before,low=recent[reg]
            if off-before<=32 and ((imm<<16)|low)==value:
                yield f'movw/movt {BASE+before:08X}..{BASE+off:08X} r{reg} (check intervening instructions)'

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('command',choices=['disasm','calls','refs','strings','summary'])
    p.add_argument('args',nargs='*')
    a=p.parse_args()
    if a.command=='disasm':
        print('\n'.join(listing(*(int(x,0) for x in a.args))))
    elif a.command=='calls':
        targets={BASE+offset(int(x,0)) for x in a.args}
        for src,dst in calls():
            if not targets or dst in targets: print(f'{src:08X} [{src-BASE:06X}] -> {dst:08X}')
    elif a.command=='refs':
        for v in a.args:
            print(v); print('\n'.join(refs(int(v,0))))
    elif a.command=='strings':
        pattern=re.compile(a.args[0] if a.args else '.',re.I)
        for match in re.finditer(rb'[\x20-\x7e]{4,}',DATA):
            text=match.group().decode('ascii')
            if pattern.search(text): print(f'{BASE+match.start():08X} [{match.start():06X}] {text}')
    else:
        print(json.dumps({'source':str(SOURCE.relative_to(ROOT)), 'size':len(DATA),
                          'sha256':hashlib.sha256(DATA).hexdigest(), 'base':hex(BASE),
                          'end_exclusive':hex(BASE+len(DATA)),
                          'initial_sp':hex(struct.unpack_from('<I',DATA)[0]),
                          'reset':hex(struct.unpack_from('<I',DATA,4)[0])},indent=2))

if __name__=='__main__':
    main()
