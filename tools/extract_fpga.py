"""Extract the embedded FPGA configuration from the known DS215H V0.0.5 BIN.

The output is a research copy, not a modified firmware or a flashable update.
"""
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'docs/firmware/APP_DS215H_V0.0.5_250905.bin'
DEST = ROOT / 'tmp/research/ds215h-v005-gw1n2.bin'
EXPECTED = '3a9b788147928093d4a6fbdf84df41b12a1587f742e8ff22d7940c60bffb7cae'
START, LENGTH = 0x3D21E, 0x1C3B6
ID_COMMAND = bytes.fromhex('06 00 00 00 01 20 68 1b')

data = SOURCE.read_bytes()
if hashlib.sha256(data).hexdigest() != EXPECTED:
    raise SystemExit('Unexpected firmware SHA-256; refusing to guess offsets.')
fpga = data[START:START + LENGTH]
if len(fpga) != LENGTH or fpga[22:24] != bytes.fromhex('a5 c3') or fpga[24:32] != ID_COMMAND:
    raise SystemExit('Unexpected FPGA header; refusing to extract.')
DEST.parent.mkdir(parents=True, exist_ok=True)
DEST.write_bytes(fpga)
print(f'Extracted {len(fpga)} bytes to {DEST}')
print(f'FPGA image SHA-256: {hashlib.sha256(fpga).hexdigest()}')
