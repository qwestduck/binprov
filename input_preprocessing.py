from elftools.elf.elffile import ELFFile
from iced_x86 import *

class Preprocessor(ELFFile):
    def __init__(self, filename):
        with open(filename, 'rb') as f:
            super().__init__(f)
            text_section = self.get_section_by_name('.text')
            self.data = text_section.data()
            self.offset = text_section["sh_offset"]

    def print_assembly(self):
        decoder = Decoder(self.elfclass, self.data, ip=self.offset)
        formatter = Formatter(FormatterSyntax.NASM)
        formatter.digit_separator = "`"
        formatter.first_operand_char_index = 10
        for instr in decoder:
            disasm = formatter.format(instr)
            start_index = instr.ip - self.offset
            bytes_str = self.data[start_index:start_index + instr.len].hex().upper()
            print(f"{instr.ip:016X} {bytes_str:20} {disasm}")

    def batch(self, batch_size):
        def batched(iterable, max_batch_size):
            batch = []
            for element in iterable:
                batch.append(element)
                if len(batch) >= max_batch_size:
                    yield batch
                    batch = []
            if len(batch) > 0:
                yield batch
        for b in batched(self.data, batch_size):
            yield b
