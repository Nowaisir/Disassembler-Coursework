from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QSizePolicy,
    QStackedLayout,
    QWidget,
    QPushButton,
    QFileDialog,
    QLabel,
    QVBoxLayout,
    QMessageBox,
)

from PySide6 import QtCore
from PySide6.QtGui import QFont

# maps numerical register codes to their more programmer friendly aliases
# fmt: off
REGISTER_ALIAS_TABLE = [
    "x0", "ra", "sp", "gp", "tp",
    "t0", "t1", "t2", "fp", "s1",
    "a0", "a1", "a2", "a3", "a4",
    "a5", "a6", "a7", "s2", "s3",
    "s4", "s5", "s6", "s7", "s8",
    "s9", "s10", "s11", "t3", "t4",
    "t5", "t6",
]

# fmt: on


class ExecutableSegmentNotFound(Exception):
    pass


class Register:
    def __init__(self, code):
        self.code = code  # each register in RISC-V is identified a number between 0-31

    def alias(self):
        # fmt: off
        REGISTER_ALIAS_TABLE = [
            "x0", "ra", "sp", "gp", "tp",
            "t0", "t1", "t2", "fp", "s1",
            "a0", "a1", "a2", "a3", "a4",
            "a5", "a6", "a7", "s2", "s3",
            "s4", "s5", "s6", "s7", "s8",
            "s9", "s10", "s11", "t3", "t4",
            "t5", "t6",
        ]

        # fmt: on

        return REGISTER_ALIAS_TABLE[self.code]


class Immediate:
    def __init__(self, bits):
        self.bits = bits

    # converts the immediate value's bits to its textual representation
    # thats suited for assembly programmers
    def parse(self):
        raise NotImplementedError(f"{self.__class__} implements no parse function")


class Int12(Immediate):
    def parse(self):
        signBit = self.bits >> 11 & 1
        if signBit == 0:
            return hex(self.bits)
        else:  # the & 0xFFF discards all the twos complementing done past the 12 bits we want
            magnitude = -self.bits & 0xFFF
            return "-" + hex(magnitude)


class Mask12(Immediate):
    def parse(self):
        # the bit that controls all the  bits more significant than bit 11 in a register
        signBit = self.bits >> 11 & 1

        # the 12 bits in self.bits have no reduced degrees of freedom however
        if signBit:
            return "0xff..f" + hex(self.bits)[2:]
        else:
            return hex(self.bits)


class BasedDisplacedAddress:
    def __init__(self, displacement: Int12, base: Register):
        self.displacement = displacement
        self.base = base


class Instruction:
    def __init__(self, opcode=None, *operands):
        self.opcode = opcode
        self.operands = list(operands)

    def asRichText(self):
        colors = {
            "UNKNOWN": "#A48A85",
            "CONSTANT": "#295F21",  # e.g 0x23
            "REGISTER": "#295F21",  # e.g sp, a0
        }

        for hexColorCode in colors.values():
            assert hexColorCode[0] == "#"  # might make this mistake

        if self.opcode == None:
            return f"<font color={colors['UNKNOWN']}>Unknown Instruction</font>"
        else:
            instructionMarkup = self.opcode

            for i, operand in enumerate(self.operands):
                if i == 0:
                    preceding = " "
                else:
                    preceding = ", "

                if isinstance(operand, Register):
                    operandMarkup = (
                        f"<font color={colors['REGISTER']}>{operand.alias()}</font>"
                    )
                elif isinstance(operand, Immediate):
                    operandMarkup = (
                        f"<font color={colors['CONSTANT']}>{operand.parse()}</font>"
                    )

                elif isinstance(operand, BasedDisplacedAddress):
                    operandMarkup = f"""\
<font color={colors['CONSTANT']}>\
{operand.displacement.parse()}\
</font>\
\
(<font color={colors['REGISTER']}>\
{operand.base.alias()}\
</font>)\
"""
                else:
                    raise NotImplementedError(
                        "Unsupported object inserted into the operands field"
                    )

                instructionMarkup += preceding + operandMarkup

            return instructionMarkup


print("Operandless instructions:")
print(Instruction("ecall").asRichText())
print(Instruction("efence").asRichText())

print("Register only testing:")
print(Instruction("sb", Register(10)).asRichText())
print(Instruction("add", Register(10), Register(0), Register(5)).asRichText())

print("Immediate integer testing")
print(Instruction("addi", Register(10), Register(0), Int12(100)).asRichText())
print(Instruction("addi", Register(10), Register(0), Int12(0xFFB)).asRichText())

print("Immediate mask testing")
print(Instruction("xori", Register(5), Register(5), Mask12(0x10)).asRichText())
print(Instruction("xori", Register(5), Register(5), Mask12(0x800)).asRichText())
print(Instruction("xori", Register(5), Register(5), Mask12(0xFFF)).asRichText())

print("Based displaced addressing:")
print(
    Instruction(
        "sw", Register(10), BasedDisplacedAddress(Int12(8), Register(2))
    ).asRichText()
)


def findInstructionsRange(fileBytes):
    # Use segment header table to locate executable segment
    SEGMENT_HEADER_TABLE = 0x40
    SEGMENT_HEADER_SIZE = 0x38

    numSegments = int.from_bytes(fileBytes[0x38:0x3A], "little")
    instructionsSegment = None

    for header in range(
        SEGMENT_HEADER_TABLE,
        SEGMENT_HEADER_TABLE + numSegments * SEGMENT_HEADER_SIZE,
        SEGMENT_HEADER_SIZE,
    ):
        segmentFlags = int.from_bytes(fileBytes[header + 4 : header + 8], "little")

        # The LSB signifies whether a segment is executable or not
        if segmentFlags & 1 == 1:
            # our heuristic is that the first segment whose memory is executable
            # is the one which all instructions are under
            instructionsSegment = dict(
                offset=int.from_bytes(fileBytes[header + 8 : header + 0x10], "little"),
                virtAddr=int.from_bytes(
                    fileBytes[header + 0x10 : header + 0x18], "little"
                ),
                size=int.from_bytes(fileBytes[header + 0x20 : header + 0x28], "little"),
            )

    if instructionsSegment == None:
        raise ExecutableSegmentNotFound

    # we need the entry point offset in the file but the ELF file only
    # explicitly stores its virtual address. We do however have all the
    # properties of the segment it probably lies in
    entryPointVirtualAddress = int.from_bytes(fileBytes[0x18:0x20], "little")
    toEntryPoint = entryPointVirtualAddress - instructionsSegment["virtAddr"]

    entryPoint = instructionsSegment["offset"] + toEntryPoint

    # each instruction is 4 bytes long, hence the 4
    return range(
        entryPoint, instructionsSegment["offset"] + instructionsSegment["size"], 4
    )


def formattedAddressNumbers(fileBytes):
    entryPointVirtAddr = int.from_bytes(fileBytes[0x18:0x20], "little")
    numInstructions = len(findInstructionsRange(fileBytes))

    addresses = (entryPointVirtAddr + 4 * i for i in range(numInstructions))

    # e.g a range() of [1024, 1028, 1032, 1036] into
    # 0x400, 0x404, 0x408 0x40C
    raw = (hex(addr).title() for addr in addresses)
    pruned = (addr[2:] for addr in raw)  # 0xF04c -> F04C

    # e.g 0000 0400, 000F 30FC, etc.
    beautified = (addr.zfill(8)[0:4] + " " + addr.zfill(8)[4:8] for addr in pruned)

    return "\n".join(beautified)  # as this is used in a QLabel


def decodeInstructions(fileBytes):
    instructions = []
    # the decoding loop
    for _ in findInstructionsRange(fileBytes):
        instructions.append(Instruction())

    # e.g if there are 2 instructions: add a0, x0, 13 and ecall
    # this text should be like
    # ...<br>
    # <font color="#001F00"> ecall</font>
    markup = "<br>".join(instr.asRichText() for instr in instructions)
    return markup


def chooseFile():
    filePath = QFileDialog.getOpenFileName()[0]

    if filePath == "":
        # the user pressed the cancel button on the file dialog
        return

    fileBytes = open(filePath, "rb").read()

    # all ELF files Start with the bytes 7f 45 4c 46
    if fileBytes[0:4] != b"\x7fELF":
        QMessageBox.warning(
            window, "Disassembler", "Oops! You didn't select an ELF executable"
        )

        return

    # This field could be 3E if it were an x86-64 executable
    # 03 if it were an x86 (32 bit) executable
    # B7 if it were an ARM 64 bit executable
    # etc.
    # We're only interested in RISC-V executables
    architecture = int.from_bytes(fileBytes[0x12:0x14], "little")

    ARCH_RISCV = 0xF3
    if architecture != ARCH_RISCV:
        QMessageBox.warning(
            window,
            "Disassembly",
            f"We only support RISC-V executables.\n\
Your architecture ({hex(architecture)}) isn't supported",
        )

        return

    try:  # subsequent calls to findInstructionsRange() are safe
        findInstructionsRange(fileBytes)
    except ExecutableSegmentNotFound:
        QMessageBox.warning(
            window,
            "Disassembler",
            f"Open an executable file. Object files aren't supported",
        )

        return

    # Passed all checks after this point
    primaryLayout.setCurrentIndex(1)  # switch to the disassembly view
    addressNumbers.setText(formattedAddressNumbers(fileBytes))
    addressNumbers.setSizePolicy(
        QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
    )

    assemblyColumn.setText(decodeInstructions(fileBytes))
    assemblyColumn.setSizePolicy(
        QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
    )


app = QApplication()
window = QWidget()  # widgets with no parents specified create their own window
window.setWindowTitle("Disassembler")
window.show()

primaryLayout = (
    QStackedLayout()
)  # allows us to switch between the start screen and disassembly view
window.setLayout(primaryLayout)

startScreen = QWidget()
startScreen.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
primaryLayout.addWidget(startScreen)

disassemblyScreen = QWidget()
disassemblyScreen.setSizePolicy(
    QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
)
primaryLayout.addWidget(
    disassemblyScreen
)  # order of adding must correspond to the .setCurrentIndexCall()

disassemblyScreenLayout = QHBoxLayout()
disassemblyScreenLayout.setAlignment(
    QtCore.Qt.AlignmentFlag.AlignTop | QtCore.Qt.AlignmentFlag.AlignLeft
)
disassemblyScreenLayout.setContentsMargins(15, 10, 0, 0)
disassemblyScreen.setLayout(disassemblyScreenLayout)

addressNumbers = QLabel()
addressNumbers.setFixedWidth(100)
addressNumbers.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
addressNumbers.setFont(QFont("Courier New", 10))
disassemblyScreenLayout.addWidget(addressNumbers)

# same size and properties of the addressNumbers above
assemblyColumn = QLabel()
assemblyColumn.setAlignment(
    QtCore.Qt.AlignmentFlag.AlignLeft | QtCore.Qt.AlignmentFlag.AlignVCenter
)
assemblyColumn.setFont(QFont("Courier New", 10))
disassemblyScreenLayout.addWidget(assemblyColumn)

startLayout = QVBoxLayout()
startScreen.setLayout(startLayout)

openFileButton = QPushButton(clicked=chooseFile)
openFileButton.setText("Open a RISC-V file")
openFileButton.setFixedSize(140, 40)
openFileButton.show()

startLayout.addWidget(openFileButton, alignment=QtCore.Qt.AlignmentFlag.AlignCenter)

app.exec()
