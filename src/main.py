from PySide6.QtWidgets import (
    QApplication,
    QWidget,
    QPushButton,
    QFileDialog,
    QVBoxLayout,
    QMessageBox,
)

import PySide6.QtCore as QtCore


class ExecutableSegmentNotFound(Exception):
    pass


def findInstructionsRange(fileBytes):
    # Use segment header table to locate executable segment
    SEGMENT_HEADER_TABLE = 0x40
    SEGMENT_HEADER_SIZE = 0x38

    numSegments = int.from_bytes(fileBytes[0x38:0x3A], "little")

    instructions_segment = None

    for header in range(
        SEGMENT_HEADER_TABLE, SEGMENT_HEADER_TABLE + numSegments * SEGMENT_HEADER_SIZE, SEGMENT_HEADER_SIZE
    ):
        segmentFlags = int.from_bytes(fileBytes[header + 4 : header + 8], "little")

        # The LSB signifies whether a segment is executable or not
        if segmentFlags & 1 == 1:
            # our heuristic is that the first segment whose memory is executable
            # is the one which all instructions are under
            instructions_segment = 1337

    if instructions_segment == None:
        raise ExecutableSegmentNotFound

    return range()  # TODO: complete this


def chooseFile():
    filePath = QFileDialog.getOpenFileName()[0]

    if filePath == "":
        # the user pressed the cancel button on the file dialog
        return

    fileBytes = open(filePath, "rb").read()

    # all ELF files start with the bytes 7f 45 4c 46
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

    try:
        findInstructionsRange(fileBytes)
    except ExecutableSegmentNotFound:
        QMessageBox.warning(
            window,
            "Disassembler",
            f"Open an executable file. Object files aren't supported",
        )

        return


app = QApplication()
window = QWidget()  # widgets with no parents specified create their own window
window.setWindowTitle("Disassembler")
window.show()

layout = QVBoxLayout()
window.setLayout(layout)

openFileButton = QPushButton(clicked=chooseFile)
openFileButton.setText("Open a RISC-V file")
openFileButton.setFixedSize(140, 40)
openFileButton.show()

layout.addWidget(openFileButton, alignment=QtCore.Qt.AlignmentFlag.AlignCenter)

app.exec()
