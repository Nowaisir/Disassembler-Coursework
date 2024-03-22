all: tests/exit

GCC := riscv64-unknown-linux-gnu-gcc
GNU_AS := riscv64-unknown-linux-gnu-as

tests/exit:  tests/artifacts/ tests/exit.asm
	$(GNU_AS) tests/exit.asm -o tests/artifacts/exit.o
	$(GCC) tests/artifacts/exit.o -o tests/exit -static -nostdlib


# artifacts store object files that may clutter our options when we tab complete
# for a binary to execute through the terminal.
tests/artifacts/:
	mkdir tests/artifacts

.PHONY: clean
clean:
	rm -rf tests/artifacts
	rm -rf tests/exit