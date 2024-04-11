all: tests/exit tests/hello_world

# on one of my systems, riscv64-linux-gnu-as is installed
# and on the other, riscv64-unknown-linux-gnu-as
TOOLCHAIN_PREFIX := $(if $(wildcard /bin/riscv64-linux-gnu*), \
	/bin/riscv64-linux-gnu, \
	/opt/riscv/bin/riscv64-unknown-linux-gnu-)

GCC := $(TOOLCHAIN_PREFIX)gcc
GNU_AS := $(TOOLCHAIN_PREFIX)as

tests/exit:  tests/artifacts/ tests/exit.asm
	$(GNU_AS) tests/exit.asm -o tests/artifacts/exit.o
	$(GCC) tests/artifacts/exit.o -o tests/exit -static -nostdlib

tests/hello_world: tests/artifacts tests/hello_world.asm
	$(GNU_AS) tests/hello_world.asm -o tests/artifacts/hello_world.o
	$(GCC) tests/artifacts/hello_world.o -o tests/hello_world -static -nostdlib

# artifacts store object files that may clutter our options when we tab complete
# for a binary to execute through the terminal.
tests/artifacts/:
	mkdir tests/artifacts

.PHONY: clean
clean:
	rm -rf tests/artifacts
	rm -rf tests/exit
