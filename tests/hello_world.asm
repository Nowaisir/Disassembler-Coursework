.text
.global _start # create a symbol here so the linker can find it
_start:
    mv a2, zero
    counting_loop_start:
        la t0, msg
        add t0, t0, a2 # address of character to verify

        lb t0, (t0) # character to verify

        beqz t0, counting_loop_end

        addi a2, a2, 1
        j counting_loop_start

    counting_loop_end:
    # the offset from `msg` to the null byte = how many non null bytes there are in the string

    # write(int fd = STDOUT_FILENO <1>, void *buf = msg, count=len(msg))
    li a7, 64
    li a0, 1
    la a1, msg
    # a2 = length of message

    # extra instructions for testing
    xori a2, a2, -1 # xori is sign extended so all the register's bits are flipped
    xori a2, a2, -1 # making this a NOT operation basically

    andi a2, a2, 0xFF # arbitary length cap to 255 characters

    ecall

    li a7, 93 # exit syscall code, find using `find /opt/riscv/ -name "unistd.h"`
    li a0, -42 # exit code

    slli a0, a0, 7
    srai a0, a0, 7 # so that the higher bits are 1s preserving the negative exit code

    ecall

.data # tack on data to the .data section
    msg: .string "Hello, world!\n"
