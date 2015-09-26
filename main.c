/* 
 * Credits:
 *  libdasm (library for disassembling x86 binaries): http://github.com/google-code-export/libdasm
 *  libelf  (library for analyzing ELF binaries    ): http://wiki.freebsd.org/LibElf
 * 
 * get_main was inspired by code given at http://ufeox.googlecode.com/svn/trunk/Tools/libelf-howto.c
 * main was inspired by code given at http://www.alexonlinux.com/how-debugger-works
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <ncurses.h>
#include <libelf/libelf.h>
#include <libelf/gelf.h>

#include "libdasm/libdasm.h"

#define INT3 0xCC
#define NTHBIT(n, b) ((((unsigned int) (n)) >> ((b))) & 1)
#define PRINTABLE(c) ((0x20 <= (c) && (c) <= 0x7e) ? (c) : '.')

// Type to store a word
typedef size_t word_t;

/* read_text: reads num words at address addr in inferior process with pid,
 * and write the data into out */
void read_text(word_t* out, pid_t pid, uintptr_t addr, size_t num) {
    size_t i;
    for (i = 0; i < num; i++) {
        out[i] = ptrace(PTRACE_PEEKTEXT, pid, (word_t *) addr + i, NULL);
    }
}

/* get_register: converts libdasm register constant to register value */
word_t get_register(struct user_regs_struct* regs, size_t register_num) {
    switch (register_num) {
        case REGISTER_EAX:
            return regs->eax;
        case REGISTER_EBX:
            return regs->ebx;
        case REGISTER_ECX:
            return regs->ecx;
        case REGISTER_EDX:
            return regs->edx;
        case REGISTER_ESP:
            return regs->esp;
        case REGISTER_EBP:
            return regs->ebp;
        case REGISTER_ESI:
            return regs->esi;
        case REGISTER_EDI:
            return regs->edi;
    }
    return 0;
}

/* get_value: Get value of operand, which can be a register, immediate, or memory location */
word_t get_value(pid_t pid, OPERAND op) {
    if (op.type == OPERAND_TYPE_MEMORY) {
        uintptr_t addr;
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        addr = get_register(&regs, op.basereg) + op.scale * get_register(&regs, op.indexreg) + op.displacement;
        return ptrace(PTRACE_PEEKTEXT, pid, (void *) addr, NULL);
    } else if (op.type == OPERAND_TYPE_REGISTER) {
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        return get_register(&regs, op.reg);
    } else if (op.type == OPERAND_TYPE_IMMEDIATE) {
        return op.immediate;
    }
    return 0;
}

/* get_inst: Read an instruction at addr */
void get_inst(INSTRUCTION *inst, pid_t pid, uintptr_t addr) {
    // x86 instructions are guaranteed to fit in 15 bytes < 4 words
    word_t raw_inst[4];
    read_text(raw_inst, pid, addr, 4);
    get_instruction(inst, (void *) raw_inst, MODE_32);
}

/* create_newwin: create new curses window and draws box */
WINDOW *create_newwin(int height, int width, int starty, int startx) {
    WINDOW *win;
    win = newwin(height, width, starty, startx);
    box(win, 0, 0);
    wrefresh(win);
    return win;
}

/* print_info: prints information about current instruction in the info window */
void print_info(WINDOW* win, pid_t pid, struct user_regs_struct* regs) {
    wclear(win);
    box(win, 0, 0);
    mvwprintw(win, 0, 0, "Info");
    INSTRUCTION inst;
    get_inst(&inst, pid, regs->eip);

    char buffer[128];
    get_instruction_string(&inst, FORMAT_ATT, 0, buffer, 127);

    mvwprintw(win, 1, 0, "Current instruction: %s", buffer);
    if (inst.op2.type != OPERAND_TYPE_NONE) 
        mvwprintw(win, 2, 0, "Op 1 = %x, Op 2 = %x", get_value(pid, inst.op2), get_value(pid, inst.op1));
    else if (inst.op1.type != OPERAND_TYPE_NONE) 
        mvwprintw(win, 2, 0, "Op 1 = %x", get_value(pid, inst.op1));

    /* Print documentation for all the jump instructions */
    switch (inst.opcode) {
        case 0x70:
            mvwprintw(win, 3, 0, "jo: jump if overflow (OF = 1)");
            break;
        case 0x71:
            mvwprintw(win, 3, 0, "jno: jump if not overflow (OF = 0)");
            break;
        case 0x78:
            mvwprintw(win, 3, 0, "js: jump if sign (SF = 1)");
            break;
        case 0x79:
            mvwprintw(win, 3, 0, "jns: jump if not sign (SF = 0)");
            break;
        case 0x74:
            mvwprintw(win, 3, 0, "je: jump if equal (ZF = 1)");
            break;
        case 0x75:
            mvwprintw(win, 3, 0, "jne: jump if not equal (ZF = 0)");
            break;
        case 0x72:
            mvwprintw(win, 3, 0, "jb: jump if below (CF = 1)");
            break;
        case 0x73:
            mvwprintw(win, 3, 0, "jnb: jump if not below (CF = 0)");
            break;
        case 0x76:
            mvwprintw(win, 3, 0, "jbe: jump if below or equal (CF = 1 or ZF = 1)");
            break;
        case 0x77:
            mvwprintw(win, 3, 0, "ja: jump if above (CF = 0 and ZF = 0)");
            break;
        case 0x7c:
            mvwprintw(win, 3, 0, "jl: jump if less (SF != OF)");
            break;
        case 0x7d:
            mvwprintw(win, 3, 0, "jge: jump if greater or equal (SF = OF)");
            break;
        case 0x7e:
            mvwprintw(win, 3, 0, "jle: jump if less or equal (ZF = 1 or SF != OF)");
            break;
        case 0x7f:
            mvwprintw(win, 3, 0, "jg: jump if greater (ZF = 0 and SF = OF)");
            break;
        case 0x7a:
            mvwprintw(win, 3, 0, "jp: jump if parity (PF = 1)");
            break;
        case 0x7b:
            mvwprintw(win, 3, 0, "jnp: jump if not parity (PF = 0)");
            break;
        case 0xe3:
            mvwprintw(win, 3, 0, "jcxz: jump if %%cx=0");
            break;
    }

    wrefresh(win);
}

/* print_code: print the assembly code in the code window
 * We maintain a buffer of assembly code so that the code wouldn't continually scroll */
INSTRUCTION *insts = NULL;
void print_code(WINDOW* win, pid_t pid, struct user_regs_struct* regs) {
    static uintptr_t lowest_addr = 0;
    static uintptr_t highest_addr = 0;
    size_t count = 0;
    size_t y, x;
    uintptr_t addr = regs->eip;

    getmaxyx(win, y, x);
    if (!insts) insts = malloc(sizeof(INSTRUCTION) * (y-2));

    wclear(win);
    box(win, 0, 0);
    mvwprintw(win, count, 0, "Code");
    count++;

    // If current instruction is not in the buffer, we refresh the buffer
    if (regs->eip+4 > highest_addr || lowest_addr > regs->eip) {
        lowest_addr = regs->eip;
        addr = regs->eip;
        for (count = 0; count < y-2; count++) {
            get_inst(insts + count, pid, addr);
            if (insts[count].length == 0) break;
            addr += insts[count].length;
        }
        highest_addr = addr;
    }

    addr = lowest_addr;
    count = 0;
    while (addr < highest_addr) {
        char buffer[128];
        get_instruction_string(insts + count, FORMAT_ATT, 0, buffer, 127);
        if (addr == regs->eip) {
            attron(A_STANDOUT | A_UNDERLINE);
            mvwprintw(win, 1 + count, 0, "eip->| %x: %s", addr, buffer);
        } else{
            mvwprintw(win, 1 + count, 0, "     | %x: %s", addr, buffer);
        }
        addr += insts[count].length;
        count++;
    }

    wrefresh(win);
}

/* print_registers: print register info in the register window */
void print_registers(WINDOW* win, pid_t pid, struct user_regs_struct* regs) {
    size_t y, x;
    getmaxyx(win, y, x);
    wclear(win);
    box(win, 0, 0);
    mvwprintw(win, 0, x / 2 - 4, "Registers");
    mvwprintw(win, 1, 0, "eip: %08x  esp: %08x  ebp: %08x", regs->eip, regs->esp, regs->ebp);
    mvwprintw(win, 2, 0, "eax: %08x  ebx: %08x  ecx: %08x  edx: %08x  esi: %08x  edi: %08x",
            regs->eax, regs->ebx, regs->ecx, regs->edx, regs->esi, regs->edi);

    // Print all the special flags
    mvwprintw(win, 3, 0, "flags: %x (carry=%d, parity=%d, adjust=%d, zero=%d, sign=%d,"
            " trap=%d, interrupt=%d, direction=%d, overflow=%d)",
            regs->eflags, NTHBIT(regs->eflags, 0), NTHBIT(regs->eflags, 2),
            NTHBIT(regs->eflags, 4), NTHBIT(regs->eflags, 6), NTHBIT(regs->eflags, 7),
            NTHBIT(regs->eflags, 8), NTHBIT(regs->eflags, 9), NTHBIT(regs->eflags, 10),
            NTHBIT(regs->eflags, 11));
    wrefresh(win);
}

/* print_stack: print the stack, which is shown growing downwards.
 * We display the memory addresses, the offsets from %esp and %ebp,
 * and the stack contents as integers and characters */
void print_stack(WINDOW* win, pid_t pid, struct user_regs_struct* regs) {
    int i;
    size_t x, stack_len;

    getmaxyx(win, stack_len, x);
    stack_len -= 1;

    word_t* stack = malloc(sizeof(word_t) * stack_len);
    read_text(stack, pid, regs->esp, stack_len);

    wclear(win);
    box(win, 0, 0);
    mvwprintw(win, 0, 0, "Stack");
    for (i = stack_len - 1; i >= 0; i--) {
        int line_no = stack_len - i;
        int esp_offset = 4*i;
        int ebp_offset = regs->esp + 4*i - regs->ebp;

        if (i == 0) {
            mvwprintw(win, line_no, 0, "esp->");
        }
        if (regs->esp + 4*i == regs->ebp) {
            mvwprintw(win, line_no, 5, "ebp->");
        }

        if (ebp_offset >= 0) {
            mvwprintw(win, line_no, 10, "| %08x (%x(%%esp), %x(%%ebp))",
                    regs->esp + 4*i, esp_offset, ebp_offset);
        } else {
            mvwprintw(win, line_no, 10, "| %08x (%x(%%esp), -%x(%%ebp))",
                    regs->esp + 4*i, esp_offset, -ebp_offset);
        }
        char * arr = (char *) (stack + i);
        mvwprintw(win, line_no, x - 18, "0x%08x | %c%c%c%c", stack[i],
                PRINTABLE(arr[0]), PRINTABLE(arr[1]),
                PRINTABLE(arr[2]), PRINTABLE(arr[3]));
    }
    wrefresh(win);
    free(stack);
}

/* get_main: Grab the address of the main function in TEXT */
uintptr_t get_main(char *fname) {
    Elf *elf;
    Elf_Scn *scn=NULL;
    Elf_Data *edata=NULL;
    GElf_Sym sym;
    GElf_Shdr shdr;
    struct stat elf_stats;

    int fd = open(fname, O_RDONLY);
    fstat(fd, &elf_stats);

    elf_version(EV_CURRENT);
    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        printf("%s\n", elf_errmsg(elf_errno()));
        return 0;
    }

    // Look through the sections to find the symbol table
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        gelf_getshdr(scn, &shdr);
        if (shdr.sh_type == SHT_SYMTAB) {
            edata = elf_getdata(scn, edata);
            int symbol_count = shdr.sh_size / shdr.sh_entsize;
            int i = 0;
            // Go through the symbols to find main
            for (i = 0; i < symbol_count; i++) {
                gelf_getsym(edata, i, &sym);
                if (ELF32_ST_TYPE(sym.st_info) == STT_FUNC) {
                    char * str =elf_strptr(elf, shdr.sh_link, sym.st_name);
                    if (strcmp(str, "main") == 0) {
                        close(fd);
                        return sym.st_value;
                    }
                }
            }
        }
    }

    close(fd);
    return 0;
}

int main(int argc, char ** argv) {
    int status;
    INSTRUCTION current_instruction;
    word_t restore;

    if (argc < 2) {
        printf("Usage: %s program\n", argv[0]);
        return 1;
    }

    // Find the address of main in the text section
    uintptr_t addr = get_main(argv[1]);

    pid_t pid = fork();
    if (pid < 0) {
        perror("Error forking child process");
        return 1;
    } else if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execv(argv[1], argv+2);
        // Should not fail
        perror(NULL);
    } else {
        int ch;

        if (ptrace(PTRACE_ATTACH, pid, 0, 0)) {
            perror("Error attaching to child process");
            return 1;
        }

        // Initialize curses
        initscr(); raw(); noecho();

        WINDOW *win_regs = create_newwin(4, COLS, 0, 0);
        WINDOW *win_code = create_newwin(LINES - 8, COLS/2-12, 4, 0);
        WINDOW *win_stack = create_newwin(LINES - 8, COLS/2+12, 4, COLS/2-12);
        WINDOW *win_info = create_newwin(LINES - 4, COLS, LINES - 4, 0);

        // Wait for child to acknowledge trace
        pid = waitpid(pid, &status, 0);

        // Now, continue until execv
        ptrace(PTRACE_CONT, pid, NULL, NULL);
        pid = waitpid(pid, &status, 0);

        // Set breakpoint at main
        word_t raw_inst[4];
        read_text(raw_inst, pid, addr, 4);
        restore = raw_inst[0];
        get_instruction(&current_instruction, (void *) raw_inst, MODE_32);

        ptrace(PTRACE_POKETEXT, pid, (void *) addr, (restore & ~0xff) | INT3);

        // Run child until break point
        ptrace(PTRACE_CONT, pid, NULL, NULL);

        // On the first run, we replace breakpoint with correct instruction
        int first = 1;
        do {
            pid = waitpid(pid, &status, 0);

            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, pid, NULL, &regs);

            if (first) {
                first = 0;

                // We need to run addr again because last time it was just an int 3
                regs.eip = addr;

                // Restore instruction at break point
                ptrace(PTRACE_POKETEXT, pid, (void *) addr, restore);
                ptrace(PTRACE_SETREGS, pid, NULL, &regs);
                ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
                continue;
            }

            print_code(win_code, pid, &regs);
            print_registers(win_regs, pid,  &regs);
            print_stack(win_stack, pid, &regs);
            print_info(win_info, pid, &regs);

            ch = wgetch(win_stack);
            if (ch == 'q') break;

            ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
        } while (!WIFEXITED(status));

        if (!WIFEXITED(status)) {
            // Kill child process
            ptrace(PTRACE_KILL, pid, NULL, NULL);
        }
        endwin();
    }
}
