Dynamic program analysis for fun & profit
=========================================

- In this video tutorial, Dmitry made a comparison between static code analysis tools & dynamic code analysis tools.
- Static code analysis uses the source code to identify properties that are true for all possible execution of the program. Dynamic analysis on the other hand captures properties of a running program.
- Lets take a simple example to explain this. I'll use `cppcheck` static code analysis tool to demonstrate the difference.

```
#include <stdio.h>
#include <stdlib.h>

int main() {
    char *ptr = malloc(10 * sizeof(char));
    ptr[20] = 'a';
    printf("%c\n", ptr[20]);
    free(ptr);
    return 0;
}
```

- if we run `cppcheck static_code_analysis.c`, we get following output:

```
Checking static_code_analysis.c ...
static_code_analysis.c:6:8: error: Array 'ptr[10]' accessed at index 20, which is out of bounds. [arrayIndexOutOfBounds]
    ptr[20] = 'a';
       ^
static_code_analysis.c:7:23: error: Array 'ptr[10]' accessed at index 20, which is out of bounds. [arrayIndexOutOfBounds]
    printf("%c\n", ptr[20]);
                      ^
```

- So, `cppcheck` catches this bug. Now, lets check another program.

```
#include <iostream>
#include <stdlib.h>
#include <string>

void simple_func(int idx) {
    std::cout << idx << std::endl;
    char *ptr = static_cast<char*>(malloc(10 * sizeof(char)));
    ptr[idx] = 'a';
    free(ptr);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return -1;
    }
    
    simple_func(std::stoi(argv[1]));
    return 0;
}
```

- On running `cppcheck dynamic_code_analysis.cpp`, it produces no output.

```
Checking dynamic_code_analysis.cpp ...
```
but, `./a.out 20` will cause `out-of-bounds` error or may modify an unknown address.

- So, that is why tools like `KASAN` are used for dynamic code analysis of the Linux Kernel. One big advantage of these tools is these tools `never show any false positives`.

- The full list of `CONFIG_*` options to enable these tools while building the Linux Kernel is available [here]().

- There are several useful macros provided by the Linux kernel like `BUG_ON`, `WARN_ON` etc. which can be used as assert statements in kernel modules. Here is an example:

```
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

static noinline void createStaticCheckError(void) {
    char *ptr = kmalloc(10 * sizeof(char), GFP_KERNEL);
    BUG_ON(20 > 10 * sizeof(char));
}

static int __init testChecksInit(void) {
    pr_info("static vs dynamic analysis module");
    createStaticCheckError();
    return 0;
}

module_init(testChecksInit);
MODULE_LICENSE("GPL");
```

- this on `insmod` throws an error
```
[ 4781.878639] ------------[ cut here ]------------
[ 4781.878641] kernel BUG at /home/sbcd90/Documents/programs/dynamic-code-analysis-kasan/dynamic_analysis.c:8!
[ 4781.878649] invalid opcode: 0000 [#1] PREEMPT SMP KASAN PTI
[ 4781.878657] CPU: 0 PID: 4603 Comm: insmod Tainted: G    B      OE     5.17.0-rc7-master-00060-g92f90cc9fe0e #2 53babe967a2e4dfa0f2321fbcd210d7c803628fd
[ 4781.878664] Hardware name: innotek GmbH VirtualBox/VirtualBox, BIOS VirtualBox 12/01/2006
[ 4781.878668] RIP: 0010:createStaticCheckError+0x41/0x50 [dynamic_analysis]
[ 4781.878676] Code: e2 2a 80 3c 10 00 74 0c 48 c7 c7 60 5e 20 ba e8 a5 da d1 f6 48 8b 3d 2e 2e 6e f9 ba 0a 00 00 00 be c0 0c 00 00 e8 df 85 d1 f6 <0f> 0b 00 00 00 00 00 00 00 00 00 00 00 00 00 be 04 00 00 00 48 c7
[ 4781.878681] RSP: 0018:ffffc900054578b8 EFLAGS: 00010286
[ 4781.878686] RAX: ffff888102d09ca0 RBX: 0000000000000000 RCX: ffff8881d01e2b60
[ 4781.878690] RDX: 0000000000000000 RSI: 0000000000000246 RDI: ffffffffbbb0ebac
[ 4781.878693] RBP: 1ffff92000a8af19 R08: 0000000000000000 R09: 0000000000000000
[ 4781.878696] R10: 00000000800000f2 R11: 0000000000000001 R12: ffffffffc0b28000
[ 4781.878700] R13: ffff888102d09780 R14: 0000000000000001 R15: ffffffffc0b25140
[ 4781.878703] FS:  00007f49d84b3b80(0000) GS:ffff8881d1000000(0000) knlGS:0000000000000000
[ 4781.878707] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[ 4781.878711] CR2: 00007f4b91379cb0 CR3: 0000000110c84001 CR4: 00000000000706f0
[ 4781.878717] Call Trace:
[ 4781.878719]  <TASK>
[ 4781.878722]  testChecksInit+0x1b/0x1000 [dynamic_analysis ad1af2e0d2d1c2e393355da19f3273afb46c41a7]
[ 4781.878729]  do_one_initcall+0x89/0x2e0
[ 4781.878736]  ? trace_event_raw_event_initcall_level+0x190/0x190
[ 4781.878741]  ? kfree+0xb9/0x400
[ 4781.878747]  ? kasan_set_track+0x21/0x30
[ 4781.878752]  ? kasan_unpoison+0x40/0x70
[ 4781.878757]  do_init_module+0x190/0x710
[ 4781.878764]  load_module+0x780e/0x9c60
[ 4781.878772]  ? module_frob_arch_sections+0x20/0x20
[ 4781.878778]  ? bpf_lsm_kernel_read_file+0x10/0x10
[ 4781.878783]  ? security_kernel_post_read_file+0x56/0x90
[ 4781.878789]  ? kernel_read_file+0x286/0x6a0
[ 4781.878796]  ? __do_sys_finit_module+0x11a/0x1c0
[ 4781.878801]  __do_sys_finit_module+0x11a/0x1c0
[ 4781.878805]  ? __ia32_sys_init_module+0xa0/0xa0
[ 4781.878811]  ? do_mmap+0x624/0xe20
[ 4781.878817]  ? randomize_stack_top+0xd0/0xd0
[ 4781.878822]  do_syscall_64+0x5c/0x80
[ 4781.878828]  ? syscall_exit_to_user_mode+0x23/0x40
[ 4781.878832]  ? do_syscall_64+0x69/0x80
[ 4781.878837]  ? syscall_exit_to_user_mode+0x23/0x40
[ 4781.878841]  ? do_syscall_64+0x69/0x80
[ 4781.878845]  ? exc_page_fault+0x5d/0xd0
[ 4781.878849]  entry_SYSCALL_64_after_hwframe+0x44/0xae
[ 4781.878854] RIP: 0033:0x7f49d85cca9d
[ 4781.878858] Code: 5b 41 5c c3 66 0f 1f 84 00 00 00 00 00 f3 0f 1e fa 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 8b 0d cb e2 0e 00 f7 d8 64 89 01 48
[ 4781.878863] RSP: 002b:00007ffe6ab28318 EFLAGS: 00000246 ORIG_RAX: 0000000000000139
[ 4781.878868] RAX: ffffffffffffffda RBX: 00005588bf0b1760 RCX: 00007f49d85cca9d
[ 4781.878872] RDX: 0000000000000000 RSI: 00005588bd3b3a2a RDI: 0000000000000003
[ 4781.878875] RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
[ 4781.878878] R10: 0000000000000003 R11: 0000000000000246 R12: 00005588bd3b3a2a
[ 4781.878881] R13: 00005588bf0b1700 R14: 00005588bd3b2618 R15: 00005588bf0b1880
[ 4781.878886]  </TASK>
[ 4781.878888] Modules linked in: dynamic_analysis(OE+) snd_seq_dummy snd_hrtimer snd_seq snd_seq_device vmwgfx intel_rapl_msr intel_rapl_common snd_intel8x0 intel_powerclamp snd_ac97_codec crct10dif_pclmul crc32_pclmul ghash_clmulni_intel ac97_bus aesni_intel snd_pcm crypto_simd cryptd rapl snd_timer psmouse rfkill snd drm_ttm_helper e1000 ttm vfat fat joydev lzo_rle intel_agp mousedev vboxguest pcspkr i2c_piix4 intel_gtt soundcore video mac_hid fuse zram bpf_preload ip_tables x_tables ext4 crc32c_generic crc16 mbcache jbd2 sr_mod serio_raw cdrom atkbd libps2 ata_generic i8042 pata_acpi crc32c_intel usbhid ata_piix serio
[ 4781.878967] ---[ end trace 0000000000000000 ]---
[ 4781.878970] RIP: 0010:createStaticCheckError+0x41/0x50 [dynamic_analysis]
[ 4781.878976] Code: e2 2a 80 3c 10 00 74 0c 48 c7 c7 60 5e 20 ba e8 a5 da d1 f6 48 8b 3d 2e 2e 6e f9 ba 0a 00 00 00 be c0 0c 00 00 e8 df 85 d1 f6 <0f> 0b 00 00 00 00 00 00 00 00 00 00 00 00 00 be 04 00 00 00 48 c7
[ 4781.878981] RSP: 0018:ffffc900054578b8 EFLAGS: 00010286
[ 4781.878985] RAX: ffff888102d09ca0 RBX: 0000000000000000 RCX: ffff8881d01e2b60
[ 4781.878988] RDX: 0000000000000000 RSI: 0000000000000246 RDI: ffffffffbbb0ebac
[ 4781.878991] RBP: 1ffff92000a8af19 R08: 0000000000000000 R09: 0000000000000000
[ 4781.878995] R10: 00000000800000f2 R11: 0000000000000001 R12: ffffffffc0b28000
[ 4781.878998] R13: ffff888102d09780 R14: 0000000000000001 R15: ffffffffc0b25140
[ 4781.879001] FS:  00007f49d84b3b80(0000) GS:ffff8881d1000000(0000) knlGS:0000000000000000
[ 4781.879005] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[ 4781.879008] CR2: 00007f4b91379cb0 CR3: 0000000110c84001 CR4: 00000000000706f0
[ 4781.887227] audit: type=1106 audit(1647482912.122:122): 
```