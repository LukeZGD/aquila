#include "common.h"
#include "util.h"
#include "oob_entry.h"
#include "memory.h"
#include "patchfinder.h"
#include "patches.h"

static void *kernel_data = NULL;
static size_t kernel_data_size = 0xffe000;

uint32_t find_patch_offset(uint32_t (*func)(uint32_t, uint8_t *, size_t)) {
    uint32_t addr = func(kinfo->kernel_base, kernel_data, kernel_data_size);
    if (addr <= 0xffff) return 0;
    return addr + kinfo->kernel_base;
}

void set_bootargs(patches_t *patches, const char *bootargs) {
    size_t args_size = strlen(bootargs) + 1;
    size_t buf_size = (args_size + 3) / 4 * 4;
    
    char *buf = calloc(1, buf_size);
    strlcpy(buf, bootargs, buf_size);
    memset(buf + args_size, 0, buf_size - args_size);
    
    uint32_t str_addr = kread32(patches->p_bootargs) + 0x38;
    kwrite_buf(str_addr, buf, args_size);
    free(buf);
    usleep(10000);
}

int patch_kernel(void) {
    patches_t *patches = calloc(1, sizeof(patches_t));
    kernel_data = calloc(1, kernel_data_size);
    kread_buf(kinfo->kernel_base, kernel_data, kernel_data_size);
    int rv = -1;

    if ((patches->pmap_location = find_patch_offset(find_pmap_location)) == 0) goto done;
    if ((patches->proc_enforce = find_patch_offset(find_proc_enforce)) == 0) goto done;
    if ((patches->cs_enforcement_disable_amfi = find_patch_offset(find_cs_enforcement_disable_amfi)) == 0) goto done;
    if ((patches->cs_enforcement_disable_kernel = find_patch_offset(find_cs_enforcement_disable_kernel)) == 0) goto done;
    if ((patches->i_can_has_debugger_1 = find_patch_offset(find_i_can_has_debugger_1)) == 0) goto done;
    if ((patches->i_can_has_debugger_2 = find_patch_offset(find_i_can_has_debugger_2)) == 0) goto done;
    if ((patches->vm_map_enter_patch = find_patch_offset(find_vm_map_enter_patch)) == 0) goto done;
    if ((patches->vm_map_protect_patch = find_patch_offset(find_vm_map_protect_patch)) == 0) goto done;
    if ((patches->tfp0_patch = find_patch_offset(find_tfp0_patch)) == 0) goto done;
    if ((patches->sb_patch = find_patch_offset(find_sb_patch)) == 0) goto done;
    if ((patches->vn_getpath = find_patch_offset(find_vn_getpath)) == 0) goto done;
    if ((patches->memcmp = find_patch_offset(find_memcmp)) == 0) goto done;
    if ((patches->p_bootargs = find_patch_offset(find_p_bootargs)) == 0) goto done;

    uint32_t kernel_pmap_store = kread32(patches->pmap_location);
    patches->tte_virt = kread32(kernel_pmap_store);
    patches->tte_phys = kread32(kernel_pmap_store + 4);
    patches->l1_table_entries = kread32(kernel_pmap_store + 0x54);
    patches->kern_phys_base =  patches->tte_phys - (patches->tte_virt - kinfo->kernel_base);
    patches->l1_page_table = calloc(1, patches->l1_table_entries * 4);

    kwrite8(patches->proc_enforce, 0);
    kwrite8(patches->cs_enforcement_disable_amfi, 1);
    kwrite8(patches->cs_enforcement_disable_kernel, 1);
    kwrite8(patches->i_can_has_debugger_1, 1);
    kwrite8(patches->i_can_has_debugger_2, 1);

    kwrite16_exec(patches->vm_map_enter_patch, 0xbf00);
    kwrite16_exec(patches->vm_map_protect_patch, 0xe005);
    kwrite16_exec(patches->tfp0_patch, 0xe006);
    set_bootargs(patches, "cs_enforcement_disable=1");

    uint8_t *sb_eval_trampoline_addr = (uint8_t *)(((uint32_t)&sb_eval_trampoline) & ~1);
    uint8_t *sb_eval_hook_addr = (uint8_t *)(((uint32_t)&sb_eval_hook) & ~1);
    uint8_t *trampoline = calloc(1, sb_eval_trampoline_len);
    
    memcpy(trampoline, sb_eval_trampoline_addr, sb_eval_trampoline_len);
    uint32_t trampoline_offset = (int32_t)&sb_eval_trampoline_hook_addr - (int32_t)sb_eval_trampoline_addr;
    *(uint32_t*)(trampoline + trampoline_offset) = kinfo->kernel_base + 0x701;
    uint8_t *overwritten_inst = malloc(sb_eval_trampoline_len + 4);
    kread_buf(patches->sb_patch, overwritten_inst, sb_eval_trampoline_len + 4);

    if (memcmp(overwritten_inst, trampoline, sb_eval_trampoline_len) != 0) {
        uint32_t overwritten_inst_size = 0;
        uint16_t *current_inst = (uint16_t *)overwritten_inst;
        
        while (((int32_t)current_inst - (int32_t)overwritten_inst) < sb_eval_trampoline_len) {
            if((*current_inst & 0xe000) == 0xe000 && (*current_inst & 0x1800) != 0x0) {
                overwritten_inst_size += 4;
                current_inst += 2;
            } else {
                overwritten_inst_size += 2;
                current_inst += 1;
            }
        }
        
        uint16_t bx_r9 = 0x4748;
        uint32_t hook_size = ((sb_eval_hook_len + overwritten_inst_size + sizeof(bx_r9) + 3) / 4) * 4;
        uint8_t *hook_data = calloc(1, hook_size);
        
        memcpy(hook_data, sb_eval_hook_addr, sb_eval_hook_len);
        memcpy(hook_data + sb_eval_hook_len, overwritten_inst, overwritten_inst_size);
        memcpy(hook_data + sb_eval_hook_len + overwritten_inst_size, &bx_r9, sizeof(bx_r9));

        *((uint32_t*)(hook_data + ((int32_t)&sb_eval_hook_orig_addr - (int32_t)sb_eval_hook_addr))) = patches->sb_patch + overwritten_inst_size + 1;
        *((uint32_t*)(hook_data + ((int32_t)&sb_eval_hook_vn_getpath - (int32_t)sb_eval_hook_addr))) = patches->vn_getpath;
        *((uint32_t*)(hook_data + ((int32_t)&sb_eval_hook_memcmp - (int32_t)sb_eval_hook_addr))) = patches->memcmp;

        kwrite_buf_exec((kinfo->kernel_base + 0x700), hook_data, hook_size);
        kwrite_buf_exec(patches->sb_patch, trampoline, sb_eval_trampoline_len);
        free(hook_data);
    }
    
    usleep(100000);
    free(overwritten_inst);
    free(trampoline);
    rv = 0;

done:
    if (patches != NULL) free(patches);
    if (kernel_data != NULL) free(kernel_data);
    return rv;
}
