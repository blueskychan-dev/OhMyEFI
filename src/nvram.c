#include "nvram.h"
#include "hwinfo.h"
#include "ui.h"
#include "util.h"

SETUP_LIVE_STATE gSetup;
UINTN            gVarCount = 0;
NVRAM_VAR_ENTRY *gVarList  = NULL;

UINT32 nvram_hash_password(const CHAR8 *pw) {
    UINT32 h = 0x811C9DC5U;
    if (!pw) return 0;
    while (*pw) {
        h ^= (UINT8)*pw++;
        h *= 0x01000193U;
    }
    return h;
}

EFI_STATUS nvram_read_var(const CHAR16 *name_w, EFI_GUID *guid, UINT32 *attrs_out, UINTN *size_out, UINT8 **data_out) {
    if (!gRT || !gRT->GetVariable || !name_w || !guid) return EFI_INVALID_PARAMETER;
    UINTN sz = 0;
    UINT32 attr = 0;
    EFI_STATUS st = gRT->GetVariable((CHAR16 *)name_w, guid, &attr, &sz, NULL);
    if (st != EFI_BUFFER_TOO_SMALL) {
        if (attrs_out) *attrs_out = attr;
        if (size_out) *size_out = 0;
        if (data_out) *data_out = NULL;
        return st;
    }
    UINT8 *buf = (UINT8 *)alloc_zero_pool(sz + 2);
    if (!buf) return EFI_OUT_OF_RESOURCES;

    st = gRT->GetVariable((CHAR16 *)name_w, guid, &attr, &sz, buf);
    if (EFI_ERROR(st)) {
        free_pool(buf);
        return st;
    }
    if (attrs_out) *attrs_out = attr;
    if (size_out)  *size_out  = sz;
    if (data_out)  *data_out  = buf;
    else           free_pool(buf);
    return EFI_SUCCESS;
}

EFI_STATUS nvram_write_var(const CHAR16 *name_w, EFI_GUID *guid, UINT32 attrs, UINTN size, const VOID *data) {
    if (!gRT || !gRT->SetVariable || !name_w || !guid) return EFI_INVALID_PARAMETER;
    return gRT->SetVariable((CHAR16 *)name_w, guid, attrs, size, (VOID *)data);
}

EFI_STATUS nvram_delete_var(const CHAR16 *name_w, EFI_GUID *guid) {
    if (!gRT || !gRT->SetVariable || !name_w || !guid) return EFI_INVALID_PARAMETER;
    return gRT->SetVariable((CHAR16 *)name_w, guid, 0, 0, NULL);
}

static VOID build_var_preview(NVRAM_VAR_ENTRY *ve, const UINT8 *data, UINTN sz) {
    ve->preview_str[0] = '\0';
    if (!data || sz == 0) {
        str_cpy(ve->preview_str, "<empty>", sizeof(ve->preview_str));
        return;
    }
    UINTN copy_n = (sz < sizeof(ve->preview)) ? sz : sizeof(ve->preview);
    memcpy(ve->preview, data, copy_n);

    BOOLEAN ascii_printable = (sz >= 2);
    UINTN ascii_chars = 0;
    for (UINTN i = 0; i < sz && i < 28; i++) {
        if (data[i] == 0 && i > 0 && i + 1 == sz) break;
        if (data[i] >= 0x20 && data[i] <= 0x7E) {
            ascii_chars++;
        } else {
            ascii_printable = FALSE;
            break;
        }
    }
    if (ascii_printable && ascii_chars >= 2) {
        CHAR8 tmp[30];
        UINTN n = (ascii_chars < 26) ? ascii_chars : 26;
        memcpy(tmp, data, n);
        tmp[n] = '\0';
        snprintf_ascii(ve->preview_str, sizeof(ve->preview_str), "\"%s\"", tmp);
        return;
    }

    if (sz >= 4 && (sz & 1) == 0 && data[1] == 0 && data[0] >= 0x20 && data[0] <= 0x7E) {
        const CHAR16 *ws = (const CHAR16 *)data;
        UINTN wcnt = sz / 2;
        BOOLEAN utf16_ok = TRUE;
        CHAR8 tmp[30];
        UINTN out_i = 0;
        for (UINTN i = 0; i < wcnt && out_i < 24; i++) {
            if (ws[i] == 0 && i + 1 == wcnt) break;
            if (ws[i] >= 0x20 && ws[i] <= 0x7E) {
                tmp[out_i++] = (CHAR8)ws[i];
            } else {
                utf16_ok = FALSE;
                break;
            }
        }
        if (utf16_ok && out_i >= 2) {
            tmp[out_i] = '\0';
            snprintf_ascii(ve->preview_str, sizeof(ve->preview_str), "L\"%s\"", tmp);
            return;
        }
    }

    UINTN pos = 0;
    UINTN show_b = (sz < 8) ? sz : 8;
    for (UINTN i = 0; i < show_b && pos + 4 < sizeof(ve->preview_str); i++) {
        snprintf_ascii(ve->preview_str + pos, sizeof(ve->preview_str) - pos,
                       (i + 1 < show_b) ? "%02X " : "%02X", data[i]);
        pos = str_len(ve->preview_str);
    }
    if (sz > show_b && pos + 4 < sizeof(ve->preview_str)) {
        str_cpy(ve->preview_str + pos, "...", sizeof(ve->preview_str) - pos);
    }
}

VOID nvram_enumerate_all(VOID) {
    if (!gRT || !gRT->GetNextVariableName) return;

    if (!gVarList) {
        gVarList = (NVRAM_VAR_ENTRY *)alloc_zero_pool(sizeof(NVRAM_VAR_ENTRY) * NVRAM_MAX_VARS);
        if (!gVarList) return;
    }
    gVarCount = 0;

    UINTN name_cap = 256 * sizeof(CHAR16);
    CHAR16 *name_buf = (CHAR16 *)alloc_zero_pool(name_cap);
    if (!name_buf) return;

    EFI_GUID cur_guid;
    memset(&cur_guid, 0, sizeof(cur_guid));
    name_buf[0] = 0;

    while (gVarCount < NVRAM_MAX_VARS) {
        UINTN sz = name_cap;
        EFI_STATUS st = gRT->GetNextVariableName(&sz, name_buf, &cur_guid);
        if (st == EFI_BUFFER_TOO_SMALL) {
            UINTN new_cap = sz + 128;
            CHAR16 *nb = (CHAR16 *)alloc_zero_pool(new_cap);
            if (!nb) break;
            memcpy(nb, name_buf, name_cap);
            free_pool(name_buf);
            name_buf = nb;
            name_cap = new_cap;
            sz = name_cap;
            st = gRT->GetNextVariableName(&sz, name_buf, &cur_guid);
        }
        if (EFI_ERROR(st)) {
            break;
        }

        NVRAM_VAR_ENTRY *ve = &gVarList[gVarCount];
        memset(ve, 0, sizeof(*ve));
        wstr_cpy(ve->name_w, name_buf, sizeof(ve->name_w) / sizeof(CHAR16));
        wstr_to_ascii(ve->name, name_buf, sizeof(ve->name));
        ve->guid = cur_guid;

        UINT32 attrs = 0;
        UINTN dsz = 0;
        UINT8 *dbuf = NULL;
        if (!EFI_ERROR(nvram_read_var(name_buf, &cur_guid, &attrs, &dsz, &dbuf))) {
            ve->attributes = attrs;
            ve->data_size  = dsz;
            ve->is_writable_hint =
                ((attrs & (EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS |
                           EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS)) == 0);
            build_var_preview(ve, dbuf, dsz);
            free_pool(dbuf);
        } else {
            str_cpy(ve->preview_str, "<unreadable>", sizeof(ve->preview_str));
        }

        gVarCount++;
    }
    free_pool(name_buf);

    gSetup.storage_info_valid = FALSE;
    if (gRT->Hdr.Revision >= 0x00020000U && gRT->QueryVariableInfo != NULL) {
        UINT64 max_st = 0, rem_st = 0, max_v = 0;
        UINT32 qattr = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;
        if (!EFI_ERROR(gRT->QueryVariableInfo(qattr, &max_st, &rem_st, &max_v))) {
            gSetup.storage_info_valid = TRUE;
            gSetup.max_storage_bytes  = max_st;
            gSetup.rem_storage_bytes  = rem_st;
            gSetup.max_var_bytes      = max_v;
        }
    }
}

static BOOLEAN parse_boot_load_option(UINT16 num, BOOLEAN in_order, BOOT_ENTRY_ITEM *out) {
    CHAR16 bname[16];
    wsnprintf(bname, 16, "Boot%04X", (UINT32)num);
    UINT32 attrs = 0;
    UINTN sz = 0;
    UINT8 *data = NULL;
    if (EFI_ERROR(nvram_read_var(bname, &gEfiGlobalVariableGuid, &attrs, &sz, &data)) || !data) {
        return FALSE;
    }
    if (sz < 8) {
        free_pool(data);
        return FALSE;
    }

    memset(out, 0, sizeof(*out));
    out->boot_num      = num;
    memcpy(&out->attributes, data, 4);
    UINT16 fp_list_len = 0;
    memcpy(&fp_list_len, data + 4, 2);
    out->active        = ((out->attributes & LOAD_OPTION_ACTIVE) != 0);
    out->in_boot_order = in_order;
    out->modified_attr = FALSE;

    const CHAR16 *desc_w = (const CHAR16 *)(data + 6);
    UINTN max_w = (sz - 6) / 2;
    UINTN i = 0;
    while (i < max_w && desc_w[i] != 0) {
        if (i + 1 < sizeof(out->description)) {
            CHAR16 c = desc_w[i];
            out->description[i] = (c >= 0x20 && c <= 0x7E) ? (CHAR8)c : '?';
        }
        i++;
    }
    UINTN desc_end_idx = (i + 1 < sizeof(out->description)) ? i : (sizeof(out->description) - 1);
    out->description[desc_end_idx] = '\0';
    if (!out->description[0]) {
        snprintf_ascii(out->description, sizeof(out->description), "UEFI Boot%04X", (UINT32)num);
    }

    /* Extract Media FilePath (Type 4 SubType 4) if present in FilePathList */
    UINTN dp_off = 6 + (i + 1) * sizeof(CHAR16);
    if (dp_off + 4 <= sz && fp_list_len >= 4) {
        UINTN dp_end = dp_off + fp_list_len;
        if (dp_end > sz) dp_end = sz;
        UINTN cur = dp_off;
        while (cur + 4 <= dp_end) {
            UINT8 ntype = data[cur];
            UINT8 nsub  = data[cur + 1];
            UINT16 nlen = (UINT16)data[cur + 2] | ((UINT16)data[cur + 3] << 8);
            if (nlen < 4 || cur + nlen > dp_end || ntype == 0x7F) break;
            if (ntype == 0x04 && nsub == 0x04 && nlen > 4) {
                CHAR16 wtmp[72];
                UINTN wchars = (nlen - 4) / sizeof(CHAR16);
                if (wchars >= 72) wchars = 71;
                memcpy(wtmp, data + cur + 4, wchars * sizeof(CHAR16));
                wtmp[wchars] = 0;
                wstr_to_ascii(out->file_path_str, wtmp, sizeof(out->file_path_str));
            }
            cur += nlen;
        }
    }

    free_pool(data);
    return TRUE;
}

static VOID load_boot_entries_only(VOID) {
    gSetup.boot_count       = 0;
    gSetup.boot_order_dirty = FALSE;

    UINT8 *buf = NULL;
    UINTN sz = 0;
    if (!EFI_ERROR(nvram_read_var(L"BootCurrent", &gEfiGlobalVariableGuid, NULL, &sz, &buf)) && buf) {
        if (sz >= 2) {
            memcpy(&gSetup.boot_current, buf, 2);
            gSetup.has_boot_current = TRUE;
        }
        free_pool(buf);
    }

    if (!EFI_ERROR(nvram_read_var(L"BootOrder", &gEfiGlobalVariableGuid, NULL, &sz, &buf)) && buf) {
        UINTN cnt = sz / 2;
        const UINT16 *ord = (const UINT16 *)buf;
        for (UINTN i = 0; i < cnt && gSetup.boot_count < NVRAM_MAX_BOOT_ENTRIES; i++) {
            BOOT_ENTRY_ITEM item;
            if (parse_boot_load_option(ord[i], TRUE, &item)) {
                gSetup.boot_entries[gSetup.boot_count++] = item;
            }
        }
        free_pool(buf);
    }

    for (UINTN i = 0; i < gVarCount && gSetup.boot_count < NVRAM_MAX_BOOT_ENTRIES; i++) {
        if (!guid_equal(&gVarList[i].guid, &gEfiGlobalVariableGuid)) continue;
        const CHAR8 *nm = gVarList[i].name;
        if (nm[0] == 'B' && nm[1] == 'o' && nm[2] == 'o' && nm[3] == 't' &&
            nm[4] != '\0' && nm[8] == '\0') {
            UINT64 bnum = 0;
            if (parse_hex_u64(nm + 4, &bnum) && bnum <= 0xFFFFULL) {
                BOOLEAN already = FALSE;
                for (UINTN j = 0; j < gSetup.boot_count; j++) {
                    if (gSetup.boot_entries[j].boot_num == (UINT16)bnum) {
                        already = TRUE;
                        break;
                    }
                }
                if (!already) {
                    BOOT_ENTRY_ITEM item;
                    if (parse_boot_load_option((UINT16)bnum, FALSE, &item)) {
                        gSetup.boot_entries[gSetup.boot_count++] = item;
                    }
                }
            }
        }
    }
}

VOID nvram_reload_boot_entries(VOID) {
    nvram_enumerate_all();
    load_boot_entries_only();
}

static VOID load_boot_variables(VOID) {
    gSetup.boot_timeout     = 3;
    gSetup.has_boot_current = FALSE;
    gSetup.timeout_dirty    = FALSE;

    UINT8 *buf = NULL;
    UINTN sz = 0;
    if (!EFI_ERROR(nvram_read_var(L"Timeout", &gEfiGlobalVariableGuid, NULL, &sz, &buf)) && buf) {
        if (sz >= 2) memcpy(&gSetup.boot_timeout, buf, 2);
        free_pool(buf);
    }

    load_boot_entries_only();

    gSetup.os_indications_sup   = 0;
    gSetup.os_indications       = 0;
    gSetup.os_indications_dirty = FALSE;
    if (!EFI_ERROR(nvram_read_var(L"OsIndicationsSupported", &gEfiGlobalVariableGuid, NULL, &sz, &buf)) && buf) {
        if (sz >= 8) memcpy(&gSetup.os_indications_sup, buf, 8);
        free_pool(buf);
    }
    if (!EFI_ERROR(nvram_read_var(L"OsIndications", &gEfiGlobalVariableGuid, NULL, &sz, &buf)) && buf) {
        if (sz >= 8) memcpy(&gSetup.os_indications, buf, 8);
        free_pool(buf);
    }
}

static VOID load_security_and_apple_vars(VOID) {
    UINT8 *buf = NULL;
    UINTN sz = 0;

    gSetup.secure_boot_enabled = FALSE;
    gSetup.setup_mode_enabled  = FALSE;
    if (!EFI_ERROR(nvram_read_var(L"SecureBoot", &gEfiGlobalVariableGuid, NULL, &sz, &buf)) && buf) {
        if (sz >= 1) gSetup.secure_boot_enabled = (buf[0] == 1);
        free_pool(buf);
    }
    if (!EFI_ERROR(nvram_read_var(L"SetupMode", &gEfiGlobalVariableGuid, NULL, &sz, &buf)) && buf) {
        if (sz >= 1) gSetup.setup_mode_enabled = (buf[0] == 1);
        free_pool(buf);
    }
    gSetup.pk_present  = !EFI_ERROR(nvram_read_var(L"PK",  &gEfiGlobalVariableGuid, NULL, &sz, NULL));
    gSetup.kek_present = !EFI_ERROR(nvram_read_var(L"KEK", &gEfiGlobalVariableGuid, NULL, &sz, NULL));
    gSetup.db_present  = !EFI_ERROR(nvram_read_var(L"db",  &gEfiImageSecurityDatabaseGuid, NULL, &sz, NULL));
    gSetup.dbx_present = !EFI_ERROR(nvram_read_var(L"dbx", &gEfiImageSecurityDatabaseGuid, NULL, &sz, NULL));

    gSetup.apple_vars_found      = gHw.is_apple_mac;
    gSetup.apple_boot_args[0]    = '\0';
    gSetup.apple_boot_args_dirty = FALSE;
    gSetup.apple_csr_present     = FALSE;
    gSetup.apple_csr_dirty       = FALSE;
    gSetup.apple_csr_config      = 0;
    gSetup.apple_vol_present     = FALSE;
    gSetup.apple_vol_dirty       = FALSE;
    gSetup.apple_audio_vol       = 0x40;
    gSetup.apple_gpu_present     = FALSE;
    gSetup.apple_gpu_dirty       = FALSE;
    gSetup.apple_gpu_mode        = 0;

    if (!EFI_ERROR(nvram_read_var(L"boot-args", &gAppleBootVariableGuid, NULL, &sz, &buf)) && buf) {
        gSetup.apple_vars_found = TRUE;
        UINTN cp = (sz < sizeof(gSetup.apple_boot_args) - 1) ? sz : (sizeof(gSetup.apple_boot_args) - 1);
        memcpy(gSetup.apple_boot_args, buf, cp);
        gSetup.apple_boot_args[cp] = '\0';
        free_pool(buf);
    }
    if (!EFI_ERROR(nvram_read_var(L"csr-active-config", &gAppleBootVariableGuid, NULL, &sz, &buf)) && buf) {
        gSetup.apple_vars_found  = TRUE;
        gSetup.apple_csr_present = TRUE;
        if (sz >= 4) memcpy(&gSetup.apple_csr_config, buf, 4);
        else memcpy(&gSetup.apple_csr_config, buf, sz);
        free_pool(buf);
    }
    if (!EFI_ERROR(nvram_read_var(L"SystemAudioVolume", &gAppleBootVariableGuid, NULL, &sz, &buf)) && buf) {
        gSetup.apple_vars_found  = TRUE;
        gSetup.apple_vol_present = TRUE;
        if (sz >= 1) gSetup.apple_audio_vol = buf[0];
        free_pool(buf);
    }
    if (!EFI_ERROR(nvram_read_var(L"gpu-power-prefs", &gAppleGpuPowerPrefsGuid, NULL, &sz, &buf)) && buf) {
        gSetup.apple_vars_found  = TRUE;
        gSetup.apple_gpu_present = TRUE;
        if (sz >= 1 && buf[0] == 1) gSetup.apple_gpu_mode = 1; /* Force Integrated Intel GPU */
        else gSetup.apple_gpu_mode = 2;                        /* Discrete / Dynamic GPU */
        free_pool(buf);
    }
}

static VOID set_default_cfg_struct(SETUP_UTILITY_CONFIG *c) {
    UINT8 keep_pw = c->has_supervisor_pw;
    UINT32 keep_hash = c->supervisor_pw_hash;
    memset(c, 0, sizeof(*c));
    c->magic              = SETUP_CFG_MAGIC;
    c->theme_idx          = UI_THEME_APTIO_2011;
    c->preferred_con_mode = -1;
    c->cpu_virtualization = (gHw.feat_vmx || gHw.feat_svm) ? 1 : 0;
    c->cpu_hyperthreading = (gHw.cpu_threads > gHw.cpu_cores) ? 1 : 0;
    c->cpu_cstates        = 1; /* Auto */
    c->cpu_turbo          = 1; /* Enabled */
    c->sata_mode          = 1; /* AHCI */
    c->fast_boot          = 0; /* Disabled */
    c->quiet_boot         = 1; /* Enabled */
    c->numlock_boot       = 1; /* On */
    c->network_pxe        = 0; /* Disabled */
    c->usb_legacy         = 1; /* Enabled */
    c->acpi_s3_sleep      = 1; /* S3 STR */
    c->primary_display    = 0; /* Auto */
    c->igd_dvmt_prealloc  = 1; /* 64MB */
    c->pcie_aspm_policy   = 4; /* OS Controlled */
    c->above_4g_decode    = 1; /* Enabled */
    c->has_supervisor_pw  = keep_pw;
    c->supervisor_pw_hash = keep_hash;
}

VOID nvram_load_optimized_defaults(VOID) {
    set_default_cfg_struct(&gSetup.cfg);
    gSetup.cfg_dirty = TRUE;
    ui_set_theme(gSetup.cfg.theme_idx);

    if (gSetup.boot_timeout != 5) {
        gSetup.boot_timeout  = 5;
        gSetup.timeout_dirty = TRUE;
    }
}

VOID nvram_init_state(VOID) {
    memset(&gSetup, 0, sizeof(gSetup));
    nvram_enumerate_all();

    UINT8 *buf = NULL;
    UINTN sz = 0;
    if (!EFI_ERROR(nvram_read_var(L"SetupUtilCfg", &gSetupUtilityConfigGuid, NULL, &sz, &buf)) && buf) {
        if (sz == sizeof(SETUP_UTILITY_CONFIG)) {
            const SETUP_UTILITY_CONFIG *loaded = (const SETUP_UTILITY_CONFIG *)buf;
            if (loaded->magic == SETUP_CFG_MAGIC) {
                gSetup.cfg = *loaded;
            } else {
                set_default_cfg_struct(&gSetup.cfg);
            }
        } else {
            set_default_cfg_struct(&gSetup.cfg);
        }
        free_pool(buf);
    } else {
        set_default_cfg_struct(&gSetup.cfg);
    }

    if (gSetup.cfg.theme_idx < UI_THEME_COUNT) {
        ui_set_theme(gSetup.cfg.theme_idx);
    }
    if (gSetup.cfg.preferred_con_mode >= 0) {
        ui_set_console_mode(gSetup.cfg.preferred_con_mode);
    }

    load_boot_variables();
    load_security_and_apple_vars();
    nvram_scan_efi_bootloaders();

    if (gRT && gRT->GetTime) {
        gRT->GetTime(&gSetup.staged_rtc, NULL);
    }
}

UINTN nvram_pending_changes_count(VOID) {
    UINTN n = 0;
    if (gSetup.cfg_dirty) n++;
    if (gSetup.timeout_dirty) n++;
    if (gSetup.boot_order_dirty) n++;
    for (UINTN i = 0; i < gSetup.boot_count; i++) {
        if (gSetup.boot_entries[i].modified_attr) n++;
    }
    if (gSetup.os_indications_dirty) n++;
    if (gSetup.apple_boot_args_dirty) n++;
    if (gSetup.apple_csr_dirty) n++;
    if (gSetup.apple_vol_dirty) n++;
    if (gSetup.apple_gpu_dirty) n++;
    if (gSetup.rtc_dirty) n++;
    return n;
}

BOOLEAN nvram_commit_staged_changes(CHAR8 *status_msg, UINTN max_msg) {
    UINT32 std_attr = EFI_VARIABLE_NON_VOLATILE |
                      EFI_VARIABLE_BOOTSERVICE_ACCESS |
                      EFI_VARIABLE_RUNTIME_ACCESS;
    UINTN ok_cnt = 0;
    UINTN err_cnt = 0;

    if (gSetup.cfg_dirty) {
        gSetup.cfg.magic = SETUP_CFG_MAGIC;
        if (!EFI_ERROR(nvram_write_var(L"SetupUtilCfg", &gSetupUtilityConfigGuid,
                                       std_attr, sizeof(gSetup.cfg), &gSetup.cfg))) {
            gSetup.cfg_dirty = FALSE;
            ok_cnt++;
        } else {
            err_cnt++;
        }
    }

    if (gSetup.timeout_dirty) {
        if (!EFI_ERROR(nvram_write_var(L"Timeout", &gEfiGlobalVariableGuid,
                                       std_attr, sizeof(UINT16), &gSetup.boot_timeout))) {
            gSetup.timeout_dirty = FALSE;
            ok_cnt++;
        } else {
            err_cnt++;
        }
    }

    for (UINTN i = 0; i < gSetup.boot_count; i++) {
        if (gSetup.boot_entries[i].modified_attr) {
            CHAR16 bname[16];
            wsnprintf(bname, 16, "Boot%04X", (UINT32)gSetup.boot_entries[i].boot_num);
            UINT32 vattr = 0;
            UINTN sz = 0;
            UINT8 *data = NULL;
            if (!EFI_ERROR(nvram_read_var(bname, &gEfiGlobalVariableGuid, &vattr, &sz, &data)) && data && sz >= 6) {
                UINT32 opt_attr = 0;
                memcpy(&opt_attr, data, 4);
                if (gSetup.boot_entries[i].active) opt_attr |= LOAD_OPTION_ACTIVE;
                else opt_attr &= ~LOAD_OPTION_ACTIVE;
                memcpy(data, &opt_attr, 4);
                if (!EFI_ERROR(nvram_write_var(bname, &gEfiGlobalVariableGuid, vattr ? vattr : std_attr, sz, data))) {
                    gSetup.boot_entries[i].modified_attr = FALSE;
                    ok_cnt++;
                } else {
                    err_cnt++;
                }
                free_pool(data);
            } else {
                free_pool(data);
                err_cnt++;
            }
        }
    }

    if (gSetup.boot_order_dirty) {
        UINT16 order_arr[NVRAM_MAX_BOOT_ENTRIES];
        UINTN ord_n = 0;
        for (UINTN i = 0; i < gSetup.boot_count; i++) {
            if (gSetup.boot_entries[i].in_boot_order) {
                order_arr[ord_n++] = gSetup.boot_entries[i].boot_num;
            }
        }
        EFI_STATUS bst;
        if (ord_n > 0) {
            bst = nvram_write_var(L"BootOrder", &gEfiGlobalVariableGuid,
                                  std_attr, ord_n * sizeof(UINT16), order_arr);
        } else {
            bst = nvram_delete_var(L"BootOrder", &gEfiGlobalVariableGuid);
            if (bst == EFI_NOT_FOUND) bst = EFI_SUCCESS;
        }
        if (!EFI_ERROR(bst)) {
            gSetup.boot_order_dirty = FALSE;
            ok_cnt++;
        } else {
            err_cnt++;
        }
    }

    if (gSetup.os_indications_dirty) {
        if (!EFI_ERROR(nvram_write_var(L"OsIndications", &gEfiGlobalVariableGuid,
                                       std_attr, sizeof(UINT64), &gSetup.os_indications))) {
            gSetup.os_indications_dirty = FALSE;
            ok_cnt++;
        } else {
            err_cnt++;
        }
    }

    if (gSetup.apple_boot_args_dirty) {
        EFI_STATUS st;
        if (gSetup.apple_boot_args[0] == '\0') {
            st = nvram_delete_var(L"boot-args", &gAppleBootVariableGuid);
            if (st == EFI_NOT_FOUND) st = EFI_SUCCESS;
        } else {
            st = nvram_write_var(L"boot-args", &gAppleBootVariableGuid,
                                 std_attr, str_len(gSetup.apple_boot_args) + 1,
                                 gSetup.apple_boot_args);
        }
        if (!EFI_ERROR(st)) {
            gSetup.apple_boot_args_dirty = FALSE;
            ok_cnt++;
        } else {
            err_cnt++;
        }
    }

    if (gSetup.apple_csr_dirty) {
        if (!EFI_ERROR(nvram_write_var(L"csr-active-config", &gAppleBootVariableGuid,
                                       std_attr, sizeof(UINT32), &gSetup.apple_csr_config))) {
            gSetup.apple_csr_dirty   = FALSE;
            gSetup.apple_csr_present = TRUE;
            ok_cnt++;
        } else {
            err_cnt++;
        }
    }

    if (gSetup.apple_vol_dirty) {
        if (!EFI_ERROR(nvram_write_var(L"SystemAudioVolume", &gAppleBootVariableGuid,
                                       std_attr, 1, &gSetup.apple_audio_vol))) {
            gSetup.apple_vol_dirty   = FALSE;
            gSetup.apple_vol_present = TRUE;
            ok_cnt++;
        } else {
            err_cnt++;
        }
    }

    if (gSetup.apple_gpu_dirty) {
        EFI_STATUS gst;
        if (gSetup.apple_gpu_mode == 0) {
            gst = nvram_delete_var(L"gpu-power-prefs", &gAppleGpuPowerPrefsGuid);
            if (gst == EFI_NOT_FOUND) gst = EFI_SUCCESS;
            if (!EFI_ERROR(gst)) gSetup.apple_gpu_present = FALSE;
        } else {
            UINT8 gval[4] = { (gSetup.apple_gpu_mode == 1) ? 0x01U : 0x00U, 0x00U, 0x00U, 0x00U };
            gst = nvram_write_var(L"gpu-power-prefs", &gAppleGpuPowerPrefsGuid, std_attr, 4, gval);
            if (!EFI_ERROR(gst)) gSetup.apple_gpu_present = TRUE;
        }
        if (!EFI_ERROR(gst)) {
            gSetup.apple_gpu_dirty = FALSE;
            ok_cnt++;
        } else {
            err_cnt++;
        }
    }

    if (gSetup.rtc_dirty && gRT && gRT->SetTime) {
        EFI_TIME cur;
        memset(&cur, 0, sizeof(cur));
        if (gRT->GetTime) gRT->GetTime(&cur, NULL);
        cur.Year   = gSetup.staged_rtc.Year;
        cur.Month  = gSetup.staged_rtc.Month;
        cur.Day    = gSetup.staged_rtc.Day;
        cur.Hour   = gSetup.staged_rtc.Hour;
        cur.Minute = gSetup.staged_rtc.Minute;
        cur.Second = gSetup.staged_rtc.Second;
        if (!EFI_ERROR(gRT->SetTime(&cur))) {
            gSetup.rtc_dirty = FALSE;
            ok_cnt++;
        } else {
            err_cnt++;
        }
    }

    nvram_enumerate_all();

    if (status_msg && max_msg > 0) {
        snprintf_ascii(status_msg, max_msg,
                       "Committed %u NVRAM/RTC setting(s) (%u failed).",
                       (UINT32)ok_cnt, (UINT32)err_cnt);
    }
    return (err_cnt == 0);
}

/* =========================================================================
 * Device Path Builder & Boot Entry Add / Remove (Boot#### + BootOrder)
 * ========================================================================= */
static EFI_DEVICE_PATH_PROTOCOL *build_file_device_path_ex(
    EFI_HANDLE dev_handle,
    const CHAR16 *path_w,
    UINTN *out_total_bytes
) {
    if (out_total_bytes) *out_total_bytes = 0;
    EFI_DEVICE_PATH_PROTOCOL *vol_dp = NULL;
    if (dev_handle) {
        gBS->HandleProtocol(dev_handle, &gEfiDevicePathProtocolGuid, (VOID **)&vol_dp);
    }

    UINTN vol_len = 0;
    if (vol_dp) {
        const EFI_DEVICE_PATH_PROTOCOL *n = vol_dp;
        for (UINTN guard = 0; guard < 64; guard++) {
            UINT16 nl = (UINT16)n->Length[0] | ((UINT16)n->Length[1] << 8);
            if (nl < 4 || n->Type == 0x7F) break;
            vol_len += nl;
            n = (const EFI_DEVICE_PATH_PROTOCOL *)((const UINT8 *)n + nl);
        }
    }

    CHAR16 norm_path[160];
    if (path_w && path_w[0] != L'\\') {
        wsnprintf(norm_path, 160, "\\%S", path_w);
    } else {
        wstr_cpy(norm_path, path_w ? path_w : L"\\EFI\\BOOT\\BOOTX64.EFI", 160);
    }

    UINTN str_bytes   = (wstr_len(norm_path) + 1) * sizeof(CHAR16);
    UINTN fp_node_len = 4 + str_bytes;
    UINTN total_len   = vol_len + fp_node_len + 4;

    UINT8 *out = (UINT8 *)alloc_zero_pool(total_len);
    if (!out) return NULL;

    if (vol_len > 0 && vol_dp) {
        memcpy(out, vol_dp, vol_len);
    }
    UINT8 *fp = out + vol_len;
    fp[0] = 0x04;
    fp[1] = 0x04;
    fp[2] = (UINT8)(fp_node_len & 0xFFU);
    fp[3] = (UINT8)((fp_node_len >> 8) & 0xFFU);
    memcpy(fp + 4, norm_path, str_bytes);

    UINT8 *endp = fp + fp_node_len;
    endp[0] = 0x7F;
    endp[1] = 0xFF;
    endp[2] = 0x04;
    endp[3] = 0x00;

    if (out_total_bytes) *out_total_bytes = total_len;
    return (EFI_DEVICE_PATH_PROTOCOL *)out;
}

BOOLEAN nvram_add_boot_entry(
    EFI_HANDLE fs_handle,
    const CHAR16 *path_w,
    const CHAR8 *description_ascii,
    BOOLEAN place_first,
    UINT16 *out_boot_num,
    CHAR8 *err_out,
    UINTN max_err
) {
    if (!fs_handle || !path_w || !path_w[0]) {
        if (err_out) str_cpy(err_out, "Invalid volume or .efi path.", max_err);
        return FALSE;
    }

    /* Find lowest free Boot#### slot (0x0000..0x00FF) */
    UINT16 free_num = 0xFFFFU;
    for (UINT16 cand = 0; cand < 0x0100U; cand++) {
        CHAR16 bname[16];
        wsnprintf(bname, 16, "Boot%04X", (UINT32)cand);
        UINTN sz = 0;
        if (nvram_read_var(bname, &gEfiGlobalVariableGuid, NULL, &sz, NULL) == EFI_NOT_FOUND) {
            free_num = cand;
            break;
        }
    }
    if (free_num == 0xFFFFU) {
        if (err_out) str_cpy(err_out, "No free Boot#### slot found in NVRAM.", max_err);
        return FALSE;
    }

    UINTN dp_bytes = 0;
    EFI_DEVICE_PATH_PROTOCOL *dp = build_file_device_path_ex(fs_handle, path_w, &dp_bytes);
    if (!dp || dp_bytes < 8) {
        free_pool(dp);
        if (err_out) str_cpy(err_out, "Could not build UEFI DevicePath.", max_err);
        return FALSE;
    }

    const CHAR8 *desc_src = (description_ascii && description_ascii[0]) ? description_ascii : "Custom UEFI Boot";
    CHAR16 desc_w[64];
    ascii_to_wstr(desc_w, desc_src, 64);
    UINTN desc_bytes = (wstr_len(desc_w) + 1) * sizeof(CHAR16);

    UINTN opt_total = 4 + 2 + desc_bytes + dp_bytes;
    UINT8 *opt_buf = (UINT8 *)alloc_zero_pool(opt_total);
    if (!opt_buf) {
        free_pool(dp);
        if (err_out) str_cpy(err_out, "Out of pool memory.", max_err);
        return FALSE;
    }

    UINT32 opt_attr = LOAD_OPTION_ACTIVE;
    UINT16 fp_len16 = (UINT16)dp_bytes;
    memcpy(opt_buf + 0, &opt_attr, 4);
    memcpy(opt_buf + 4, &fp_len16, 2);
    memcpy(opt_buf + 6, desc_w, desc_bytes);
    memcpy(opt_buf + 6 + desc_bytes, dp, dp_bytes);
    free_pool(dp);

    UINT32 std_attr = EFI_VARIABLE_NON_VOLATILE |
                      EFI_VARIABLE_BOOTSERVICE_ACCESS |
                      EFI_VARIABLE_RUNTIME_ACCESS;
    CHAR16 bname[16];
    wsnprintf(bname, 16, "Boot%04X", (UINT32)free_num);
    EFI_STATUS st = nvram_write_var(bname, &gEfiGlobalVariableGuid, std_attr, opt_total, opt_buf);
    free_pool(opt_buf);
    if (EFI_ERROR(st)) {
        if (err_out) snprintf_ascii(err_out, max_err, "SetVariable(%S) failed: %s", bname, efi_status_str(st));
        return FALSE;
    }

    /* Update BootOrder in NVRAM */
    UINT16 new_order[NVRAM_MAX_BOOT_ENTRIES + 2];
    UINTN ord_n = 0;
    if (place_first) {
        new_order[ord_n++] = free_num;
    }
    for (UINTN i = 0; i < gSetup.boot_count && ord_n < NVRAM_MAX_BOOT_ENTRIES; i++) {
        if (gSetup.boot_entries[i].in_boot_order && gSetup.boot_entries[i].boot_num != free_num) {
            new_order[ord_n++] = gSetup.boot_entries[i].boot_num;
        }
    }
    if (!place_first) {
        new_order[ord_n++] = free_num;
    }
    nvram_write_var(L"BootOrder", &gEfiGlobalVariableGuid, std_attr, ord_n * sizeof(UINT16), new_order);

    if (out_boot_num) *out_boot_num = free_num;
    nvram_reload_boot_entries();
    return TRUE;
}

BOOLEAN nvram_delete_boot_entry(UINTN boot_idx, CHAR8 *err_out, UINTN max_err) {
    if (boot_idx >= gSetup.boot_count) {
        if (err_out) str_cpy(err_out, "Invalid boot entry selection.", max_err);
        return FALSE;
    }

    UINT16 target_num = gSetup.boot_entries[boot_idx].boot_num;
    CHAR16 bname[16];
    wsnprintf(bname, 16, "Boot%04X", (UINT32)target_num);

    EFI_STATUS st = nvram_delete_var(bname, &gEfiGlobalVariableGuid);
    if (EFI_ERROR(st) && st != EFI_NOT_FOUND) {
        if (err_out) snprintf_ascii(err_out, max_err, "Delete Boot%04X failed: %s",
                                    (UINT32)target_num, efi_status_str(st));
        return FALSE;
    }

    /* Remove from BootOrder and write updated BootOrder to NVRAM */
    UINT16 new_order[NVRAM_MAX_BOOT_ENTRIES];
    UINTN ord_n = 0;
    for (UINTN i = 0; i < gSetup.boot_count && ord_n < NVRAM_MAX_BOOT_ENTRIES; i++) {
        if (i != boot_idx && gSetup.boot_entries[i].in_boot_order &&
            gSetup.boot_entries[i].boot_num != target_num) {
            new_order[ord_n++] = gSetup.boot_entries[i].boot_num;
        }
    }

    UINT32 std_attr = EFI_VARIABLE_NON_VOLATILE |
                      EFI_VARIABLE_BOOTSERVICE_ACCESS |
                      EFI_VARIABLE_RUNTIME_ACCESS;
    if (ord_n > 0) {
        nvram_write_var(L"BootOrder", &gEfiGlobalVariableGuid, std_attr, ord_n * sizeof(UINT16), new_order);
    } else {
        nvram_delete_var(L"BootOrder", &gEfiGlobalVariableGuid);
    }

    nvram_reload_boot_entries();
    return TRUE;
}

/* =========================================================================
 * Interactive Volume & Directory .EFI File Browser (Keyboard Only)
 * ========================================================================= */
#define BROWSER_MAX_ITEMS 48

typedef struct {
    CHAR16  name_w[64];
    CHAR8   disp[68];
    BOOLEAN is_dir;
    BOOLEAN is_up;
    BOOLEAN is_custom;
} EFI_BROWSER_ITEM;

static VOID get_volume_summary(EFI_HANDLE h, UINTN idx, CHAR8 *out, UINTN max_len) {
    CHAR8 vlabel[32];
    vlabel[0] = '\0';
    UINT64 size_mb = 0;

    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *sfs = NULL;
    if (!EFI_ERROR(gBS->HandleProtocol(h, &gEfiSimpleFileSystemProtocolGuid, (VOID **)&sfs)) && sfs) {
        EFI_FILE_PROTOCOL *root = NULL;
        if (!EFI_ERROR(sfs->OpenVolume(sfs, &root)) && root) {
            UINT8 fsibuf[256];
            UINTN fsisz = sizeof(fsibuf);
            if (!EFI_ERROR(root->GetInfo(root, &gEfiFileSystemInfoGuid, &fsisz, fsibuf))) {
                EFI_FILE_SYSTEM_INFO *fsi = (EFI_FILE_SYSTEM_INFO *)fsibuf;
                size_mb = fsi->VolumeSize >> 20;
                wstr_to_ascii(vlabel, fsi->VolumeLabel, sizeof(vlabel));
            }
            root->Close(root);
        }
    }
    if (!vlabel[0]) str_cpy(vlabel, "EFI_VOL", sizeof(vlabel));
    snprintf_ascii(out, max_len, "[FS%u] %-14s (%lu MB)", (UINT32)idx, vlabel, size_mb);
}

BOOLEAN nvram_browse_efi_file_interactive(
    EFI_HANDLE *out_fs,
    CHAR16 *out_path_w,
    UINTN max_wchars,
    CHAR8 *out_default_label,
    UINTN max_label
) {
    if (!out_fs || !out_path_w || max_wchars < 8) return FALSE;

    UINTN fs_cnt = 0;
    EFI_HANDLE *fs_handles = NULL;
    if (EFI_ERROR(efi_locate_handles(&gEfiSimpleFileSystemProtocolGuid, &fs_cnt, &fs_handles)) ||
        !fs_handles || fs_cnt == 0) {
        free_pool(fs_handles);
        ui_message_modal("No EFI Volumes", "No mounted FAT/EFI SimpleFileSystem volumes detected.", TRUE);
        return FALSE;
    }

    CHAR8 vol_labels[16][64];
    const CHAR8 *vol_ptrs[16];
    UINTN show_vols = (fs_cnt < 16) ? fs_cnt : 16;
    for (UINTN v = 0; v < show_vols; v++) {
        get_volume_summary(fs_handles[v], v, vol_labels[v], sizeof(vol_labels[v]));
        vol_ptrs[v] = vol_labels[v];
    }

    EFI_BROWSER_ITEM *items = (EFI_BROWSER_ITEM *)alloc_zero_pool(sizeof(EFI_BROWSER_ITEM) * BROWSER_MAX_ITEMS);
    if (!items) {
        free_pool(fs_handles);
        return FALSE;
    }

    BOOLEAN picked_ok = FALSE;
    for (;;) {
        INTN vpick = ui_select_modal("Select Volume for Boot Entry", vol_ptrs, show_vols, 0);
        if (vpick < 0) break;

        EFI_HANDLE vh = fs_handles[vpick];
        EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *sfs = NULL;
        EFI_FILE_PROTOCOL *root = NULL;
        if (EFI_ERROR(gBS->HandleProtocol(vh, &gEfiSimpleFileSystemProtocolGuid, (VOID **)&sfs)) ||
            !sfs || EFI_ERROR(sfs->OpenVolume(sfs, &root)) || !root) {
            ui_message_modal("Volume Error", "Unable to open selected volume.", TRUE);
            continue;
        }

        CHAR16 cur_dir[128];
        wstr_cpy(cur_dir, L"\\", 128);

        for (;;) {
            EFI_FILE_PROTOCOL *dir_h = NULL;
            if (EFI_ERROR(root->Open(root, &dir_h, cur_dir, EFI_FILE_MODE_READ, 0)) || !dir_h) {
                wstr_cpy(cur_dir, L"\\", 128);
                if (EFI_ERROR(root->Open(root, &dir_h, cur_dir, EFI_FILE_MODE_READ, 0)) || !dir_h) break;
            }

            UINTN icnt = 0;
            if (wstr_cmp(cur_dir, L"\\") != 0) {
                items[icnt].is_up = TRUE;
                str_cpy(items[icnt].disp, "[..] (Parent Directory)", sizeof(items[icnt].disp));
                icnt++;
            }

            /* Pass 0: Subdirectories, Pass 1: .efi files */
            for (UINTN pass = 0; pass < 2; pass++) {
                dir_h->SetPosition(dir_h, 0);
                UINT8 fibuf[512];
                for (UINTN guard = 0; guard < 128 && icnt + 1 < BROWSER_MAX_ITEMS; guard++) {
                    UINTN fisz = sizeof(fibuf);
                    if (EFI_ERROR(dir_h->Read(dir_h, &fisz, fibuf)) || fisz == 0) break;
                    EFI_FILE_INFO *fi = (EFI_FILE_INFO *)fibuf;
                    if (fi->FileName[0] == L'.') continue;
                    BOOLEAN is_d = ((fi->Attribute & EFI_FILE_DIRECTORY) != 0);
                    if (pass == 0 && !is_d) continue;
                    if (pass == 1 && (is_d || !wstr_contains_icase(fi->FileName, L".efi"))) continue;

                    EFI_BROWSER_ITEM *it = &items[icnt++];
                    memset(it, 0, sizeof(*it));
                    it->is_dir = is_d;
                    wstr_cpy(it->name_w, fi->FileName, 64);
                    CHAR8 nm_a[52];
                    wstr_to_ascii(nm_a, fi->FileName, sizeof(nm_a));
                    if (is_d) {
                        snprintf_ascii(it->disp, sizeof(it->disp), "[DIR] %s\\", nm_a);
                    } else {
                        snprintf_ascii(it->disp, sizeof(it->disp), "[EFI] %-28s (%lu KB)",
                                       nm_a, (fi->FileSize + 1023ULL) >> 10);
                    }
                }
            }
            dir_h->Close(dir_h);

            items[icnt].is_custom = TRUE;
            str_cpy(items[icnt].disp, "[+] Enter Custom .EFI Path on This Volume...", sizeof(items[icnt].disp));
            icnt++;

            const CHAR8 *iptrs[BROWSER_MAX_ITEMS];
            for (UINTN i = 0; i < icnt; i++) iptrs[i] = items[i].disp;

            CHAR8 dtitle[64], dpath_a[48];
            wstr_to_ascii(dpath_a, cur_dir, sizeof(dpath_a));
            snprintf_ascii(dtitle, sizeof(dtitle), "FS%u:%s", (UINT32)vpick, dpath_a);

            INTN sel = ui_select_modal(dtitle, iptrs, icnt, 0);
            if (sel < 0) {
                if (wstr_cmp(cur_dir, L"\\") == 0) break; /* Back to volume picker */
                /* Pop one directory up */
                UINTN l = wstr_len(cur_dir);
                while (l > 0 && cur_dir[l - 1] != L'\\') l--;
                if (l <= 1) wstr_cpy(cur_dir, L"\\", 128);
                else cur_dir[l - 1] = 0;
                continue;
            }

            if (items[sel].is_up) {
                UINTN l = wstr_len(cur_dir);
                while (l > 0 && cur_dir[l - 1] != L'\\') l--;
                if (l <= 1) wstr_cpy(cur_dir, L"\\", 128);
                else cur_dir[l - 1] = 0;
            } else if (items[sel].is_dir) {
                CHAR16 next_d[128];
                if (wstr_cmp(cur_dir, L"\\") == 0) {
                    wsnprintf(next_d, 128, "\\%S", items[sel].name_w);
                } else {
                    wsnprintf(next_d, 128, "%S\\%S", cur_dir, items[sel].name_w);
                }
                wstr_cpy(cur_dir, next_d, 128);
            } else if (items[sel].is_custom) {
                CHAR8 cpath[96];
                if (ui_input_modal("Custom .EFI File Path",
                                   "Enter path on selected volume (e.g. \\EFI\\BOOT\\BOOTX64.EFI):",
                                   "\\EFI\\BOOT\\BOOTX64.EFI", cpath, sizeof(cpath), FALSE) && cpath[0]) {
                    *out_fs = vh;
                    ascii_to_wstr(out_path_w, cpath, max_wchars);
                    if (out_default_label && max_label > 0) {
                        str_cpy(out_default_label, cpath, max_label);
                    }
                    picked_ok = TRUE;
                    break;
                }
            } else {
                if (wstr_cmp(cur_dir, L"\\") == 0) {
                    wsnprintf(out_path_w, max_wchars, "\\%S", items[sel].name_w);
                } else {
                    wsnprintf(out_path_w, max_wchars, "%S\\%S", cur_dir, items[sel].name_w);
                }
                *out_fs = vh;
                if (out_default_label && max_label > 0) {
                    CHAR8 fn_a[48];
                    wstr_to_ascii(fn_a, items[sel].name_w, sizeof(fn_a));
                    snprintf_ascii(out_default_label, max_label, "UEFI: %s", fn_a);
                }
                picked_ok = TRUE;
                break;
            }
        }

        root->Close(root);
        if (picked_ok) break;
    }

    free_pool(items);
    free_pool(fs_handles);
    return picked_ok;
}

/* =========================================================================
 * Scan Mounted Volumes for Standard OS Bootloaders & Chainloading
 * ========================================================================= */
static const struct {
    const CHAR16 *path_w;
    const CHAR8  *desc;
} kCommonBootloaders[] = {
    { L"\\System\\Library\\CoreServices\\boot.efi", "macOS / OS X Bootloader (boot.efi)" },
    { L"\\EFI\\APPLE\\UPDATERS\\MULTIUPDATER\\ThorUtil.efi", "Apple Firmware Utility" },
    { L"\\EFI\\OC\\OpenCore.efi",                   "OpenCore Bootloader" },
    { L"\\EFI\\CLOVER\\CLOVERX64.efi",              "Clover EFI Bootloader" },
    { L"\\EFI\\refind\\refind_x64.efi",             "rEFInd Boot Manager" },
    { L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi",      "Windows Boot Manager (bootmgfw.efi)" },
    { L"\\EFI\\ubuntu\\grubx64.efi",                "Ubuntu Linux (GRUB x64)" },
    { L"\\EFI\\debian\\grubx64.efi",                "Debian Linux (GRUB x64)" },
    { L"\\EFI\\fedora\\grubx64.efi",                "Fedora Linux (GRUB x64)" },
    { L"\\EFI\\arch\\grubx64.efi",                  "Arch Linux (GRUB x64)" },
    { L"\\EFI\\systemd\\systemd-bootx64.efi",       "Linux systemd-boot" },
    { L"\\shellx64.efi",                            "UEFI Interactive Shell (shellx64)" },
    { L"\\EFI\\BOOT\\Shell.efi",                    "UEFI Shell (EFI/BOOT/Shell.efi)" },
    { L"\\EFI\\BOOT\\BOOTX64.EFI",                  "UEFI Removable Boot (BOOTX64.EFI)" },
    { L"\\EFI\\BOOT\\BOOTIA32.EFI",                 "UEFI 32-bit Boot (BOOTIA32.EFI)" },
};

static BOOLEAN check_file_exists(EFI_FILE_PROTOCOL *root, const CHAR16 *path) {
    EFI_FILE_PROTOCOL *fh = NULL;
    if (EFI_ERROR(root->Open(root, &fh, (CHAR16 *)path, EFI_FILE_MODE_READ, 0)) || !fh) {
        return FALSE;
    }
    fh->Close(fh);
    return TRUE;
}

VOID nvram_scan_efi_bootloaders(VOID) {
    gSetup.loader_count = 0;
    UINTN count = 0;
    EFI_HANDLE *handles = NULL;
    if (EFI_ERROR(efi_locate_handles(&gEfiSimpleFileSystemProtocolGuid, &count, &handles)) || !handles) {
        return;
    }

    EFI_HANDLE self_dev = NULL;
    if (gImageHandle) {
        EFI_LOADED_IMAGE_PROTOCOL *li = NULL;
        if (!EFI_ERROR(gBS->HandleProtocol(gImageHandle, &gEfiLoadedImageProtocolGuid, (VOID **)&li)) && li) {
            self_dev = li->DeviceHandle;
        }
    }

    for (UINTN v = 0; v < count && gSetup.loader_count < NVRAM_MAX_EFI_LOADERS; v++) {
        EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *sfs = NULL;
        if (EFI_ERROR(gBS->HandleProtocol(handles[v], &gEfiSimpleFileSystemProtocolGuid, (VOID **)&sfs)) || !sfs) {
            continue;
        }
        EFI_FILE_PROTOCOL *root = NULL;
        if (EFI_ERROR(sfs->OpenVolume(sfs, &root)) || !root) {
            continue;
        }

        for (UINTN k = 0; k < sizeof(kCommonBootloaders) / sizeof(kCommonBootloaders[0]); k++) {
            if (gSetup.loader_count >= NVRAM_MAX_EFI_LOADERS) break;
            if (handles[v] == self_dev &&
                (wstr_icmp(kCommonBootloaders[k].path_w, L"\\EFI\\BOOT\\BOOTX64.EFI") == 0 ||
                 wstr_icmp(kCommonBootloaders[k].path_w, L"\\EFI\\BOOT\\BOOTIA32.EFI") == 0)) {
                continue;
            }
            if (check_file_exists(root, kCommonBootloaders[k].path_w)) {
                DISCOVERED_EFI_LOADER *ld = &gSetup.loaders[gSetup.loader_count++];
                ld->fs_handle = handles[v];
                wstr_cpy(ld->path_w, kCommonBootloaders[k].path_w, 128);
                wstr_to_ascii(ld->path_ascii, ld->path_w, sizeof(ld->path_ascii));
                snprintf_ascii(ld->label, sizeof(ld->label), "[FS%u] %s",
                               (UINT32)v, kCommonBootloaders[k].desc);
            }
        }

        EFI_FILE_PROTOCOL *efi_dir = NULL;
        if (!EFI_ERROR(root->Open(root, &efi_dir, L"\\EFI", EFI_FILE_MODE_READ, 0)) && efi_dir) {
            UINT8 info_buf[512];
            for (UINTN guard = 0; guard < 32 && gSetup.loader_count < NVRAM_MAX_EFI_LOADERS; guard++) {
                UINTN isz = sizeof(info_buf);
                if (EFI_ERROR(efi_dir->Read(efi_dir, &isz, info_buf)) || isz == 0) break;
                EFI_FILE_INFO *fi = (EFI_FILE_INFO *)info_buf;
                if (fi->FileName[0] == L'.') continue;
                if ((fi->Attribute & EFI_FILE_DIRECTORY) == 0 && wstr_contains_icase(fi->FileName, L".efi")) {
                    DISCOVERED_EFI_LOADER *ld = &gSetup.loaders[gSetup.loader_count++];
                    ld->fs_handle = handles[v];
                    wsnprintf(ld->path_w, 128, "\\EFI\\%S", fi->FileName);
                    wstr_to_ascii(ld->path_ascii, ld->path_w, sizeof(ld->path_ascii));
                    snprintf_ascii(ld->label, sizeof(ld->label), "[FS%u] %s", (UINT32)v, ld->path_ascii);
                }
            }
            efi_dir->Close(efi_dir);
        }

        root->Close(root);
    }
    free_pool(handles);
}

EFI_STATUS nvram_chainload_efi(EFI_HANDLE fs_handle, const CHAR16 *path_w) {
    if (!gBS || !fs_handle || !path_w) return EFI_INVALID_PARAMETER;

    EFI_DEVICE_PATH_PROTOCOL *full_dp = build_file_device_path_ex(fs_handle, path_w, NULL);
    EFI_HANDLE child_img = NULL;
    EFI_STATUS st = EFI_NOT_FOUND;

    if (full_dp) {
        st = gBS->LoadImage(FALSE, gImageHandle, full_dp, NULL, 0, &child_img);
    }

    VOID *file_buf = NULL;
    if (EFI_ERROR(st)) {
        EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *sfs = NULL;
        if (!EFI_ERROR(gBS->HandleProtocol(fs_handle, &gEfiSimpleFileSystemProtocolGuid, (VOID **)&sfs)) && sfs) {
            EFI_FILE_PROTOCOL *root = NULL;
            if (!EFI_ERROR(sfs->OpenVolume(sfs, &root)) && root) {
                EFI_FILE_PROTOCOL *fh = NULL;
                if (!EFI_ERROR(root->Open(root, &fh, (CHAR16 *)path_w, EFI_FILE_MODE_READ, 0)) && fh) {
                    UINT8 fibuf[256];
                    UINTN fisz = sizeof(fibuf);
                    if (!EFI_ERROR(fh->GetInfo(fh, &gEfiFileInfoGuid, &fisz, fibuf))) {
                        EFI_FILE_INFO *fi = (EFI_FILE_INFO *)fibuf;
                        UINTN fsz = (UINTN)fi->FileSize;
                        if (fsz > 64 && fsz < 0x8000000U) {
                            file_buf = alloc_pool(fsz);
                            if (file_buf) {
                                if (!EFI_ERROR(fh->Read(fh, &fsz, file_buf))) {
                                    st = gBS->LoadImage(FALSE, gImageHandle, full_dp, file_buf, fsz, &child_img);
                                }
                            }
                        }
                    }
                    fh->Close(fh);
                }
                root->Close(root);
            }
        }
    }

    if (EFI_ERROR(st) || !child_img) {
        free_pool(file_buf);
        free_pool(full_dp);
        return EFI_ERROR(st) ? st : EFI_LOAD_ERROR;
    }

    EFI_LOADED_IMAGE_PROTOCOL *child_li = NULL;
    if (!EFI_ERROR(gBS->HandleProtocol(child_img, &gEfiLoadedImageProtocolGuid, (VOID **)&child_li)) && child_li) {
        if (!child_li->DeviceHandle) child_li->DeviceHandle = fs_handle;
    }

    if (gST && gST->ConOut) {
        gST->ConOut->SetAttribute(gST->ConOut, EFI_TEXT_ATTR(EFI_LIGHTGRAY, EFI_BACKGROUND_BLACK));
        gST->ConOut->ClearScreen(gST->ConOut);
        if (gST->ConOut->EnableCursor) gST->ConOut->EnableCursor(gST->ConOut, TRUE);
    }

    UINTN exit_sz = 0;
    CHAR16 *exit_data = NULL;
    st = gBS->StartImage(child_img, &exit_sz, &exit_data);
    if (exit_data) free_pool(exit_data);
    free_pool(file_buf);
    free_pool(full_dp);

    ui_force_redraw();
    return st;
}

EFI_STATUS nvram_set_boot_next(UINT16 boot_num) {
    UINT32 std_attr = EFI_VARIABLE_NON_VOLATILE |
                      EFI_VARIABLE_BOOTSERVICE_ACCESS |
                      EFI_VARIABLE_RUNTIME_ACCESS;
    return nvram_write_var(L"BootNext", &gEfiGlobalVariableGuid, std_attr, sizeof(UINT16), &boot_num);
}

static BOOLEAN fs_handle_matches_gpt_sig(EFI_HANDLE fs_h, const UINT8 gpt_sig[16]) {
    EFI_DEVICE_PATH_PROTOCOL *dp = NULL;
    if (EFI_ERROR(gBS->HandleProtocol(fs_h, &gEfiDevicePathProtocolGuid, (VOID **)&dp)) || !dp) {
        return FALSE;
    }
    const EFI_DEVICE_PATH_PROTOCOL *n = dp;
    for (UINTN guard = 0; guard < 32; guard++) {
        UINT16 nl = (UINT16)n->Length[0] | ((UINT16)n->Length[1] << 8);
        if (nl < 4 || n->Type == 0x7FU) break;
        if (n->Type == 0x04U && n->SubType == 0x01U && nl >= 42U) {
            const UINT8 *raw = (const UINT8 *)n;
            if (raw[41] == 0x02U && memcmp(raw + 24, gpt_sig, 16) == 0) {
                return TRUE;
            }
        }
        n = (const EFI_DEVICE_PATH_PROTOCOL *)((const UINT8 *)n + nl);
    }
    return FALSE;
}

EFI_STATUS nvram_chainload_boot_entry(UINT16 boot_num, CHAR8 *err_out, UINTN max_err) {
    if (!gBS) return EFI_UNSUPPORTED;
    CHAR16 bname[16];
    wsnprintf(bname, 16, "Boot%04X", (UINT32)boot_num);

    UINT8 *data = NULL;
    UINTN sz = 0;
    EFI_STATUS st = nvram_read_var(bname, &gEfiGlobalVariableGuid, NULL, &sz, &data);
    if (EFI_ERROR(st) || !data || sz < 10) {
        if (data) free_pool(data);
        if (err_out) snprintf_ascii(err_out, max_err, "Unable to read Boot%04X from NVRAM.", (UINT32)boot_num);
        return EFI_NOT_FOUND;
    }

    UINT16 fp_list_len = 0;
    memcpy(&fp_list_len, data + 4, 2);
    const CHAR16 *desc_w = (const CHAR16 *)(data + 6);
    UINTN max_w = (sz - 6) / 2;
    UINTN wi = 0;
    while (wi < max_w && desc_w[wi] != 0) wi++;
    UINTN dp_off = 6 + (wi + 1) * sizeof(CHAR16);
    if (dp_off + 4 > sz || fp_list_len < 4) {
        free_pool(data);
        if (err_out) str_cpy(err_out, "Boot entry has no valid EFI Device Path.", max_err);
        return EFI_LOAD_ERROR;
    }

    UINTN dp_len = fp_list_len;
    if (dp_off + dp_len > sz) dp_len = sz - dp_off;
    EFI_DEVICE_PATH_PROTOCOL *dp = (EFI_DEVICE_PATH_PROTOCOL *)(data + dp_off);
    UINTN opt_off = dp_off + dp_len;
    UINTN opt_sz  = (opt_off < sz) ? (sz - opt_off) : 0;

    /* 1. Try native UEFI LoadImage(BootPolicy=TRUE) directly on the Boot#### DevicePath */
    EFI_HANDLE child_img = NULL;
    st = gBS->LoadImage(TRUE, gImageHandle, dp, NULL, 0, &child_img);
    if (!EFI_ERROR(st) && child_img) {
        EFI_LOADED_IMAGE_PROTOCOL *child_li = NULL;
        if (!EFI_ERROR(gBS->HandleProtocol(child_img, &gEfiLoadedImageProtocolGuid, (VOID **)&child_li)) &&
            child_li && opt_sz > 0) {
            VOID *opt_copy = alloc_pool(opt_sz);
            if (opt_copy) {
                memcpy(opt_copy, data + opt_off, opt_sz);
                child_li->LoadOptions     = opt_copy;
                child_li->LoadOptionsSize = (UINT32)opt_sz;
            }
        }
        if (gST && gST->ConOut) {
            gST->ConOut->SetAttribute(gST->ConOut, EFI_TEXT_ATTR(EFI_LIGHTGRAY, EFI_BACKGROUND_BLACK));
            gST->ConOut->ClearScreen(gST->ConOut);
            if (gST->ConOut->EnableCursor) gST->ConOut->EnableCursor(gST->ConOut, TRUE);
        }
        UINTN exit_sz = 0;
        CHAR16 *exit_data = NULL;
        st = gBS->StartImage(child_img, &exit_sz, &exit_data);
        if (exit_data) free_pool(exit_data);
        free_pool(data);
        ui_force_redraw();
        if (EFI_ERROR(st) && err_out) {
            snprintf_ascii(err_out, max_err, "Boot%04X StartImage returned: %s",
                           (UINT32)boot_num, efi_status_str(st));
        }
        return st;
    }

    /* 2. Fallback: Expand short-form HD(Part,GPT,Guid)\FilePath across mounted FAT/ESP volumes! */
    BOOLEAN has_gpt_sig = FALSE;
    UINT8   gpt_sig[16];
    CHAR16  fpath_w[160];
    fpath_w[0] = 0;

    UINTN cur = 0;
    const UINT8 *dp_raw = (const UINT8 *)dp;
    while (cur + 4 <= dp_len) {
        UINT8 ntype = dp_raw[cur];
        UINT8 nsub  = dp_raw[cur + 1];
        UINT16 nlen = (UINT16)dp_raw[cur + 2] | ((UINT16)dp_raw[cur + 3] << 8);
        if (nlen < 4 || cur + nlen > dp_len || ntype == 0x7FU) break;
        if (ntype == 0x04U && nsub == 0x01U && nlen >= 42U && dp_raw[cur + 41] == 0x02U) {
            memcpy(gpt_sig, dp_raw + cur + 24, 16);
            has_gpt_sig = TRUE;
        } else if (ntype == 0x04U && nsub == 0x04U && nlen > 4U) {
            CHAR16 seg[128];
            UINTN wc = (nlen - 4U) / sizeof(CHAR16);
            if (wc >= 128U) wc = 127U;
            memcpy(seg, dp_raw + cur + 4, wc * sizeof(CHAR16));
            seg[wc] = 0;
            if (seg[0] != L'\\' && (fpath_w[0] == 0 || fpath_w[wstr_len(fpath_w) - 1] != L'\\')) {
                wstr_cat(fpath_w, L"\\", 160);
            }
            wstr_cat(fpath_w, seg, 160);
        }
        cur += nlen;
    }
    free_pool(data);

    if (fpath_w[0] == 0) {
        wstr_cpy(fpath_w, L"\\EFI\\BOOT\\BOOTX64.EFI", 160);
    }

    UINTN fs_cnt = 0;
    EFI_HANDLE *fs_handles = NULL;
    if (!EFI_ERROR(efi_locate_handles(&gEfiSimpleFileSystemProtocolGuid, &fs_cnt, &fs_handles)) && fs_handles) {
        for (UINTN pass = 0; pass < 2; pass++) {
            for (UINTN i = 0; i < fs_cnt; i++) {
                if (pass == 0 && (!has_gpt_sig || !fs_handle_matches_gpt_sig(fs_handles[i], gpt_sig))) {
                    continue;
                }
                EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *sfs = NULL;
                EFI_FILE_PROTOCOL *root = NULL;
                if (!EFI_ERROR(gBS->HandleProtocol(fs_handles[i], &gEfiSimpleFileSystemProtocolGuid, (VOID **)&sfs)) &&
                    sfs && !EFI_ERROR(sfs->OpenVolume(sfs, &root)) && root) {
                    BOOLEAN exists = check_file_exists(root, fpath_w);
                    root->Close(root);
                    if (exists) {
                        EFI_HANDLE target_fs = fs_handles[i];
                        free_pool(fs_handles);
                        st = nvram_chainload_efi(target_fs, fpath_w);
                        if (EFI_ERROR(st) && err_out) {
                            snprintf_ascii(err_out, max_err, "Chainload failed: %s", efi_status_str(st));
                        }
                        return st;
                    }
                }
            }
        }
        free_pool(fs_handles);
    }

    if (err_out) {
        snprintf_ascii(err_out, max_err,
            "Boot%04X is a firmware-internal / non-EFI boot target (%s). Select an .EFI bootloader instead.",
            (UINT32)boot_num, efi_status_str(st));
    }
    return EFI_ERROR(st) ? st : EFI_NOT_FOUND;
}

VOID nvram_boot_os_preserve_live_modal(const CHAR8 *modal_title) {
    nvram_scan_efi_bootloaders();

    CHAR8  obufs[66][80];
    const CHAR8 *opt_ptrs[66];
    INTN   kind[66];     /* 0 = loader, 1 = Boot####, 2 = custom browse */
    UINTN  ref_idx[66];
    UINTN  ocnt = 0;

    /* 1. List Auto-Discovered OS .EFI Bootloaders first (Windows, OpenCore, Linux, macOS) */
    for (UINTN i = 0; i < gSetup.loader_count && ocnt < 64; i++) {
        snprintf_ascii(obufs[ocnt], sizeof(obufs[ocnt]), "Chainload %s", gSetup.loaders[i].label);
        opt_ptrs[ocnt] = obufs[ocnt];
        kind[ocnt]     = 0;
        ref_idx[ocnt]  = i;
        ocnt++;
    }

    /* 2. List Installed UEFI Boot#### Entries (Direct LoadImage without Reset!) */
    for (UINTN i = 0; i < gSetup.boot_count && ocnt < 64; i++) {
        const BOOT_ENTRY_ITEM *be = &gSetup.boot_entries[i];
        /* Skip UEFI internal Setup/Shell pseudo-entries without file paths if loaders exist */
        snprintf_ascii(obufs[ocnt], sizeof(obufs[ocnt]),
                       "[Boot%04X] %s (No-Reset Direct Boot)",
                       (UINT32)be->boot_num, be->description);
        opt_ptrs[ocnt] = obufs[ocnt];
        kind[ocnt]     = 1;
        ref_idx[ocnt]  = i;
        ocnt++;
    }

    /* 3. Browse any mounted volume for custom .EFI file */
    str_cpy(obufs[ocnt], "[Browse] Select Any .EFI Bootloader File on Mounted Volumes...", sizeof(obufs[ocnt]));
    opt_ptrs[ocnt] = obufs[ocnt];
    kind[ocnt]     = 2;
    ref_idx[ocnt]  = 0;
    ocnt++;

    INTN sel = ui_select_modal(
        modal_title ? modal_title : "Boot OS Directly (Keep Temp Spoofs & Live Tweaks Active!)",
        opt_ptrs, ocnt, 0
    );
    if (sel < 0) return;

    /* Commit any staged NVRAM edits if user wants before handing off to OS */
    if (nvram_pending_changes_count() > 0) {
        if (ui_confirm_modal("Save Staged NVRAM Changes?",
                             "You also have staged NVRAM changes. Save them before booting OS?", TRUE)) {
            CHAR8 msg[96];
            nvram_commit_staged_changes(msg, sizeof(msg));
        }
    }

    if (kind[sel] == 0) {
        UINTN li = ref_idx[sel];
        EFI_STATUS st = nvram_chainload_efi(gSetup.loaders[li].fs_handle, gSetup.loaders[li].path_w);
        if (EFI_ERROR(st)) {
            CHAR8 err[96];
            snprintf_ascii(err, sizeof(err), "Chainload returned: %s", efi_status_str(st));
            ui_message_modal("Boot / Chainload Error", err, TRUE);
        }
    } else if (kind[sel] == 1) {
        UINTN bi = ref_idx[sel];
        CHAR8 err[160];
        err[0] = '\0';
        EFI_STATUS st = nvram_chainload_boot_entry(gSetup.boot_entries[bi].boot_num, err, sizeof(err));
        if (EFI_ERROR(st)) {
            ui_message_modal("Direct Boot#### Chainload Notice",
                             err[0] ? err : "Boot target returned to Setup.", TRUE);
        }
    } else {
        EFI_HANDLE fs_h = NULL;
        CHAR16 wp[128];
        if (nvram_browse_efi_file_interactive(&fs_h, wp, 128, NULL, 0)) {
            EFI_STATUS st = nvram_chainload_efi(fs_h, wp);
            if (EFI_ERROR(st)) {
                CHAR8 err[96];
                snprintf_ascii(err, sizeof(err), "Chainload returned: %s", efi_status_str(st));
                ui_message_modal("Boot / Chainload Error", err, TRUE);
            }
        }
    }
}
