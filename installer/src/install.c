#include "common.h"
#include "oob_entry.h"
#include "util.h"

int create_file(const char *path, mode_t mode, uid_t uid, gid_t gid) {
    if (access(path, F_OK) == 0) {
        if (chmod(path, mode) != 0) return -1;
        if (chown(path, uid, gid) != 0) return -1;
        sync();
        return 0;
    }

    int fd = open(path, O_RDWR|O_CREAT);
    if (fd == -1) return -1;
    close(fd);
    sync();

    if (chmod(path, mode) != 0) return -1;
    if (chown(path, uid, gid) != 0) return -1;
    sync();
    return 0;
}

int set_file_permissions(const char *path, mode_t mode, uid_t uid, gid_t gid) {
    if (access(path, F_OK) != 0) return -1;
    if (chmod(path, mode) != 0) return -1;
    if (chown(path, uid, gid) != 0) return -1;
    sync();
    return 0;
}

void *load_file(const char *path, size_t *size) {
    int fd = open(path, O_RDONLY);
    if (fd == -1) return NULL;

    *size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    void *data = mmap(NULL, *size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (data == MAP_FAILED) {
        *size = 0;
        return NULL;
    }
    return data;
}

char *get_hw_model(void) {
    size_t size = 0;
    sysctlbyname("hw.model", NULL, &size, NULL, 0);
    char *model = calloc(1, size+1);
    sysctlbyname("hw.model", model, &size, NULL, 0);
    return model;
}

int edit_plist(const char *path, void (^action)(CFMutableDictionaryRef plist)) {
    size_t size = 0;
    void *data = load_file(path, &size);
    if (data == NULL) return -1;

    if (size < 8) {
        munmap(data, size);
        return -1;
    }

    CFDataRef cf_data = CFDataCreate(NULL, data, size);
    CFPropertyListFormat format = kCFPropertyListXMLFormat_v1_0;
    bool use_bplist = false;

    if (strncmp((char *)data, "bplist00", strlen("bplist00")) == 0) {
        format = kCFPropertyListBinaryFormat_v1_0;
        use_bplist = true;
    }

    munmap(data, size);
    CFMutableDictionaryRef dict = (CFMutableDictionaryRef)CFPropertyListCreateWithData(NULL, cf_data, kCFPropertyListMutableContainersAndLeaves, &format, NULL);
    if (dict == NULL) {
        CFRelease(cf_data);
        return -1;
    }

    action(dict);
    FILE *file = fopen(path, "wb+");

    if (file != NULL) {
        CFDataRef plist_data = NULL;
        if (use_bplist) {
            plist_data = CFPropertyListCreateData(NULL, dict, kCFPropertyListBinaryFormat_v1_0, 0, NULL);
        } else {
            plist_data = CFPropertyListCreateData(NULL, dict, kCFPropertyListXMLFormat_v1_0, 0, NULL);
        }

        if (plist_data != NULL) {
            fwrite((void *)CFDataGetBytePtr(plist_data), CFDataGetLength(plist_data), 1, file);
            fflush(file);
            CFRelease(plist_data);
        }

        fclose(file);
        sync();
    }

    CFRelease(cf_data);
    CFRelease(dict);
    return 0;
}

int launchctl_unsetenv(void) {
    char **args = calloc(1, sizeof(char *) * 4);
    args[0] = "/bin/launchctl";
    args[1] = "unsetenv";
    args[2] = "DYLD_INSERT_LIBRARIES";
    args[3] = NULL;

    pid_t pid = -1;
    int status = -1;
    int rv = posix_spawn(&pid, "/bin/launchctl", NULL, NULL, args, NULL);
    if (rv != 0 || pid == -1) goto done;

    do { if (waitpid(pid, &status, 0) == -1) goto done; }
    while (!WIFEXITED(status) && !WIFSIGNALED(status));

    done:
    free(args);
    return status;
}

int run_tar(const char *tar_path, const char *output_path) {
    char **args = calloc(1, sizeof(char *) * 9);
    args[0] = "/bin/tar";
    args[1] = "-xf";
    args[2] = (char *)tar_path;
    args[3] = "-C";
    args[4] = (char *)output_path;
    args[5] = "--preserve-permissions";
    args[6] = "--no-overwrite-dir";
    args[7] = NULL;

    pid_t pid = -1;
    int status = -1;
    int rv = posix_spawn(&pid, "/bin/tar", NULL, NULL, args, NULL);
    if (rv != 0 || pid == -1) goto done;

    do { if (waitpid(pid, &status, 0) == -1) goto done; }
    while (!WIFEXITED(status) && !WIFSIGNALED(status));

    done:
    free(args);
    return status;
}

int clear_mobile_installation_cache(void) {
    if (access("/var/mobile/Library/Caches/com.apple.mobile.installation.plist", F_OK) == 0) {
        unlink("/var/mobile/Library/Caches/com.apple.mobile.installation.plist");
        sync();
    }

    DIR *dir = opendir("/var/mobile/Library/Caches");
    if (dir == NULL) return 1;
    struct dirent *entry = NULL;

    while ((entry = readdir(dir)) != NULL) {
        char *item = (char *)(entry->d_name);
        if (strncmp(item, "com.apple.LaunchServices", strlen("com.apple.LaunchServices")) == 0) {
            if (strstr(item, ".csstore") != NULL) {
                char *full_path = calloc(1, PATH_MAX);
                snprintf(full_path, PATH_MAX, "/var/mobile/Library/Caches/%s", item);
                unlink(full_path);
                free(full_path);
                sync();
            }
        }
    }

    closedir(dir);
    return 0;
}

int show_non_default_apps(void) {
    char *model = get_hw_model();
    char path_buf[PATH_MAX] = {0};
    snprintf(path_buf, PATH_MAX-1, "/System/Library/CoreServices/SpringBoard.app/%s.plist", model);
    free(model);

    edit_plist(path_buf,  ^void (CFMutableDictionaryRef dict) {
        CFMutableDictionaryRef capabilities = (CFMutableDictionaryRef)CFDictionaryGetValue(dict, CFSTR("capabilities"));
        if (capabilities == NULL) {
            CFMutableDictionaryRef temp = CFDictionaryCreateMutable(NULL, 0, NULL, NULL);
            CFDictionaryAddValue(dict, CFSTR("capabilities"), temp);
            capabilities = (CFMutableDictionaryRef)CFDictionaryGetValue(dict, CFSTR("capabilities"));
            if (capabilities == NULL) return;
        }

        CFDictionaryAddValue(capabilities, CFSTR("hide-non-default-apps"), kCFBooleanFalse);
    });

    edit_plist("/var/mobile/Library/Preferences/com.apple.springboard.plist",  ^void (CFMutableDictionaryRef dict) {
        CFDictionaryAddValue(dict, CFSTR("SBShowNonDefaultSystemApps"), kCFBooleanTrue);
    });

    usleep(100000);
    return 0;
}

int install_jailbreak(void) {
    bool no_bootstrap_install = false;
    if (access("/.aquila_installed", F_OK) == 0 ||
        access("/Applications/Cydia.app/Cydia", F_OK) == 0 ||
        access("/.cydia_no_stash", F_OK) == 0) no_bootstrap_install = true;

    launchctl_unsetenv();
    chmod("/private", 0755);
    chmod("/private/var", 0755);

    set_file_permissions("/private/var/mobile", 0755, 501, 501);
    set_file_permissions("/private/var/mobile/Library", 0755, 501, 501);
    set_file_permissions("/private/var/mobile/Library/Preferences", 0755, 501, 501);
    set_file_permissions("/bin/tar", 0755, 0, 0);
    set_file_permissions("/private/var/aquila/aquila", 0755, 0, 0);
    set_file_permissions("/private/var/aquila/_libmis.dylib", 0755, 0, 0);
    set_file_permissions("/private/var/aquila/bootstrap.tar", 0777, 501, 501);

    if (!no_bootstrap_install) {
        set_file_permissions("/private/var/aquila/bootstrap.tar", 0777, 501, 501);
        run_tar("/private/var/aquila/bootstrap.tar", "/");
        print_log("[*] bootstrap installed\n");
    } else {
        unlink("/private/var/aquila/bootstrap.tar");
    }

    clear_mobile_installation_cache();
    show_non_default_apps();
    print_log("[*] non default apps set\n");

    create_file("/.aquila_installed", 0644, 0, 0);
    if (!no_bootstrap_install) {
        create_file("/.cydia_no_stash", 0644, 0, 0);
    }

    DIR *dir = opendir("Library/LaunchDaemons");
    if (dir != NULL) {
        struct dirent *entry = NULL;
        char path_buf[PATH_MAX] = {0};

        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
            if (strstr(entry->d_name, ".plist") == NULL) continue;

            bzero(path_buf, PATH_MAX);
            snprintf(path_buf, PATH_MAX, "/Library/LaunchDaemons/%s", entry->d_name);

            chmod(path_buf, 0644);
            chown(path_buf, 0, 0);
        }

        closedir(dir);
        sync();
    }

    FILE *file = fopen("/etc/launchd.conf", "wb+");
    if (file == NULL) return -1;
    fprintf(file, "unload /System/Library/LaunchDaemons/com.apple.MobileFileIntegrity.plist\n");
    fprintf(file, "bsexec .. /sbin/mount -u -o rw,suid,dev /\n");
    fprintf(file, "setenv DYLD_INSERT_LIBRARIES /private/var/aquila/_libmis.dylib\n");
    fprintf(file, "load /System/Library/LaunchDaemons/com.apple.MobileFileIntegrity.plist\n");
    fprintf(file, "bsexec .. /private/var/aquila/aquila\n");
    fprintf(file, "unsetenv DYLD_INSERT_LIBRARIES\n");

    fflush(file);
    fclose(file);
    set_file_permissions("/etc/launchd.conf", 0644, 0, 0);

    file = fopen("/etc/fstab", "wb+");
    if (file == NULL) return -1;
    fprintf(file, "/dev/disk0s1s1 / hfs rw 0 1\n");
    fprintf(file, "/dev/disk0s1s2 /private/var hfs rw 0 2\n");

    fflush(file);
    fclose(file);
    set_file_permissions("/etc/launchd.conf", 0644, 0, 0);

    unlink("/Library/Logs/CrashReporter/Baseband");
    unlink("/private/var/aquila/splashscreen.jp2");
    sync();
    return 0;
}
