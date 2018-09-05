#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <cxxopts.hpp>
#include <vector>
#include <string>
#include <sys/utsname.h>
#include <sched.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/capability.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <grp.h>
#include <iostream>
#include <fstream>
#include <sys/mount.h>
#include <linux/unistd.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <stdio.h>
#include <sched.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/capability.h>
#include <sys/prctl.h>
#include <seccomp.h>

struct Config
{
    int socketFd;
    int other;
    uid_t uid;
    std::string root;
    std::string command;
    std::string output;

    bool hasOutput;
};

int pivot_root(const char *new_root, const char *put_old)
{
    return syscall(SYS_pivot_root, new_root, put_old);
}

#define USERNS_OFFSET 10000
#define USERNS_COUNT 2000

bool setUidGid(const struct Config *config)
{
    close(config->other);
    std::cout << "trying a user namespace..." << std::endl;

    int has_userns = !unshare(CLONE_NEWUSER);


    if (write(config->socketFd, &has_userns, sizeof(has_userns)) != sizeof (has_userns))
    {
        std::cerr << "Faild to Communicate With Parent" << std::endl;
        return false;
    }
    std::cout << "send: " << has_userns << std::endl;
    int result = -1;
    if (read(config->socketFd, &result, sizeof(result)) != sizeof (result))
    {
        std::cerr << "couldn't read:" << std::endl;
        return false;
    }
    else
    {
        std::cout << "read some" << std::endl;
    }

    if (result != 1)
    {
        return false;
    }

    close(config->socketFd);

    if (!has_userns)
    {
        std::cerr << "Config uid/gid is unsupported?" << std::endl;
    }

    std::cerr << "Switching to uid " << config->uid << " / gid " << config->uid << "..." << std::endl;

    gid_t gid{ config->uid };
    if (setgroups(1, &gid) ||
        setresgid(config->uid, config->uid, config->uid) ||
        setresuid(config->uid, config->uid, config->uid))
    {
        std::cerr << "Child process failed to config uid/gid." << std::endl;
        return false;
    }

    std::cout << "Uid/gid config done.";
    return true;
}

bool setChildProcessUidMap(pid_t childPid, int socketFd)
{
    int has_userns = -1;
    std::cout << "parent set uid" << std::endl;

    if (read(socketFd, &has_userns, sizeof(has_userns)) != sizeof(has_userns) )
    {
        std::cerr << "Couldn't read from child process" << std::endl;
        std::cerr << "Couldn't read from child process" << std::endl;
        std::cerr << "Couldn't read from child process" << std::endl;
        return false;
    }
    else
    {
        std::cout << "Read: " << has_userns << std::endl;
        std::cout << "Read: " << has_userns << std::endl;
        std::cout << "Read: " << has_userns << std::endl;

    }

    if (has_userns)
    {
        std::ofstream uidOutput;
        std::ofstream gidOutput;

        try
        {
            uidOutput.open(std::string{"/proc/"} + std::to_string(childPid) + "/uid_map");
            uidOutput << "0 " << USERNS_OFFSET << " " << USERNS_COUNT << std::endl;
            gidOutput.open(std::string{"/proc/"} + std::to_string(childPid) + "/gid_map");
            gidOutput << "0 " << USERNS_OFFSET << " " << USERNS_COUNT << std::endl;
        }
        catch (std::ifstream::failure e)
        {
            std::cout << "Unable to config the uid/gid files." << std::endl;
        }

        uidOutput.close();
        gidOutput.close();
    }

    int dummy = 1;
    std::cout << "set uid" << std::endl;
    if (write(socketFd, &dummy, sizeof(dummy)) != sizeof(dummy))
    {
        std::cerr << "couldn't write: " << std::endl;
        return false;
    }
    else
    {
        std::cerr << "write" << std::endl;
    }
    close(socketFd);
    return true;
}

bool mount(const struct Config *config)
{
    fprintf(stderr, "=> remounting everything with MS_PRIVATE...\n");
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
        fprintf(stderr, "failed! %m\n");
        return false;
    }
    fprintf(stderr, "remounted.\n");

    fprintf(stderr, "=> making a temp directory and a bind mount there...\n");
    char mount_dir[] = "/tmp/tmp.XXXXXX";
    if (!mkdtemp(mount_dir)) {
        fprintf(stderr, "failed making a directory!\n");
        return false;
    }

    if (mount(config->root.c_str(), mount_dir, NULL, MS_BIND | MS_PRIVATE | MS_RDONLY, NULL))
    {
        fprintf(stderr, "bind mount failed!\n");
        return false;
    }

    char inner_mount_dir[] = "/tmp/tmp.XXXXXX/oldroot.XXXXXX";
    memcpy(inner_mount_dir, mount_dir, sizeof(mount_dir) - 1);
    if (!mkdtemp(inner_mount_dir))
    {
        fprintf(stderr, "failed making the inner directory!\n");
        return false;
    }

    if (config->hasOutput)
    {
        fprintf(stderr, "=> making a temp build directory and a bind mount there...\n");

        std::string outputMountFolder = mount_dir;
        outputMountFolder.append(config->output);

        if (mkdir(outputMountFolder.c_str(), ACCESSPERMS))
        {
            if (errno != EEXIST)
            {
                fprintf(stderr, "failed making the inner build directory! %s\n", strerror(errno));
                return false;
            }
        }

        if (mount(config->output.c_str(), outputMountFolder.c_str(), NULL, MS_BIND | MS_PRIVATE , NULL))
        {
            fprintf(stderr, "bind mount build folder failed! (%s, %s)\n", strerror(errno), outputMountFolder.c_str());
            return false;
        }

        if (chmod( outputMountFolder.c_str(), ACCESSPERMS))
        {
            fprintf(stderr, "failed to change the permission of the build directory! %s\n", strerror(errno));
            return false;
        }
    }

    fprintf(stderr, "=> pivoting root...");
    if (pivot_root(mount_dir, inner_mount_dir)) {
        fprintf(stderr, "failed!\n");
        return false;
    }
    fprintf(stderr, "done.\n");

    char *old_root_dir = basename(inner_mount_dir);
    char old_root[sizeof(inner_mount_dir) + 1] = { "/" };
    strcpy(&old_root[1], old_root_dir);

    fprintf(stderr, "=> unmounting %s...", old_root);
    if (chdir("/")) {
        fprintf(stderr, "chdir failed! %m\n");
        return false;
    }
    if (umount2(old_root, MNT_DETACH)) {
        fprintf(stderr, "umount failed! %m\n");
        return false;
    }
    if (rmdir(old_root)) {
        fprintf(stderr, "rmdir failed! %m\n");
        return false;
    }
    fprintf(stderr, "done.\n");
    return true;
}

int capabilities()
{
    fprintf(stderr, "=> dropping capabilities...");
    int drop_caps[] = {
        CAP_AUDIT_CONTROL,
        CAP_AUDIT_READ,
        CAP_AUDIT_WRITE,
        CAP_BLOCK_SUSPEND,
        CAP_DAC_READ_SEARCH,
        CAP_FSETID,
        CAP_IPC_LOCK,
        CAP_MAC_ADMIN,
        CAP_MAC_OVERRIDE,
        CAP_MKNOD,
        CAP_SETFCAP,
        CAP_SYSLOG,
        CAP_SYS_ADMIN,
        CAP_SYS_BOOT,
        CAP_SYS_MODULE,
        CAP_SYS_NICE,
        CAP_SYS_RAWIO,
        CAP_SYS_RESOURCE,
        CAP_SYS_TIME,
        CAP_WAKE_ALARM
    };
    size_t num_caps = sizeof(drop_caps) / sizeof(*drop_caps);
    fprintf(stderr, "bounding...");
    for (size_t i = 0; i < num_caps; i++) {
        if (prctl(PR_CAPBSET_DROP, drop_caps[i], 0, 0, 0)) {
            fprintf(stderr, "prctl failed: %m\n");
            return 1;
        }
    }
    fprintf(stderr, "inheritable...");
    cap_t caps = NULL;
    if (!(caps = cap_get_proc())
        || cap_set_flag(caps, CAP_INHERITABLE, num_caps, drop_caps, CAP_CLEAR)
        || cap_set_proc(caps)) {
        fprintf(stderr, "failed: %m\n");
        if (caps) cap_free(caps);
        return 1;
    }
    cap_free(caps);
    fprintf(stderr, "done.\n");
    return 0;
}

#define SCMP_FAIL SCMP_ACT_ERRNO(EPERM)

int syscalls()
{
    scmp_filter_ctx ctx = NULL;
    fprintf(stderr, "=> filtering syscalls...");
    if (!(ctx = seccomp_init(SCMP_ACT_ALLOW))
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(chmod), 1,
                SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID))
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(chmod), 1,
                SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID))
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmod), 1,
                SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID))
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmod), 1,
                SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID))
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmodat), 1,
                SCMP_A2(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID))
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmodat), 1,
                SCMP_A2(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID))
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(unshare), 1,
                SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER))
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(clone), 1,
                SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER))
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(ioctl), 1,
                SCMP_A1(SCMP_CMP_MASKED_EQ, TIOCSTI, TIOCSTI))
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(keyctl), 0)
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(add_key), 0)
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(request_key), 0)
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(ptrace), 0)
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(mbind), 0)
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(migrate_pages), 0)
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(move_pages), 0)
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(set_mempolicy), 0)
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(userfaultfd), 0)
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(perf_event_open), 0)
        || seccomp_attr_set(ctx, SCMP_FLTATR_CTL_NNP, 0)
        || seccomp_load(ctx)) {
        if (ctx) seccomp_release(ctx);
        fprintf(stderr, "failed: %m\n");
        return 1;
    }
    seccomp_release(ctx);
    fprintf(stderr, "done.\n");
    return 0;
}

int child(void *arg)
{
    /*struct child_config *config = arg;
    if (sethostname(config->hostname, strlen(config->hostname))
        || mounts(config)
        || userns(config)
        || capabilities()
        || syscalls()) {
        close(config->fd);
        return -1;
    }
    if (close(config->fd)) {
        fprintf(stderr, "close failed: %m\n");
        return -1;
    }
    if (execve(config->argv[0], config->argv, NULL)) {
        fprintf(stderr, "execve failed! %m.\n");
        return -1;
    }*/

    struct Config *config = (struct Config *)arg;

    std::cout << "config: "<< config->socketFd << config->other << std::endl;

    std::cout << "Subprocess PID: " << getpid() << " Parent PID: " << getppid() << std::endl;

    if (sethostname("caged", 5) == -1)
    {
        std::cerr << "Unable to set Hostname." << std::endl;
        return -1;
    }

    if (!mount(config))
    {
        std::cerr << "Unable to mount rootfs." << std::endl;
        return -1;
    }

    if (!setUidGid(config))
    {
        std::cerr << "Unable to set Uid Pid." << std::endl;
        return -1;
    }

    if ( capabilities() || syscalls())
    {
        return -1;
    }

    char * const cmd =(char*) config->command.c_str();
    char * const argv[]{cmd, nullptr};

    if (execve(argv[0], argv, nullptr) == -1)
    {
        std::cerr << "Unable to start process: " << errno << std::endl;
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    cxxopts::Options options("Caged", "Lightweight Linux Sandbox.");

    options.add_options()
      ("c,command", "Command to Run", cxxopts::value<std::string>())
      ("r,root", "Root Filesystem", cxxopts::value<std::string>())
      ("o,output", "Output Folder", cxxopts::value<std::string>());

    std::string rootfs;
    std::string commandLine;
    std::string outputFolder;
    struct Config config;
    config.hasOutput = false;

    try
    {
        auto result = options.parse(argc, argv);

        if (!result["root"].count())
        {
            std::cerr << "No Root Filesystem specified." << std::endl;
            return 1;
        }
        else
        {
            rootfs = result["root"].as<std::string>();
            std::cout << "Root Filesystem: " << rootfs << std::endl;
        }

        if (!result["command"].count())
        {
            std::cerr << "No Command to Run in the Sandbox." << std::endl;
            return 1;
        }
        else
        {
            commandLine = result["command"].as<std::string>();
            std::cout << "Commandline: " << commandLine << std::endl;
        }

        if (result["output"].count())
        {
            config.hasOutput = true;
            outputFolder = result["output"].as<std::string>();
            std::cout << "Output:" << outputFolder << std::endl;
        }
    }
    catch(const cxxopts::option_not_exists_exception &e)
    {
        std::cout << "Unable to Parse Option:" << std::endl;
        std::cout << e.what() << std::endl;
        return 1;
    }

    std::cerr << "validating Linux version..." << std::endl;
    struct utsname host{};

    if (uname(&host))
    {
        std::cerr << "Failed to get Linux Info." << std::endl;
        return 1;
    }
    else
    {
        std::cout << host.release << std::endl;
    }

    int major = -1;
    int minor = -1;

    std::cmatch linuxVersionMatch;
    std::regex linuxVersionRegExp("^([0-9]+).([0-9]+)");

    std::regex_search (host.release, linuxVersionMatch, linuxVersionRegExp);

    if (linuxVersionMatch.size() != 3)
    {
        std::cerr << "Unable to Parse Linux Version." << std::endl;
        return 1;
    }

    try
    {
        std::cout << "Major: " << (major = std::stoi(linuxVersionMatch[1].str())) << std::endl;
        std::cout << "Minor: " << (minor = std::stoi(linuxVersionMatch[2].str())) << std::endl;
    }
    catch(const std::invalid_argument &e)
    {
        std::cerr << "Unable to Parse Linux Version:" << e.what() << std::endl;
        return 1;
    }
    catch(const std::out_of_range &e)
    {
        std::cerr << "Unable to Parse Linux Version:" << e.what() << std::endl;
        return 1;
    }

    if (major != 4 || (minor < 7))
    {
        std::cerr << "Linux Version is Too Old." << std::endl;
        return 1;
    }

    std::cout << host.machine << std::endl;

    std::string machine = host.machine;
    if ("x86_64" != machine)
    {
        std::cerr << machine << " is Unsupported." << std::endl;
        return 1;
    }

    const unsigned int STACK_SIZE{1024 * 1024};
    char *stack = nullptr;
    if (!(stack = new char[STACK_SIZE]))
    {
        std::cerr << "Failed to Allocate Stack." << std::endl;
        return 1;
    }

    int flags{CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWUTS};

    int childPid{0};

    int sockets[2]{0};

    if (socketpair(AF_LOCAL, SOCK_SEQPACKET, 0, sockets) == -1) {
        std::cerr << "Failed to Create Socket Pair to Communicate With the Child Process: " << errno << std::endl;
        return 1;
    }

    std::cout << sockets[0] << sockets[1] << std::endl;

    config.socketFd = sockets[0];
    config.other = sockets[1];
    config.uid = 256;
    config.root = rootfs;
    config.command = commandLine;
    config.output = outputFolder;

    std::cout << "socket" << config.socketFd << config.other << std::endl;

    if ((childPid = clone(child, stack + STACK_SIZE, flags | SIGCHLD, &config)) == -1)
    {
        std::cerr << "Process Launch Failed." << std::endl;
        return 1;
    }
    else
    {
        std::cout << "Parent Process PID: " << getpid() << " Child Process PID: " << childPid << std::endl;
    }
    std::cout << "test1" << std::endl;

    close(sockets[0]);
    //sockets[0] = 0;

    setChildProcessUidMap(childPid, sockets[1]);

    close(sockets[1]);

    return 0;
}
