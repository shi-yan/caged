#include <cxxopts.hpp>
#include <vector>
#include <string>
#include <sys/utsname.h>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

struct Config
{
    int socketFd;
};


bool setUidGid(const struct Config &config)
{
    std::cout << "trying a user namespace..." << std::endl;

    int has_userns = !unshare(CLONE_NEWUSER);

    if (write(config.socketFd, &has_userns, sizeof(has_userns)) != sizeof(has_userns))
    {
        std::cerr << "Faild to Communicate With Parent" << std::endl;
        return false;
    }
    std::cout << "send: " << has_userns << std::endl;
    int result = 0;
    if (read(config.socketFd, &result, sizeof(result)) != sizeof(result))
    {
        std::cerr << "couldn't read:" << std::endl;
        return -1;
    }
    /*if (result) return -1;
    if (has_userns) {
        fprintf(stderr, "done.\n");
    } else {
        fprintf(stderr, "unsupported? continuing.\n");
    }
    fprintf(stderr, "=> switching to uid %d / gid %d...", config->uid, config->uid);
    if (setgroups(1, & (gid_t) { config->uid }) ||
        setresgid(config->uid, config->uid, config->uid) ||
        setresuid(config->uid, config->uid, config->uid)) {
        fprintf(stderr, "%m\n");
        return -1;
    }
    fprintf(stderr, "done.\n");
    return 0;*/
    return true;


}

bool setChildProcessUidMap(pid_t childPid, int socketFd)
{
    int uid_map = 0;
    int has_userns = -1;
    if (read(socketFd, &has_userns, sizeof(has_userns)) != sizeof(has_userns))
    {
        std::cerr << "Couldn't read from child process" << std::endl;
        return false;
    }
    else
    {
        std::cout << "Read: " << has_userns << std::endl;

    }
    if (has_userns) {
        /*char path[PATH_MAX] = {0};
        for (char **file = (char *[]) { "uid_map", "gid_map", 0 }; *file; file++) {
            if (snprintf(path, sizeof(path), "/proc/%d/%s", child_pid, *file)
                > sizeof(path)) {
                fprintf(stderr, "snprintf too big? %m\n");
                return -1;
            }
            fprintf(stderr, "writing %s...", path);
            if ((uid_map = open(path, O_WRONLY)) == -1) {
                fprintf(stderr, "open failed: %m\n");
                return -1;
            }
            if (dprintf(uid_map, "0 %d %d\n", USERNS_OFFSET, USERNS_COUNT) == -1) {
                fprintf(stderr, "dprintf failed: %m\n");
                close(uid_map);
                return -1;
            }
            close(uid_map);
        }*/
    }
    /*if (write(fd, & (int) { 0 }, sizeof(int)) != sizeof(int)) {
        fprintf(stderr, "couldn't write: %m\n");
        return -1;
    }*/
    return true;
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

    struct Config config = *(struct Config *)arg;

    std::cout << "Subprocess PID: " << getpid() << " Parent PID: " << getppid() << std::endl;

    if (sethostname("caged", 5) == -1)
    {
        std::cerr << "Unable to set Hostname." << std::endl;
        return -1;
    }

    if (!setUidGid(config))
    {
        std::cerr << "Unable to set Uid Pid." << std::endl;
        return -1;
    }

    char * const argv[]{"/home/shiy/debug.sh", nullptr};

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
      ("r,root", "Root Filesystem", cxxopts::value<std::string>());

    std::string rootfs;
    std::string commandLine;

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

    struct Config config;

    config.socketFd = sockets[1];

    if (socketpair(AF_LOCAL, SOCK_SEQPACKET, 0, sockets) == -1) {
        std::cerr << "Failed to Create Socket Pair to Communicate With the Child Process: " << errno << std::endl;
        return 1;
    }

    if ((childPid = clone(child, stack + STACK_SIZE, flags | SIGCHLD, &config)) == -1)
    {
        std::cerr << "Process Launch Failed." << std::endl;
        return 1;
    }
    else
    {
        std::cout << "Parent Process PID: " << getpid() << " Child Process PID: " << childPid << std::endl;
    }

    //close(sockets[1]);
    //sockets[1] = 0;

    setChildProcessUidMap(childPid, sockets[0]);

    return 0;
}
