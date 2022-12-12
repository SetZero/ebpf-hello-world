#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <string>
#include <iostream>
#include <sstream>
#include <fstream>
#include <streambuf>
#include <stdexcept>

extern "C"
{
#include "hello.skel.h"
}

struct hello_bpf *obj;

static constexpr rlimit rlim = {
    .rlim_cur = 512UL << 20,
    .rlim_max = 512UL << 20,
};

class EbpfLoader
{
public:
    EbpfLoader()
    {
        handle_error(setrlimit(RLIMIT_MEMLOCK, &rlim), "set rlimit");

        mEbpfObj = hello_bpf__open();
        if (!mEbpfObj)
        {
            std::stringstream ss;
            ss << "Failed to open hello bpf: " << std::hex << mEbpfObj;
            throw std::runtime_error(ss.str());
        }

        handle_error(hello_bpf__load(mEbpfObj), "load hello bpf");
        handle_error(hello_bpf__attach(mEbpfObj), "attach hello bpf");
        read_trace_pipe();
    }

    ~EbpfLoader() noexcept
    {
        if (mEbpfObj != nullptr)
            hello_bpf__destroy(mEbpfObj);
    }

    EbpfLoader(const EbpfLoader &other) = delete;
    EbpfLoader(const EbpfLoader &&other) = delete;
    EbpfLoader &operator=(const EbpfLoader &other) = delete;
    EbpfLoader &operator=(const EbpfLoader &&other) = delete;

private:
    void handle_error(int statusCode, const std::string &command) const
    {
        if (statusCode != 0)
        {
            std::stringstream ss;
            ss << "Failed to " << command << ": " << statusCode;
            throw std::runtime_error(ss.str());
        }
    }

    void read_trace_pipe() const
    {
        std::ifstream file("/sys/kernel/debug/tracing/trace_pipe", std::ios::in);
        std::string line;

        while (std::getline(file, line))
        {
            std::istringstream iss(line);
            std::cout << iss.str() << '\n';
        }
    }

    hello_bpf *mEbpfObj = nullptr;
};

[[nodiscard]] bool isPrivileged() noexcept
{
    const auto uid = getuid();
    const auto euid = geteuid();
    return uid != euid || uid <= 0;
}

int main()
{
    if (isPrivileged())
    {
        EbpfLoader loader;
    }
    else
    {
        std::cerr << "You need root permissions to execute this: " << getuid() << " vs. " << geteuid() << '\n';
    }
}