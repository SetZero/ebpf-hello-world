#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/capability.h>
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
#include <map>
#include <thread>
#include <chrono>
#include <ranges>

extern "C"
{
#include "hello.skel.h"
#include "bpf/map.h"
}

[[nodiscard]] bool isPrivileged() noexcept
{
    const auto cap = cap_get_proc();
    cap_flag_value_t v;
    /*CAP_SYS_ADMIN, CAP_BPF, CAP_NET_ADMIN, CAP_PEFMON */
    cap_get_flag(cap, CAP_SYS_ADMIN, CAP_EFFECTIVE, &v);
    return v == 1;
}

class EbpfLoader
{
public:
    EbpfLoader()
    {
        if (!isPrivileged())
        {
            throw std::runtime_error("You need CAP_SYS_ADMIN to execute bpf()");
        }

        // starting froom 5.11 this is not required anymore
        // https://lore.kernel.org/bpf/20201201215900.3569844-1-guro@fb.com/t/#u
        static constexpr rlimit rlim = {
            .rlim_cur = 512UL << 20,
            .rlim_max = 512UL << 20,
        };

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

        
    }

    ~EbpfLoader() noexcept
    {
        if (mEbpfObj != nullptr)
            hello_bpf__destroy(mEbpfObj);
    }

    [[noreturn]] void run() {
        while (true) {
            auto fd = bpf_map__fd(mEbpfObj->maps.execs);
            read_execs(fd);
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }

    [[nodiscard]] constexpr const std::map<pid_t, event>& getProcs() const noexcept {
        return mProc;
    }

    EbpfLoader(const EbpfLoader &other) = delete;
    EbpfLoader(const EbpfLoader &&other) = delete;
    EbpfLoader &operator=(const EbpfLoader &other) = delete;
    EbpfLoader &operator=(const EbpfLoader &&other) = delete;

private:
    void read_execs(const int fd) {
        std::lock_guard<std::mutex> lock(mMapMutex);

        pid_t lookup_key = 0;
        pid_t next_key = 0;
	    event ev;

        while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
            handle_error(bpf_map_lookup_elem(fd, &next_key, &ev), "map lookup element");
            mProc[ev.pid] = ev;
            lookup_key = next_key;
        }
    }

    void handle_error(int statusCode, const std::string &command) const
    {
        if (statusCode != 0)
        {
            std::stringstream ss;
            ss << "Failed to " << command << ": " << statusCode;
            throw std::runtime_error(ss.str());
        }
    }

    hello_bpf *mEbpfObj = nullptr;
    std::map<pid_t, event> mProc;
    mutable std::mutex mMapMutex;
};

int main()
{
    namespace rv = std::ranges::views;

    std::cout << "Starting eBPF Demo\n";
    try
    {
        EbpfLoader loader;
        std::thread th([&loader]{
            loader.run();
        });

        while(true) {
            std::cout << "=== [ Processes (" << loader.getProcs().size() << ") ] ===\n";
            for (const auto & [_, proc] : loader.getProcs() | rv::take(10)) {
                std::cout << proc.pid << " - " << proc.comm << " - " << proc.uid << '\n';
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        th.join();
    }
    catch (std::runtime_error &e)
    {
        std::cerr << "Error: " << e.what() << '\n';
    }
}