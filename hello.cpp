#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <string>
#include <stdexcept>
#include <bpf/bpf.h>

extern "C"
{
#include "hello.skel.h"
#include <bpf/libbpf.h>
}

struct hello_bpf *obj;
int err = 0;

class EbpfLoader
{
public:
    EbpfLoader()
    {
        mEbpfObj = hello_bpf__open();
        if (!mEbpfObj)
        {
            throw std::runtime_error("Failed to open hello bpf");
        }
        handle_error(hello_bpf__load(mEbpfObj), "load hello bpf");
        handle_error(hello_bpf__attach(mEbpfObj), "attach hello bpf");
    }

    void handle_error(int statusCode, const std::string &command)
    {
        if (!statusCode)
        {
            throw std::runtime_error("Failed to " + command);
        }
    }

    ~EbpfLoader()
    {
        hello_bpf__destroy(mEbpfObj);
    }

private:
    hello_bpf *mEbpfObj;
};

int main()
{
    EbpfLoader loader;
}