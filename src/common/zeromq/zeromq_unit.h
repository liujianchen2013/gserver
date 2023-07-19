#pragma once
#include <zmq.h>

#include "common/type_define.h"

enum class SocketType {
    kDealer = ZMQ_DEALER,
    kRouter = ZMQ_ROUTER
};

class ZeroMqUnit {
public:
    using EventFunc = std::function<void(ZeroMqUnit*, uint32_t)>;

    ZeroMqUnit(const std::string& identify, SocketType socket_type);
    ~ZeroMqUnit();

    bool Bind(const std::string& addr);
    bool Connect(const std::string& addr);

    void SetEventFunc(EventFunc fun) { event_func_ = fun; }

    int32_t Send(const std::string& data, const std::string& dst_identify);
    int32_t Send(const std::string& data, bool send_more = false);
    int32_t Send(const void* data, size_t data_len, bool send_more = false);
    int32_t Recv(std::string& buff);

    void* ZmqSock() const { return zmq_sock_; }
    void OnEvent();
    int32_t GetSockFd();

    static bool HasPollIn(uint32_t events) { return events & ZMQ_POLLIN; }

private:
    bool InitSock();
    // bool BindEvent();
    static int32_t Recv(void* sock, std::string& buff);

private:
    std::string identify_;
    SocketType socket_type_;
    void* zmq_ctx_ = nullptr;
    void* zmq_sock_ = nullptr;
    EventFunc event_func_ = nullptr;
};