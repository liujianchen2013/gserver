#include "zeromq_unit.h"

#include <iostream>

ZeroMqUnit::ZeroMqUnit(const std::string& identify, SocketType socket_type)
    : identify_(identify), socket_type_(socket_type) {
    zmq_ctx_ = zmq_ctx_new();
}

ZeroMqUnit::~ZeroMqUnit() {
    if (zmq_sock_) {
        zmq_close(zmq_sock_);
        zmq_sock_ = nullptr;
    }
    zmq_ctx_term(zmq_ctx_);
    zmq_ctx_ = nullptr;
}

bool ZeroMqUnit::Bind(const std::string& addr) {
    if (!InitSock()) {
        return false;
    }

    if (zmq_bind(zmq_sock_, addr.c_str()) != 0) {
        return false;
    }

    // return BindEvent();
    return true;
}

bool ZeroMqUnit::Connect(const std::string& addr) {
    if (!InitSock()) {
        return false;
    }

    if (zmq_connect(zmq_sock_, addr.c_str()) != 0) {
        return false;
    }

    // return BindEvent();
    return true;
}

bool ZeroMqUnit::InitSock() {
    if (zmq_sock_) {
        zmq_close(zmq_sock_);
    }

    zmq_sock_ = zmq_socket(zmq_ctx_, int32_t(socket_type_));
    if (!zmq_sock_) {
        return false;
    }

    if (zmq_setsockopt(zmq_sock_, ZMQ_ROUTING_ID, identify_.c_str(), identify_.size()) != 0) {
        return false;
    }

    return true;
}

// bool ZeroMqUnit::BindEvent() {
//     event* ev = event_new(
//         ev_base_, GetSockFd(), EV_READ | EV_PERSIST, [](int, short, void* arg) {
//             reinterpret_cast<ZeroMqUnit*>(arg)->OnEvent();
//         },
//         this);

//     if (!ev || event_add(ev, nullptr) != 0) {
//         return false;
//     }

//     return true;
// }

int32_t ZeroMqUnit::GetSockFd() {
    if (!zmq_sock_) {
        return 0;
    }
    int32_t fd = -1;
    size_t fd_len = sizeof(fd);
    zmq_getsockopt(zmq_sock_, ZMQ_FD, &fd, &fd_len);
    return fd;
}

int32_t ZeroMqUnit::Send(const std::string& data, const std::string& dst_identify) {
    if (Send(dst_identify, true) == -1) {
        return -1;
    }
    return Send(data);
}

int32_t ZeroMqUnit::Send(const std::string& data, bool send_more /* = false */) {
    return Send(data.c_str(), data.size(), send_more);
}

int32_t ZeroMqUnit::Send(const void* data, size_t data_len, bool send_more/*  = false */) {
    return zmq_send(zmq_sock_, data, data_len, send_more ? ZMQ_SNDMORE : 0);
}

int32_t ZeroMqUnit::Recv(std::string& buff) {
    return ZeroMqUnit::Recv(zmq_sock_, buff);
}

int32_t ZeroMqUnit::Recv(void* sock, std::string& buff) {
    zmq_msg_t msg;
    int32_t ret = zmq_msg_init(&msg);
    if (ret != 0) {
        return ret;
    }
    ret = zmq_msg_recv(&msg, sock, ZMQ_NOBLOCK);
    if (ret <= 0) {
        zmq_msg_close(&msg);
        return ret;
    }

    char* data = (char*)zmq_msg_data(&msg);
    size_t len = zmq_msg_size(&msg);
    buff.assign(data, len);
    zmq_msg_close(&msg);
    return ret;
}

void ZeroMqUnit::OnEvent() {
    uint32_t events = 0;
    size_t len = sizeof(events);
    zmq_getsockopt(zmq_sock_, ZMQ_EVENTS, &events, &len);
    if(event_func_) {
        event_func_(this, events);
    }
    // if (events & ZMQ_POLLIN) {
    //     int more = 0;
    //     size_t more_size = sizeof(more);
    //     while (true) {
    //         std::string data;
    //         if (Recv(data) <= 0) {
    //             break;
    //         }
    //         if (zmq_getsockopt(zmq_sock_, ZMQ_RCVMORE, &more, &more_size) != 0 || more > 0) {
    //             std::cout << "data:" << data << std::endl;
    //             continue;
    //         }
    //         // 处理数据
    //         if(onDataFun_) {
    //             onDataFun_(data);
    //         }
    //     }
    // }
}