#ifndef _BASH_LISTENER_H_
#define _BASH_LISTENER_H_

#include <stdio.h>
#include <string>
#include <memory>
#include <vector>
#include <thread>
#include <array>
#include <functional>
#include <fstream>
#include <future>
#include <boost/asio.hpp>

using namespace std;
using namespace boost;
using Work = boost::asio::io_service::work;

namespace BL {


enum class Provider{
    UNIX,
    FILE
};

class DataCollector {
public:
    DataCollector(){}
    virtual ~DataCollector(){};
    virtual bool Init() = 0;
    virtual bool Run() = 0;
    virtual void Stop() = 0;
    virtual bool PostData(string data) = 0;

    void Enable(int64_t uid);
    void Disable();

protected:
    bool  enable_ = false;
    int64_t uid_  = 0;
};

class HttpDataCollector : public DataCollector{
public:
    HttpDataCollector(string url): url_(std::move(url)){
        work_ = make_unique<Work>(service_);
    }
    ~HttpDataCollector() override {}
    bool Init() override;
    bool Run() override;
    void Stop() override;
    bool PostData(string data) override;
    
private:
    bool PostDataTls(string data);

private:
    string url_;
    asio::io_service  service_;
    unique_ptr<Work>  work_;
    ofstream          ofs_;
    vector<string>    data_keys_;
    vector<string>    send_keys_;
};

class BashListener {

public:
    BashListener(const string &path, function<void(string data, int err)> cb):path_(path), read_cb_(cb){
    }

    virtual ~BashListener(){};

    virtual bool Init() = 0;
    virtual bool Run() = 0;
    virtual void Stop() = 0;

protected:
    string path_;
    std::function<void(string data, int err)> read_cb_;
};

class UnixBashListener : public BashListener {

public:

    UnixBashListener(const string &path, function<void(string data, int err)> cb);
    ~UnixBashListener();

    bool Init() override;
    bool Run() override;
    void Stop() override;

private:
    void HandleReceiveFrom(const boost::system::error_code& error,
                            size_t bytes_recvd);

private:
    asio::io_service             listen_service_;
    unique_ptr<Work>             listen_work_;
    asio::local::datagram_protocol::endpoint listen_ep_;
    unique_ptr<asio::local::datagram_protocol::socket>   sock_;
    asio::local::datagram_protocol::endpoint sender_endpoint_;
    enum { max_length = 1024 };
    char data_[max_length];
};

class UserManager {

    enum class AUTH_STATUS {
        SUCCESS = 0,
        FAILED, 
        UNKNOWN
    }; 
public:
    UserManager(){}
    ~UserManager(){}

    void StartAuthRoutine(std::function<void(bool enable)> cb);
    void Stop();
    inline int64_t GetUid() const {
        return uid_;
    }

private:
    AUTH_STATUS PostAuthReq();
private:
    std::promise<int> pro_;
    std::future<int> fut_;
    int64_t          uid_;
    volatile bool    cur_state_ = false;
    volatile bool    stop_ = false;
    int64_t          expired_ts_ = 0;
};

class BashCore {

public:
    BashCore(){}

    bool Init(Provider provider = Provider::UNIX, const string &path = "/tmp/bash_promt.sock");
    bool Run(std::function<void(bool enable, int64_t uid)> cb);
    bool Stop();
    void WaitForShutdown();
    virtual ~BashCore(){}

private:
    void BashCb(const string &data, int err);

private:
    unique_ptr<BashListener>  bash_listener_;
    unique_ptr<DataCollector> data_collector_;
    UserManager               user_manager_;
    std::future<bool>         data_collector_fut_;
    std::future<bool>         bash_fut_;
};

}

#endif
