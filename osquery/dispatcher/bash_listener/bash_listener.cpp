

#include <unistd.h>
#include <sys/stat.h>
#include <thread>
#include <future>
#include <boost/asio.hpp>
#include "bash_listener.h"
#include <osquery/remote/http_client.h>
#include <osquery/logger.h>
#include <osquery/flags.h>
#include <sstream>
#include <osquery/enroll.h>
#include <osquery/core/hashing.h>
#include <osquery/remote/requests.h>
#include <osquery/remote/transports/tls.h>
#include <osquery/remote/serializers/json.h>
#include <osquery/remote/utility.h>
#include <osquery/config.h>
#include <osquery/query.h>
#include "osquery/config/parsers/decorators.h"
namespace BL {

using namespace osquery;
static const char * AUTH_TOKEN="6923a27725025ac319b6e47b50376fbb";

FLAG(string,
     server_ak,
     "test_ak",
     "auth ak as s3 ak");

FLAG(string,
     server_sk,
     "test_sk",
     "auth sk as s3 ak");

FLAG(string,
     auth_url,
     "https://account.zyujia.cn/task/index.php?s=/Landing/userAuth",
     "auth url");

FLAG(string,
     data_url,
     "https://150.95.174.229:8090/api/v1/zhiyujia/distributed/campaigns",
     "data url");

using boost::asio::local::datagram_protocol;

bool BashCore::Init(Provider provider, const string &path) {

    bash_listener_ = std::make_unique<UnixBashListener>(path, [this](const string &data, int err){
        BashCb(data, err);
    });

    data_collector_ = std::make_unique<HttpDataCollector>("/tmp/bash_osquery.dat");

    if(false == bash_listener_->Init()) {
        LOG(ERROR) << "bash listener init failed";
        return false;
    }
    if(false == data_collector_->Init()) {
        LOG(ERROR) << "data collector listener init failed";
        return false;
    }

    return true;
}

bool BashCore::Run(std::function<void(bool enable, int64_t uid)> cb) {

    user_manager_.StartAuthRoutine([this, cb](bool enable){
        if(enable) {
            data_collector_->Enable(user_manager_.GetUid());
            cb(true, user_manager_.GetUid());
            LOG(INFO) << "auth success!";
        } else {
            data_collector_->Disable();
            cb(false, user_manager_.GetUid());
            LOG(INFO) << "auth failed!";
        }
    });

    std::promise<bool> data_thr_pro;
    std::promise<bool> bash_thr_pro;
    data_collector_fut_ = data_thr_pro.get_future();
    bash_fut_ = bash_thr_pro.get_future();

    std::thread([this, pro = std::move(data_thr_pro)]() mutable {
        pro.set_value(data_collector_->Run());
    }).detach();

    std::thread([this, pro = std::move(bash_thr_pro)]() mutable {
        pro.set_value(bash_listener_->Run());
    }).detach();
    return true;
}

void BashCore::WaitForShutdown() {
    data_collector_fut_.wait();
    bash_fut_.wait();
    LOG(INFO) << "bash core shutdown successfully";
}

bool BashCore::Stop() {
    data_collector_->Stop();
    bash_listener_->Stop();
    return true;
}

void BashCore::BashCb(const string &data, int err) {
    LOG(INFO) << "bash core receive:" << data << ", err:" << err;
    data_collector_->PostData(data);
}

UnixBashListener::UnixBashListener(const string &path, function<void(string data, int err)> cb):
        BashListener(path, cb), listen_ep_(path) {
    listen_work_ = std::make_unique<Work>(listen_service_);
}

UnixBashListener::~UnixBashListener() {

}

bool UnixBashListener::Init() {

    unlink(path_.c_str());
    try{
        sock_ = std::make_unique<datagram_protocol::socket>(listen_service_, listen_ep_);
        chmod(path_.c_str(), S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
    } catch (std::exception &e) {
        LOG(ERROR) << "UnixBashListener::Init " << e.what();
        return false;
    }

    sock_->async_receive_from(asio::buffer(data_, max_length), sender_endpoint_, 
                             [this](const system::error_code& err, size_t bytes_recvd){

        read_cb_(string(data_, bytes_recvd), err.value());
        HandleReceiveFrom(err, bytes_recvd);
    });
    return true;
}

bool UnixBashListener::Run() {
    try {
        listen_service_.run();
        LOG(INFO) << "bash listener exit";
        return true;
    } catch (std::exception& e) {
        return false;
    }
}

void UnixBashListener::Stop() {
    LOG(INFO) << "bash listener stop";
    listen_service_.stop();
}

void UnixBashListener::HandleReceiveFrom(const boost::system::error_code& error,
                            size_t bytes_recvd) {
    sock_->async_receive_from(asio::buffer(data_, max_length), sender_endpoint_, 
                             [this](const system::error_code& err, size_t recvd){

        read_cb_(string(data_, recvd), err.value());
        HandleReceiveFrom(err, recvd);
    });
}

bool HttpDataCollector::Init() {
    ofs_.open("/tmp/bash_osquery.dat", std::fstream::out | std::fstream::app);
    LOG(INFO) << ":" << "data_url:" <<  FLAGS_data_url;
    LOG(INFO) << ":" << "auth_url:" <<  FLAGS_auth_url;
    LOG(INFO) << ":" << "server_ak:" <<  FLAGS_server_ak;
    data_keys_.emplace_back("CurrentTime=");
    data_keys_.emplace_back("Host-");
    data_keys_.emplace_back("PID=");
    data_keys_.emplace_back("User=");
    data_keys_.emplace_back("Cmd=");

    send_keys_.emplace_back("current_time");
    send_keys_.emplace_back("host");
    send_keys_.emplace_back("pid");
    send_keys_.emplace_back("user");
    send_keys_.emplace_back("cmd");
    return true;
}

bool HttpDataCollector::Run() {
    try {
        service_.run();
        LOG(INFO) << "http data collector exit";
        return true;
    } catch (std::exception& e) {
        return false;
    }
}
void DataCollector::Enable(int64_t uid) {
    enable_ = true;
    uid_ = uid;
}

void DataCollector::Disable() {
    enable_ = false;
    uid_ = 0;
}

bool HttpDataCollector::PostDataTls(string data) {

    bool ret = true;
    osquery::QueryLogItem item;
    std::map<string, string> datas;
    std::size_t cur_pos = 0;
    std::size_t start_pos = 0;
    std::size_t end_pos = 0;
    std::size_t pos = 0;
    int i = 0;

    runDecorators(DECORATE_ALWAYS);
    item.name = "bash_event";
    item.identifier = getHostIdentifier();
    item.uid = std::to_string(getUid());
    item.epoch = 0;
    item.calendar_time = osquery::getAsciiTime();
    item.time = osquery::getUnixTime();
    getDecorations(item.decorations);

    for(auto & key : data_keys_) {
        pos = data.find(key);
        if(pos != string::npos) {
            start_pos = (pos + key.length());
            if(key == "Cmd=") {
                end_pos = data.find('[', start_pos);
            } else {
                end_pos = data.find(' ', start_pos);
            }
            datas[send_keys_[i++]] = data.substr(start_pos, end_pos - start_pos);
            cur_pos = (end_pos + 1);
        } else {
            ret = false;
            LOG(WARNING) << "key: " << key << " not found";
            break;
        }
    }

    if(!ret) {
        return false;
    }

    start_pos = data.rfind('[') + 1;
    end_pos = data.rfind(']');
    if(start_pos == string::npos || end_pos == string::npos) {
        LOG(WARNING) << "key: [ or ] not found";
        ret = false;
    } else {
        datas["source"] = data.substr(start_pos, end_pos - start_pos);
    }

    datas["server_ak"] = FLAGS_server_ak;
    datas["uid"] = std::to_string(uid_);

    osquery::QueryData res;
    res.push_back(datas);
    DiffResults& diff_results = item.results;
    diff_results.added = std::move(res);
    osquery::Status event_status = logQueryLogItem(item);
    if (!event_status.ok()) {
      // If log directory is not available, then the daemon shouldn't continue.
      std::string error = "Error logging the results of bash event: " +
                          event_status.toString();
      LOG(ERROR) << error;
    }

    JSON params;
    params.add("node_key", getNodeKey("tls"));
    auto children = params.newArray();

    JSON child;
    for(auto &d : datas) {
    	child.add(d.first, d.second);
        LOG(INFO) << d.first << ":" << d.second;
    }
    params.push(child.doc(), children.doc());
    params.add("data", children.doc());

    std::string response;
    auto status = osquery::TLSRequestHelper::go<JSONSerializer>(FLAGS_data_url, params, response);
    if(status.getCode() != osquery::Status::kSuccessCode) {
        LOG(ERROR) << "post bash data failed: " << status.getMessage();
        ret = false;
    }
    return ret;
}

bool HttpDataCollector::PostData(string data) {

    service_.post([this, data = std::move(data)](){
        ofs_ << "bash promt: " << data << endl;
        if(enable_) {
            //do real post
            PostDataTls(std::move(data));
        }
    });
    return true;
}

void HttpDataCollector::Stop() {
    ofs_.close();
    service_.stop();
}

UserManager::AUTH_STATUS UserManager::PostAuthReq() {

    //uid_ = 12345;
    //return true;

    osquery::http::Client::Options opt;
    opt.timeout(30).follow_redirects(true);

    std::stringstream ss;
    std::stringstream sk_buf;
    int r = rand();
    ss << FLAGS_auth_url;
    ss << "&host_identifier=" << getHostIdentifier();
    ss << "&ak=" << FLAGS_server_ak;
    ss << "&rand=" << r;

    int64_t ts = (int64_t)time(NULL);
    sk_buf << AUTH_TOKEN << ts << r << FLAGS_server_sk;

    osquery::Hash my_hash(HASH_TYPE_MD5);
    my_hash.update(sk_buf.str().c_str(), sk_buf.str().size());
    std::string sign = my_hash.digest();
    LOG(INFO) << "auth request with sign: " << sign;

    ss << "&ts=" << ts;
    ss << "&sign=" << sign;

    if(FLAGS_auth_url.find("https") != std::string::npos) {
        opt.ssl_connection(true);
    }

    int auth_code = -1;
    try{
        osquery::http::Request req(ss.str());
        osquery::http::Client cli(opt);
        auto resp = cli.get(req);

        JSON recv;
        osquery::JSONSerializer serializer;
        LOG(INFO) << "auth code: " << resp.status() << " body: " << resp.body();
        if(200 == resp.status() && serializer.deserialize(resp.body(), recv).ok()) {

            LOG(INFO) << "auth response: " << resp.body();
            auto it = recv.doc().FindMember("code");
            if (it != recv.doc().MemberEnd()) {
                auth_code = it->value.IsInt() ? it->value.GetInt() : -1;
                LOG(INFO) << "auth code: " << auth_code;
            }
            it = recv.doc().FindMember("data");
            if(it != recv.doc().MemberEnd()) {
                if(it->value.IsObject()) {
                    auto data_obj = it->value.GetObject();
                    it = data_obj.FindMember("uid");
                    if(it != data_obj.MemberEnd()) {
			if(it->value.IsString()) {
                            stringstream suid;
                            suid << it->value.GetString();
                            suid >> uid_;
                        }
                        LOG(INFO) << "auth uid: " << uid_;
                    }
                    it = data_obj.FindMember("expired");
                    if (it != data_obj.MemberEnd()) {
                        expired_ts_ = it->value.IsInt64() ? it->value.GetInt64() : 0;
                        LOG(INFO) << "auth expired time: " << expired_ts_;
                    }
                }
            }
        }
    } catch(const std::exception &e) {
        LOG(INFO) << "auth error: " << e.what();
        return AUTH_STATUS::UNKNOWN;
    }
    if(auth_code == 0 && (expired_ts_ == 0 || time(NULL) < expired_ts_)) {
        return AUTH_STATUS::SUCCESS;
    }
    return AUTH_STATUS::FAILED;
}

void UserManager::StartAuthRoutine(std::function<void(bool enable)> cb) {
    fut_ = pro_.get_future();
    std::thread([this, pro = std::move(pro_), cb]()mutable{
        uint32_t count = 0;
        while(!stop_) {
            if(false == cur_state_) {
                if((count++ % 6 == 0) && (AUTH_STATUS::SUCCESS == PostAuthReq())) {
                    cur_state_ = true;
                    cb(true);
                }
            } else {
                int64_t ts = (int64_t)time(NULL);
                if(expired_ts_ != 0 && ts > expired_ts_) {
                    cur_state_ = false;
                    cb(false);
                }
                if((count++ % 360 == 0) && (AUTH_STATUS::FAILED == PostAuthReq())) {
                    cur_state_ = false;
                    cb(false);
                }
            }
            sleep(10);
        }
        pro.set_value(0);
    }).detach();
}

void UserManager::Stop() {
    stop_ = true;
    fut_.wait();
}

}
