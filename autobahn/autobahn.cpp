///////////////////////////////////////////////////////////////////////////////
//
//  Copyright (C) 2014 Tavendo GmbH
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

#include "autobahn.h"

#include "util/Continuation.h"
#include "util/make_unique.h"
#include "util/SHA256Engine.h"

#include "Poco/PBKDF2Engine.h"
#include "Poco/HMACEngine.h"
#include "Poco/Base64Encoder.h"

#include <stdlib.h>


#include <cstdint>
#include <iostream>
#include <vector>
#include <map>
#include <string>
#include <sstream>


static Poco::JSON::Array DynToJSON(const Poco::Dynamic::Array& dynamic)
{
    Poco::JSON::Array arr;
    for (const auto& i : dynamic)
        arr.add(i);
    return arr;
}

static Poco::JSON::Object DynToJSON(const Poco::DynamicStruct& dynamic)
{
    Poco::JSON::Object obj;
    for (const auto& i : dynamic)
        obj.set(i.first, i.second);
    return obj;
}


namespace autobahn {

    session::~session() {

        stop();
    }

    bool session::start(const Poco::Net::SocketAddress& addr, bool useSSL) {

        stop();

        try {
            Poco::Net::HTTPRequest request("GET", "/ws", Poco::Net::HTTPRequest::HTTP_1_1);
            Poco::Net::HTTPResponse response;

            request.add("Sec-WebSocket-Protocol", "wamp.2.json");

            if (useSSL)
            {
                Poco::Net::Context::Ptr ctx = new Poco::Net::Context(Poco::Net::Context::CLIENT_USE, "", Poco::Net::Context::VERIFY_NONE, 9, true);
                m_httpsession = std::make_unique<Poco::Net::HTTPSClientSession>(addr.host().toString(), addr.port(), ctx);
            }
            else
            {
                m_httpsession = std::make_unique<Poco::Net::HTTPClientSession>(addr);
            }

            m_ws = std::make_unique<Poco::Net::WebSocket>(*m_httpsession, request, response);
            m_ws->setReceiveTimeout(0);

        } catch (Poco::Exception&) {
            return false;
        }

        m_stopped = false;
        m_runThread = std::thread([this]{ run(); });
        return true;
    }


    void session::stop() {
        m_stopped = true;
        if (m_runThread.joinable())
        {
            if (m_ws)
                m_ws->shutdown();
            m_runThread.join();
        }
    }


    bool session::isConnected() const
    {
        return !m_stopped;
    }


    std::future<uint64_t> session::join(const std::string& realm, const std::string& method, const std::string& authid, const std::string& signature) {

        // [HELLO, Realm|uri, Details|dict]

        Poco::JSON::Array json;
        json.add(static_cast<int>(msg_code::HELLO));
        json.add(realm);

        Poco::JSON::Object roles;
        roles.set("caller", Poco::JSON::Object());
        roles.set("callee", Poco::JSON::Object());
        roles.set("publisher", Poco::JSON::Object());
        roles.set("subscriber", Poco::JSON::Object());

        Poco::JSON::Object details;
        details.set("roles", roles);

        if (method != "")
        {
            Poco::JSON::Array methods;
            methods.add(method);
            details.set("authmethods", methods);
            details.set("authid", authid);
            m_signature = signature;
        }

        json.add(details);

        writeJson(json);
        send();

        m_session_join = decltype(m_session_join)();
        return m_session_join.get_future();
    }


    authinfo session::getAuthInfo() const {
        return m_authinfo;
    }


    std::future<subscription> session::subscribe(const std::string& topic, handler_t handler) {

        if (!m_session_id) {
            throw no_session_error();
        }

        // [SUBSCRIBE, Request|id, Options|dict, Topic|uri]

        m_request_id += 1;
        m_subscribe_requests.insert(std::make_pair(m_request_id, subscribe_request_t(handler)));

        Poco::JSON::Array json;
        json.add(static_cast<int>(msg_code::SUBSCRIBE));
        json.add(m_request_id);
        json.add(Poco::JSON::Object());
        json.add(topic);

        writeJson(json);
        send();

        return m_subscribe_requests[m_request_id].m_res.get_future();
    }



    std::future<registration> session::provide(const std::string& procedure, endpoint_t endpoint) {
        return _provide(procedure, static_cast<endpoint_t> (endpoint));
    }


    std::future<registration> session::provide_v(const std::string& procedure, endpoint_v_t endpoint) {
        return _provide(procedure, static_cast<endpoint_v_t> (endpoint));
    }


    std::future<registration> session::provide_m(const std::string& procedure, endpoint_m_t endpoint) {
        return _provide(procedure, static_cast<endpoint_m_t> (endpoint));
    }


    std::future<registration> session::provide_vm(const std::string& procedure, endpoint_vm_t endpoint) {
        return _provide(procedure, static_cast<endpoint_vm_t> (endpoint));
    }


    std::future<registration> session::provide_f(const std::string& procedure, endpoint_f_t endpoint) {
        return _provide(procedure, static_cast<endpoint_f_t> (endpoint));
    }


    std::future<registration> session::provide_fv(const std::string& procedure, endpoint_fv_t endpoint) {
        return _provide(procedure, static_cast<endpoint_fv_t> (endpoint));
    }


    std::future<registration> session::provide_fm(const std::string& procedure, endpoint_fm_t endpoint) {
        return _provide(procedure, static_cast<endpoint_fm_t> (endpoint));
    }


    std::future<registration> session::provide_fvm(const std::string& procedure, endpoint_fvm_t endpoint) {
        return _provide(procedure, static_cast<endpoint_fvm_t> (endpoint));
    }


    template<typename E>
    std::future<registration> session::_provide(const std::string& procedure, E endpoint) {

        if (!m_session_id) {
            throw no_session_error();
        }

        m_request_id += 1;
        m_register_requests.insert(std::make_pair(m_request_id, register_request_t(endpoint)));

        // [REGISTER, Request|id, Options|dict, Procedure|uri]

        Poco::JSON::Array json;
        json.add(static_cast<int>(msg_code::REGISTER));
        json.add(m_request_id);
        json.add(Poco::JSON::Object());
        json.add(procedure);
        writeJson(json);
        send();

        return m_register_requests[m_request_id].m_res.get_future();
    }


    void session::publish(const std::string& topic) {

        if (!m_session_id) {
            throw no_session_error();
        }

        m_request_id += 1;

        // [PUBLISH, Request|id, Options|dict, Topic|uri]

        Poco::JSON::Array json;
        json.add(static_cast<int>(msg_code::PUBLISH));
        json.add(m_request_id);
        json.add(Poco::JSON::Object());
        json.add(topic);
        writeJson(json);
        send();
    }


    void session::publish(const std::string& topic, const anyvec& args) {

        if (!m_session_id) {
            throw no_session_error();
        }

        if (args.size() > 0) {

            m_request_id += 1;

            // [PUBLISH, Request|id, Options|dict, Topic|uri, Arguments|list]

            Poco::JSON::Array json;
            json.add(static_cast<int>(msg_code::PUBLISH));
            json.add(m_request_id);
            json.add(Poco::JSON::Object());
            json.add(topic);
            json.add(DynToJSON(args));
            writeJson(json);
            send();

        } else {

            publish(topic);
        }
    }


    void session::publish(const std::string& topic, const anyvec& args, const anymap& kwargs) {

        if (!m_session_id) {
            throw no_session_error();
        }

        if (kwargs.size() > 0) {

            m_request_id += 1;

            // [PUBLISH, Request|id, Options|dict, Topic|uri, Arguments|list, ArgumentsKw|dict]

            Poco::JSON::Array json;
            json.add(static_cast<int>(msg_code::PUBLISH));
            json.add(m_request_id);
            json.add(Poco::JSON::Object());
            json.add(topic);
            json.add(DynToJSON(args));
            json.add(DynToJSON(kwargs));
            writeJson(json);
            send();

        } else {

            publish(topic, args);
        }
    }


    std::future<any> session::call(const std::string& procedure) {

        if (!m_session_id) {
            throw no_session_error();
        }

        m_request_id += 1;
        m_calls.insert(std::make_pair(m_request_id, call_t()));

        // [CALL, Request|id, Options|dict, Procedure|uri]

        Poco::JSON::Array json;
        json.add(static_cast<int>(msg_code::CALL));
        json.add(m_request_id);
        json.add(Poco::JSON::Object());
        json.add(procedure);
        writeJson(json);
        send();

        return m_calls[m_request_id].m_res.get_future();
    }


    std::future<any> session::call(const std::string& procedure, const anyvec& args) {

        if (!m_session_id) {
            throw no_session_error();
        }

        if (args.size() > 0) {

            m_request_id += 1;
            m_calls.insert(std::make_pair(m_request_id, call_t()));

            // [CALL, Request|id, Options|dict, Procedure|uri, Arguments|list]

            Poco::JSON::Array json;
            json.add(static_cast<int>(msg_code::CALL));
            json.add(m_request_id);
            json.add(Poco::JSON::Object());
            json.add(procedure);
            json.add(DynToJSON(args));
            writeJson(json);
            send();

            return m_calls[m_request_id].m_res.get_future();

        } else {

            return call(procedure);
        }
    }


    std::future<any> session::call(const std::string& procedure, const anyvec& args, const anymap& kwargs) {

        if (!m_session_id) {
            throw no_session_error();
        }

        if (kwargs.size() > 0) {

            m_request_id += 1;
            m_calls.insert(std::make_pair(m_request_id, call_t()));

            // [CALL, Request|id, Options|dict, Procedure|uri, Arguments|list, ArgumentsKw|dict]

            Poco::JSON::Array json;
            json.add(static_cast<int>(msg_code::CALL));
            json.add(m_request_id);
            json.add(Poco::JSON::Object());
            json.add(procedure);
            json.add(DynToJSON(args));
            json.add(DynToJSON(kwargs));
            writeJson(json);
            send();

            return m_calls[m_request_id].m_res.get_future();

        } else {
            return call(procedure, args);
        }
    }



    void session::process_welcome(const wamp_msg_t& msg) {

        // [WELCOME, Session|id, Details|dict]

        m_session_id = msg[1];

        anymap details = msg[2].extract<anymap>();
        if (details.contains("authmethod"))
            m_authinfo.authmethod = details["authmethod"].toString();
        if (details.contains("authprovider"))
            m_authinfo.authprovider = details["authprovider"].toString();
        if (details.contains("authid"))
            m_authinfo.authid = details["authid"].toString();
        if (details.contains("authrole"))
            m_authinfo.authrole = details["authrole"].toString();

        m_session_join.set_value(m_session_id);
    }


    void session::process_abort(const wamp_msg_t& msg) {

        // [ABORT, Details|dict, Reason|uri]

        auto eptr = std::make_exception_ptr(server_error(msg[2].toString()));
        m_session_join.set_exception(eptr);
    }


    void session::process_challenge(const wamp_msg_t& msg)
    {
        // [CHALLENGE, AuthMethod|string, Extra|dict]

        // [AUTHENTICATE, Signature|string, Extra|dict]
        Poco::JSON::Array json;
        json.add(static_cast<int>(msg_code::AUTHENTICATE));

        std::string method = msg[1];
        if (method == "wampcra")
        {
            anymap extra = msg[2].extract<anymap>();

            std::string salt = extra["salt"];
            int iterations = extra["iterations"];
            std::string challenge = extra["challenge"];

            // derive a key
            Poco::PBKDF2Engine<Poco::HMACEngine<util::SHA256Engine>> pbkdf2(salt, iterations);
            pbkdf2.update(m_signature);
            auto key = pbkdf2.digest();

            std::stringstream ssKey;
            Poco::Base64Encoder encoderKey(ssKey);
            for (auto c : key)
                encoderKey << c;
            encoderKey.close();

            // sign
            Poco::HMACEngine<util::SHA256Engine> hmac(ssKey.str());
            hmac.update(challenge);
            auto signature = hmac.digest();

            std::stringstream ssSig;
            Poco::Base64Encoder encoderSig(ssSig);
            for (auto c : signature)
                encoderSig << c;
            encoderSig.close();

            json.add(ssSig.str());

        } else if (method == "ticket")
        {
            json.add(m_signature);
        } else {
            throw protocol_error("unable to respond to auth method");
        }

        for (char& c : m_signature)
            c = '\0';

        json.add(Poco::JSON::Object());
        writeJson(json);
        send();
    }


    void session::process_error(const wamp_msg_t& msg) {

        // [ERROR, REQUEST.Type|int, REQUEST.Request|id, Details|dict, Error|uri]
        // [ERROR, REQUEST.Type|int, REQUEST.Request|id, Details|dict, Error|uri, Arguments|list]
        // [ERROR, REQUEST.Type|int, REQUEST.Request|id, Details|dict, Error|uri, Arguments|list, ArgumentsKw|dict]

        auto eptr = std::make_exception_ptr(server_error(msg[4].toString()));

        switch (static_cast<msg_code>(static_cast<int>(msg[1])))
        {
        case msg_code::REGISTER:
        {
            auto register_request = m_register_requests.find(msg[2]);
            if (register_request != m_register_requests.end()) {
                register_request->second.m_res.set_exception(eptr);
            }
        }
            break;
        case msg_code::SUBSCRIBE:
        {
            auto subscribe_request = m_subscribe_requests.find(msg[2]);
            if (subscribe_request != m_subscribe_requests.end()) {
                subscribe_request->second.m_res.set_exception(eptr);
            }
        }
            break;
        case msg_code::CALL:
        {
            auto call_req = m_calls.find(msg[2]);
            if (call_req != m_calls.end()) {
                call_req->second.m_res.set_exception(eptr);
            }
        }
            break;
            // TODO: INVOCATION, UNREGISTER, PUBLISH, UNSUBSCRIBE
        }
    }


    void session::process_goodbye(const wamp_msg_t& msg) {

        /*
        if (!m_session_id) {
        throw protocol_error("GOODBYE received an no session established");
        }
        */
        m_session_id = 0;

        if (!m_goodbye_sent) {

            // if we did not initiate closing, reply ..

            // [GOODBYE, Details|dict, Reason|uri]

            Poco::JSON::Array json;
            json.add(static_cast<int>(msg_code::GOODBYE));
            json.add(Poco::JSON::Object());
            json.add("wamp.error.goodbye_and_out");
            writeJson(json);
            send();

        } else {
            // we previously initiated closing, so this
            // is the peer reply
        }
        std::string reason = msg[2];
        m_session_leave.set_value(reason);
    }


    std::future<std::string> session::leave(const std::string& reason) {

        if (!m_session_id) {
            throw no_session_error();
        }

        m_goodbye_sent = true;
        m_session_id = 0;

        // [GOODBYE, Details|dict, Reason|uri]

        Poco::JSON::Array json;
        json.add(static_cast<int>(msg_code::GOODBYE));
        json.add(Poco::JSON::Object());
        json.add(reason);
        writeJson(json);
        send();

        m_session_leave = decltype(m_session_leave)();
        return m_session_leave.get_future();
    }


    template <typename T>
    void session::writeJson(const T& objOrArray)
    {
        std::stringstream ssout;
        objOrArray.stringify(ssout);
        m_sendSize = static_cast<int>(ssout.tellp());
        if (m_sendSize > BUFFER_SIZE)
            throw std::out_of_range("received a message that was too big");

        ssout.read(m_sendBuffer, m_sendSize);

        // workaround for a poco bug. will be fixed after 1.5.3
        for (int i = 0; i < m_sendSize; i++)
        {
            switch (m_sendBuffer[i])
            {
            case '\b': m_sendBuffer[i] = 'b'; break;
            case '\f': m_sendBuffer[i] = 'f'; break;
            case '\n': m_sendBuffer[i] = 'n'; break;
            case '\r': m_sendBuffer[i] = 'r'; break;
            case '\t': m_sendBuffer[i] = 't'; break;
            }
        }
    }


    void session::process_invocation(const wamp_msg_t& msg) {

        // [INVOCATION, Request|id, REGISTERED.Registration|id, Details|dict]
        // [INVOCATION, Request|id, REGISTERED.Registration|id, Details|dict, CALL.Arguments|list]
        // [INVOCATION, Request|id, REGISTERED.Registration|id, Details|dict, CALL.Arguments|list, CALL.ArgumentsKw|dict]

        if (msg.size() != 4 && msg.size() != 5 && msg.size() != 6) {
            throw protocol_error("invalid INVOCATION message structure - length must be 4, 5 or 6");
        }

        // TODO
        /*if (msg[1].type != msgpack::type::POSITIVE_INTEGER) {
        throw protocol_error("invalid INVOCATION message structure - INVOCATION.Request must be an integer");
        }*/
        uint64_t request_id = msg[1];

        /*if (msg[2].type != msgpack::type::POSITIVE_INTEGER) {
        throw protocol_error("invalid INVOCATION message structure - INVOCATION.Registration must be an integer");
        }*/
        uint64_t registration_id = msg[2];

        endpoints_t::iterator endpoint = m_endpoints.find(registration_id);

        if (endpoint != m_endpoints.end()) {

            /*if (msg[3].type != msgpack::type::MAP) {
            throw protocol_error("invalid INVOCATION message structure - Details must be a dictionary");
            }*/

            anyvec args;
            anymap kwargs;

            if (msg.size() > 4) {

                /*if (msg[4].type != msgpack::type::ARRAY) {
                throw protocol_error("invalid INVOCATION message structure - INVOCATION.Arguments must be a list");
                }*/

                args = msg[4].extract<anyvec>();

                if (msg.size() > 5) {
                    kwargs = msg[5].extract<anymap>();
                }
            }

            // [YIELD, INVOCATION.Request|id, Options|dict]
            // [YIELD, INVOCATION.Request|id, Options|dict, Arguments|list]
            // [YIELD, INVOCATION.Request|id, Options|dict, Arguments|list, ArgumentsKw|dict]
            try {

                if ((endpoint->second).type() == typeid(endpoint_t)) {

                    poco_trace_f1(m_logger, "Invoking endpoint registered under %?i as of type endpoint_t", registration_id);

                    any res = endpoint->second.extract<endpoint_t>()(args, kwargs);

                    Poco::JSON::Array json;
                    json.add(static_cast<int>(msg_code::YIELD));
                    json.add(request_id);
                    json.add(Poco::JSON::Object());
                    Poco::JSON::Array result;
                    result.add(res);
                    json.add(result);
                    writeJson(json);
                    send();

                } else if ((endpoint->second).type() == typeid(endpoint_v_t)) {

                    poco_trace_f1(m_logger, "Invoking endpoint registered under %?i as of type endpoint_v_t", registration_id);

                    anyvec res = endpoint->second.extract<endpoint_v_t>()(args, kwargs);

                    Poco::JSON::Array json;
                    json.add(static_cast<int>(msg_code::YIELD));
                    json.add(request_id);
                    json.add(Poco::JSON::Object());
                    json.add(DynToJSON(res));
                    writeJson(json);
                    send();

                } else if ((endpoint->second).type() == typeid(endpoint_fvm_t)) {

                    poco_trace_f1(m_logger, "Invoking endpoint registered under %?i as of type endpoint_fvm_t", registration_id);

                    auto f_res = endpoint->second.extract<endpoint_fvm_t>()(args, kwargs);

                    auto done = util::then(std::move(f_res), [&](decltype(f_res) f) {

                        anyvecmap res = f.get();

                        Poco::JSON::Array json;
                        json.add(static_cast<int>(msg_code::YIELD));
                        json.add(request_id);
                        json.add(Poco::JSON::Object());
                        json.add(DynToJSON(res.first));
                        json.add(DynToJSON(res.second));
                        writeJson(json);
                        send();
                    });

                    done.wait();

                } else {
                    // FIXME
                    poco_error(m_logger, "not implemented");
                }

            } catch (...) {
                // FIXME: send ERROR
                poco_error(m_logger, "INVOCATION failed");
            }

        } else {
            throw protocol_error("bogus INVOCATION message for non-registered registration ID");
        }
    }


    void session::process_call_result(const wamp_msg_t& msg) {

        // [RESULT, CALL.Request|id, Details|dict]
        // [RESULT, CALL.Request|id, Details|dict, YIELD.Arguments|list]
        // [RESULT, CALL.Request|id, Details|dict, YIELD.Arguments|list, YIELD.ArgumentsKw|dict]

        if (msg.size() != 3 && msg.size() != 4 && msg.size() != 5) {
            throw protocol_error("invalid RESULT message structure - length must be 3, 4 or 5");
        }

        if (!msg[1].isInteger()) {
            throw protocol_error("invalid RESULT message structure - CALL.Request must be an integer");
        }

        uint64_t request_id = msg[1];

        calls_t::iterator call = m_calls.find(request_id);

        if (call != m_calls.end()) {

            /*if (msg[2].type != msgpack::type::MAP) {
            throw protocol_error("invalid RESULT message structure - Details must be a dictionary");
            }*/

            if (msg.size() > 3) {

                /*if (msg[3].type != msgpack::type::ARRAY) {
                throw protocol_error("invalid RESULT message structure - YIELD.Arguments must be a list");
                }*/

                auto args = msg[3].extract<anyvec>();

                if (args.size() > 0) {
                    call->second.m_res.set_value(args[0]);
                } else {
                    call->second.m_res.set_value(any());
                }

            } else {
                // empty result
                call->second.m_res.set_value(any());
            }
        } else {
            throw protocol_error("bogus RESULT message for non-pending request ID");
        }
    }


    void session::process_subscribed(const wamp_msg_t& msg) {

        // [SUBSCRIBED, SUBSCRIBE.Request|id, Subscription|id]

        if (msg.size() != 3) {
            throw protocol_error("invalid SUBSCRIBED message structure - length must be 3");
        }

        if (!msg[1].isInteger()) {
            throw protocol_error("invalid SUBSCRIBED message structure - SUBSCRIBED.Request must be an integer");
        }

        uint64_t request_id = msg[1];

        subscribe_requests_t::iterator subscribe_request = m_subscribe_requests.find(request_id);

        if (subscribe_request != m_subscribe_requests.end()) {

            if (!msg[2].isInteger()) {
                throw protocol_error("invalid SUBSCRIBED message structure - SUBSCRIBED.Subscription must be an integer");
            }

            uint64_t subscription_id = msg[2];

            m_handlers[subscription_id] = subscribe_request->second.m_handler;

            subscribe_request->second.m_res.set_value(subscription(subscription_id));

            m_subscribe_requests.erase(request_id);

        } else {
            throw protocol_error("bogus SUBSCRIBED message for non-pending request ID");
        }
    }


    void session::process_event(const wamp_msg_t& msg) {

        // [EVENT, SUBSCRIBED.Subscription|id, PUBLISHED.Publication|id, Details|dict]
        // [EVENT, SUBSCRIBED.Subscription|id, PUBLISHED.Publication|id, Details|dict, PUBLISH.Arguments|list]
        // [EVENT, SUBSCRIBED.Subscription|id, PUBLISHED.Publication|id, Details|dict, PUBLISH.Arguments|list, PUBLISH.ArgumentsKw|dict]

        if (msg.size() != 4 && msg.size() != 5 && msg.size() != 6) {
            throw protocol_error("invalid EVENT message structure - length must be 4, 5 or 6");
        }

        if (!msg[1].isInteger()) {
            throw protocol_error("invalid EVENT message structure - SUBSCRIBED.Subscription must be an integer");
        }

        uint64_t subscription_id = msg[1];

        handlers_t::iterator handler = m_handlers.find(subscription_id);

        if (handler != m_handlers.end()) {

            if (!msg[2].isInteger()) {
                throw protocol_error("invalid EVENT message structure - PUBLISHED.Publication|id must be an integer");
            }

            //uint64_t publication_id = msg[2].as<uint64_t>();

            /*if (msg[3].type != msgpack::type::MAP) {
            throw protocol_error("invalid EVENT message structure - Details must be a dictionary");
            }*/

            anyvec args;
            anymap kwargs;

            if (msg.size() > 4) {

                /*if (msg[4].type != msgpack::type::ARRAY) {
                throw protocol_error("invalid EVENT message structure - EVENT.Arguments must be a list");
                }*/

                args = msg[4].extract<anyvec>();

                if (msg.size() > 5) {

                    /*if (msg[5].type != msgpack::type::MAP) {
                    throw protocol_error("invalid EVENT message structure - EVENT.Arguments must be a list");
                    }*/

                    kwargs = msg[5].extract<anymap>();
                }
            }

            try {

                // now trigger the user supplied event handler ..
                //
                (handler->second)(args, kwargs);

            } catch (...) {
                poco_warning(m_logger, "event handler fired exception");
            }

        } else {
            // silently swallow EVENT for non-existent subscription IDs.
            // We may have just unsubscribed, the this EVENT might be have
            // already been in-flight.
            poco_trace_f1(m_logger, "Skipping EVENT for non-existent subscription ID %?i", subscription_id);
        }
    }


    void session::process_registered(const wamp_msg_t& msg) {

        // [REGISTERED, REGISTER.Request|id, Registration|id]

        if (msg.size() != 3) {
            throw protocol_error("invalid REGISTERED message structure - length must be 3");
        }

        if (!msg[1].isInteger()) {
            throw protocol_error("invalid REGISTERED message structure - REGISTERED.Request must be an integer");
        }

        uint64_t request_id = msg[1];

        register_requests_t::iterator register_request = m_register_requests.find(request_id);

        if (register_request != m_register_requests.end()) {

            if (!msg[2].isInteger()) {
                throw protocol_error("invalid REGISTERED message structure - REGISTERED.Registration must be an integer");
            }

            uint64_t registration_id = msg[2];

            m_endpoints[registration_id] = register_request->second.m_endpoint;

            register_request->second.m_res.set_value(registration(registration_id));

        } else {
            throw protocol_error("bogus REGISTERED message for non-pending request ID");
        }
    }


    void session::got_msg() {

        m_parser.reset();

        auto json = m_parser.parse(std::string(m_recvBuffer, m_recvSize));

        wamp_msg_t msg = *json.extract<Poco::JSON::Array::Ptr>();

        if (msg.size() < 1) {
            throw protocol_error("invalid message structure - missing message code");
        }

        if (!msg[0].isInteger()) {
            throw protocol_error("invalid message code type - not an integer");
        }

        msg_code code = static_cast<msg_code> (static_cast<int>(msg[0]));

        switch (code) {
        case msg_code::HELLO:
            throw protocol_error("received HELLO message unexpected for WAMP client roles");

        case msg_code::WELCOME:
            process_welcome(msg);
            break;

        case msg_code::ABORT:
            process_abort(msg);
            break;

        case msg_code::CHALLENGE:
            process_challenge(msg);
            break;

        case msg_code::AUTHENTICATE:
            throw protocol_error("received AUTHENTICATE message unexpected for WAMP client roles");

        case msg_code::GOODBYE:
            process_goodbye(msg);
            break;

        case msg_code::HEARTBEAT:
            // FIXME
            break;

        case msg_code::ERROR:
            process_error(msg);
            break;

        case msg_code::PUBLISH:
            throw protocol_error("received PUBLISH message unexpected for WAMP client roles");

        case msg_code::PUBLISHED:
            // FIXME
            break;

        case msg_code::SUBSCRIBE:
            throw protocol_error("received SUBSCRIBE message unexpected for WAMP client roles");

        case msg_code::SUBSCRIBED:
            process_subscribed(msg);
            break;

        case msg_code::UNSUBSCRIBE:
            throw protocol_error("received UNSUBSCRIBE message unexpected for WAMP client roles");

        case msg_code::UNSUBSCRIBED:
            // FIXME
            break;

        case msg_code::EVENT:
            process_event(msg);
            break;

        case msg_code::CALL:
            throw protocol_error("received CALL message unexpected for WAMP client roles");

        case msg_code::CANCEL:
            throw protocol_error("received CANCEL message unexpected for WAMP client roles");

        case msg_code::RESULT:
            process_call_result(msg);
            break;

        case msg_code::REGISTER:
            throw protocol_error("received REGISTER message unexpected for WAMP client roles");

        case msg_code::REGISTERED:
            process_registered(msg);
            break;

        case msg_code::UNREGISTER:
            throw protocol_error("received UNREGISTER message unexpected for WAMP client roles");

        case msg_code::UNREGISTERED:
            // FIXME
            break;

        case msg_code::INVOCATION:
            process_invocation(msg);
            break;

        case msg_code::INTERRUPT:
            throw protocol_error("received INTERRUPT message - not implemented");

        case msg_code::YIELD:
            throw protocol_error("received YIELD message unexpected for WAMP client roles");
        }
    }


    void session::dbg_buffers() {
        printf("sendBuffer:\n");
        for (int i = 0; i < m_sendSize; i++)
            printf("%02X ", (unsigned char)m_sendBuffer[i]);
        printf("\nrecvBuffer:\n");
        for (int i = 0; i < m_recvSize; i++)
            printf("%02X ", (unsigned char)m_recvBuffer[i]);
        printf("\n");
    }


    void session::send() {

        if (!m_stopped) {
            try {
                m_ws->sendFrame(m_sendBuffer, m_sendSize);
            } catch (Poco::Exception& e) {
                poco_error(m_logger, e.displayText().c_str());
                m_stopped = true;
                dbg_buffers();
            } catch (protocol_error& e) {
                poco_error(m_logger, e.what());
                m_stopped = true;
                dbg_buffers();
            } catch (...) {
                poco_error(m_logger, "unexpected exception");
                m_stopped = true;
                dbg_buffers();
            }
        }
    }

    void session::run() {
        while (!m_stopped)
        {
            try {
                int flags;
                m_recvSize = m_ws->receiveFrame(m_recvBuffer, sizeof(m_recvBuffer), flags);
                if (m_recvSize == 0)
                {
                    m_stopped = true;
                    break;
                }

                got_msg();
            } catch (Poco::Exception& e) {
                poco_error(m_logger, e.displayText().c_str());
                dbg_buffers();
                break;
            } catch (protocol_error& e) {
                poco_error(m_logger, e.what());
                dbg_buffers();
                break;
            } catch (...) {
                poco_error(m_logger, "unexpected exception");
                dbg_buffers();
                break;
            }
        }

        m_stopped = true;
    }
}
