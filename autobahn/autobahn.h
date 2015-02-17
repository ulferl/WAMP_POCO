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

#ifndef AUTOBAHN_H
#define AUTOBAHN_H

#include <cstdint>
#include <stdexcept>
#include <istream>
#include <ostream>
#include <string>
#include <utility>
#include <vector>
#include <map>
#include <functional>

#include <future>

#include <Poco/Net/HTTPSClientSession.h>
#include <Poco/Net/HTTPRequest.h>
#include <Poco/Net/HTTPResponse.h>
#include <Poco/Net/WebSocket.h>
#include <Poco/JSON/Parser.h>
#include <Poco/JSON/Stringifier.h>
#include <Poco/Dynamic/Var.h>
#include <Poco/Logger.h>

// thank you microsoft
#ifdef ERROR
#undef ERROR
#endif


/*! \mainpage Reference Documentation
*
* Welcome to the reference documentation of <b>Autobahn</b>|Cpp.<br>
*
* For a more gentle introduction, please visit http://autobahn.ws/cpp/.
*/


/*!
* Autobahn namespace.
*/
namespace autobahn {

    static const size_t BUFFER_SIZE = 16384;

    typedef Poco::Dynamic::Var any;

    /// A map holding any values and string keys.
    typedef Poco::DynamicStruct anymap;

    /// A vector holding any values.
    typedef Poco::Dynamic::Array anyvec;

    /// A pair of ::anyvec and ::anymap.
    typedef std::pair<anyvec, anymap> anyvecmap;


    /// Handler type for use with session::subscribe(const std::string&, handler_t)
    typedef std::function<void(const anyvec&, const anymap&)> handler_t;


    /// Endpoint type for use with session::provide(const std::string&, endpoint_t)
    typedef std::function<any(const anyvec&, const anymap&)> endpoint_t;

    /// Endpoint type for use with session::provide_v(const std::string&, endpoint_v_t)
    typedef std::function<anyvec(const anyvec&, const anymap&)> endpoint_v_t;

    /// Endpoint type for use with session::provide_m(const std::string&, endpoint_m_t)
    typedef std::function<anymap(const anyvec&, const anymap&)> endpoint_m_t;

    /// Endpoint type for use with session::provide_vm(const std::string&, endpoint_vm_t)
    typedef std::function<anyvecmap(const anyvec&, const anymap&)> endpoint_vm_t;


    /// Endpoint type for use with session::provide(const std::string&, endpoint_ft)
    typedef std::function<std::future<any>(const anyvec&, const anymap&)> endpoint_f_t;

    /// Endpoint type for use with session::provide_fv(const std::string&, endpoint_fv_t)
    typedef std::function<std::future<anyvec>(const anyvec&, const anymap&)> endpoint_fv_t;

    /// Endpoint type for use with session::provide_fm(const std::string&, endpoint_fm_t)
    typedef std::function<std::future<anymap>(const anyvec&, const anymap&)> endpoint_fm_t;

    /// Endpoint type for use with session::provide_fvm(const std::string&, endpoint_fvm_t)
    typedef std::function<std::future<anyvecmap>(const anyvec&, const anymap&)> endpoint_fvm_t;


    /// Represents a procedure registration.
    struct registration {
        registration() : id(0) {};
        registration(uint64_t id) : id(id) {};
        uint64_t id;
    };

    /// Represents a topic subscription.
    struct subscription {
        subscription() : id(0) {};
        subscription(uint64_t id) : id(id) {};
        uint64_t id;
    };

    /// Represents an event publication (for acknowledged publications).
    struct publication {
        publication() : id(0) {};
        publication(uint64_t id) : id(id) {};
        uint64_t id;
    };

    /// Represents the authentication information sent on welcome
    struct authinfo {
        std::string authmethod;
        std::string authprovider;
        std::string authid;
        std::string authrole;
    };


    /*!
    * A WAMP session.
    */
    class session {

    public:

        ~session();

        /*!
        * Start listening on the IStream provided to the constructor
        * of this session.
        */
        bool start(const Poco::Net::SocketAddress& addr, bool useSSL = false);

        /*!
        * Closes the IStream and the OStream provided to the constructor
        * of this session.
        */
        void stop();

        bool isConnected() const;

        /*!
        * Join a realm with this session.
        *
        * \param realm The realm to join on the WAMP router connected to.
        * \param method The method used for login. Empty string will cause no login.
        * \param authid The authid to login with.
        * \param signature The signature to use when logging in. For method "ticket" the ticket, for method "wampcra" the passphrase.
        * \return A future that resolves with the session ID when the realm was joined.
        */
        std::future<uint64_t> join(const std::string& realm, const std::string& method = "", const std::string& authid = "", const std::string& signature = "");

        /*!
        * Leave the realm.
        *
        * \param reason An optional WAMP URI providing a reason for leaving.
        * \return A future that resolves with the reason sent by the peer.
        */
        std::future<std::string> leave(const std::string& reason = std::string("wamp.error.close_realm"));


        authinfo getAuthInfo() const;


        /*!
        * Publish an event with empty payload to a topic.
        *
        * \param topic The URI of the topic to publish to.
        */
        void publish(const std::string& topic);

        /*!
        * Publish an event with positional payload to a topic.
        *
        * \param topic The URI of the topic to publish to.
        * \param args The positional payload for the event.
        */
        void publish(const std::string& topic, const anyvec& args);

        /*!
        * Publish an event with both positional and keyword payload to a topic.
        *
        * \param topic The URI of the topic to publish to.
        * \param args The positional payload for the event.
        * \param kwargs The keyword payload for the event.
        */
        void publish(const std::string& topic, const anyvec& args, const anymap& kwargs);


        /*!
        * Subscribe a handler to a topic to receive events.
        *
        * \param topic The URI of the topic to subscribe to.
        * \param handler The handler that will receive events under the subscription.
        * \return A future that resolves to a autobahn::subscription
        */
        std::future<subscription> subscribe(const std::string& topic, handler_t handler);


        /*!
        * Calls a remote procedure with no arguments.
        *
        * \param procedure The URI of the remote procedure to call.
        * \return A future that resolves to the result of the remote procedure call.
        */
        std::future<any> call(const std::string& procedure);

        /*!
        * Calls a remote procedure with positional arguments.
        *
        * \param procedure The URI of the remote procedure to call.
        * \param args The positional arguments for the call.
        * \return A future that resolves to the result of the remote procedure call.
        */
        std::future<any> call(const std::string& procedure, const anyvec& args);

        /*!
        * Calls a remote procedure with positional and keyword arguments.
        *
        * \param procedure The URI of the remote procedure to call.
        * \param args The positional arguments for the call.
        * \param kwargs The keyword arguments for the call.
        * \return A future that resolves to the result of the remote procedure call.
        */
        std::future<any> call(const std::string& procedure, const anyvec& args, const anymap& kwargs);


        /*!
        * Register an endpoint as a procedure that can be called remotely.
        *
        * \param procedure The URI under which the procedure is to be exposed.
        * \param endpoint The endpoint to be exposed as a remotely callable procedure.
        * \return A future that resolves to a autobahn::registration
        */
        std::future<registration> provide(const std::string& procedure, endpoint_t endpoint);

        std::future<registration> provide_v(const std::string& procedure, endpoint_v_t endpoint);

        std::future<registration> provide_m(const std::string& procedure, endpoint_m_t endpoint);

        std::future<registration> provide_vm(const std::string& procedure, endpoint_vm_t endpoint);

        std::future<registration> provide_f(const std::string& procedure, endpoint_f_t endpoint);

        std::future<registration> provide_fv(const std::string& procedure, endpoint_fv_t endpoint);

        std::future<registration> provide_fm(const std::string& procedure, endpoint_fm_t endpoint);

        std::future<registration> provide_fvm(const std::string& procedure, endpoint_fvm_t endpoint);

    private:

        template<typename E>
        std::future<registration> _provide(const std::string& procedure, E endpoint);


        //////////////////////////////////////////////////////////////////////////////////////
        /// Caller

        /// An outstanding WAMP call.
        struct call_t {
            call_t() { }
            call_t(call_t&& c) : m_res(std::move(c.m_res)) { }
            std::promise<any> m_res;
        };

        /// Map of outstanding WAMP calls (request ID -> call).
        typedef std::map<uint64_t, call_t> calls_t;

        /// Map of WAMP call ID -> call
        calls_t m_calls;


        //////////////////////////////////////////////////////////////////////////////////////
        /// Subscriber

        /// An outstanding WAMP subscribe request.
        struct subscribe_request_t {
            subscribe_request_t() {};
            subscribe_request_t(subscribe_request_t&& s) :
                m_handler(std::move(s.m_handler)),
                m_res(std::move(s.m_res)) { }
            subscribe_request_t(handler_t handler) : m_handler(handler) {};
            handler_t m_handler;
            std::promise<subscription> m_res;
        };

        /// Map of outstanding WAMP subscribe requests (request ID -> subscribe request).
        typedef std::map<uint64_t, subscribe_request_t> subscribe_requests_t;

        /// Map of WAMP subscribe request ID -> subscribe request
        subscribe_requests_t m_subscribe_requests;

        /// Map of subscribed handlers (subscription ID -> handler)
        typedef std::map<uint64_t, handler_t> handlers_t;

        /// Map of WAMP subscription ID -> handler
        handlers_t m_handlers;


        //////////////////////////////////////////////////////////////////////////////////////
        /// Callee

        /// An outstanding WAMP register request.
        struct register_request_t {
            register_request_t() {};
            register_request_t(register_request_t&& r) :
                m_endpoint(std::move(r.m_endpoint)),
                m_res(std::move(r.m_res)) { }
            register_request_t(any endpoint) : m_endpoint(endpoint) {};
            any m_endpoint;
            std::promise<registration> m_res;
        };

        /// Map of outstanding WAMP register requests (request ID -> register request).
        typedef std::map<uint64_t, register_request_t> register_requests_t;

        /// Map of WAMP register request ID -> register request
        register_requests_t m_register_requests;

        /// Map of registered endpoints (registration ID -> endpoint)
        typedef std::map<uint64_t, any> endpoints_t;

        /// Map of WAMP registration ID -> endpoint
        endpoints_t m_endpoints;



        /// An unserialized, raw WAMP message.
        typedef Poco::Dynamic::Array wamp_msg_t;



        /// Process a WAMP WELCOME message.
        void process_welcome(const wamp_msg_t& msg);

        /// Process a WAMP ABORT message.
        void process_abort(const wamp_msg_t& msg);

        /// Process a WAMP CHALLENGE message.
        void process_challenge(const wamp_msg_t& msg);

        /// Process a WAMP ERROR message.
        void process_error(const wamp_msg_t& msg);

        /// Process a WAMP RESULT message.
        void process_call_result(const wamp_msg_t& msg);

        /// Process a WAMP SUBSCRIBED message.
        void process_subscribed(const wamp_msg_t& msg);

        /// Process a WAMP EVENT message.
        void process_event(const wamp_msg_t& msg);

        /// Process a WAMP REGISTERED message.
        void process_registered(const wamp_msg_t& msg);

        /// Process a WAMP INVOCATION message.
        void process_invocation(const wamp_msg_t& msg);

        /// Process a WAMP GOODBYE message.
        void process_goodbye(const wamp_msg_t& msg);


        /// serializes json to output buffer
        /// T must have stringify(std::ofstream&) member function
        template <typename T>
        void writeJson(const T& objOrArray);

        void dbg_buffers();

        /// Send out message serialized in serialization buffer to ostream.
        void send();

        /// Runs the session
        void run();


        void got_msg();


        Poco::Logger& m_logger = Poco::Logger::get("autobahn");

        bool m_stopped = true;

        std::unique_ptr<Poco::Net::HTTPClientSession> m_httpsession;
        std::unique_ptr<Poco::Net::WebSocket> m_ws;
        std::thread m_runThread;


        char m_recvBuffer[BUFFER_SIZE];
        int m_recvSize = 0;
        char m_sendBuffer[BUFFER_SIZE];
        int m_sendSize = 0;

        Poco::JSON::Parser m_parser;

        /// WAMP session ID (if the session is joined to a realm).
        uint64_t m_session_id = 0;

        /// Future to be fired when session was joined.
        std::promise<uint64_t> m_session_join;

        /// Last request ID of outgoing WAMP requests.
        uint64_t m_request_id = 0;

        /// Signature to be used to authenticate
        std::string m_signature;

        /// Authentication information sent on welcome
        authinfo m_authinfo;


        bool m_goodbye_sent = false;

        std::promise<std::string> m_session_leave;

        /// WAMP message type codes.
        enum class msg_code : int {
            HELLO = 1,
            WELCOME = 2,
            ABORT = 3,
            CHALLENGE = 4,
            AUTHENTICATE = 5,
            GOODBYE = 6,
            HEARTBEAT = 7,
            ERROR = 8,
            PUBLISH = 16,
            PUBLISHED = 17,
            SUBSCRIBE = 32,
            SUBSCRIBED = 33,
            UNSUBSCRIBE = 34,
            UNSUBSCRIBED = 35,
            EVENT = 36,
            CALL = 48,
            CANCEL = 49,
            RESULT = 50,
            REGISTER = 64,
            REGISTERED = 65,
            UNREGISTER = 66,
            UNREGISTERED = 67,
            INVOCATION = 68,
            INTERRUPT = 69,
            YIELD = 70
        };
    };


    class protocol_error : public std::runtime_error {
    public:
        protocol_error(const std::string& msg) : std::runtime_error(msg) {};
    };

    class no_session_error : public std::runtime_error {
    public:
        no_session_error() : std::runtime_error("session not joined") {};
    };

    class server_error : public std::runtime_error {
    public:
        server_error(const std::string& msg) : std::runtime_error(msg) {};
    };

}

#endif // AUTOBAHN_H
