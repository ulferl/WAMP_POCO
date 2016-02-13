#ifndef APPLICATIONWEBSOCKET_H
#define APPLICATIONWEBSOCKET_H

#include <Poco/Net/WebSocket.h>
#include <Poco/Net/NetException.h>
#include <vector>
#include <mutex>


/*
Wrapper for Poco::Net::WebSocket that handles websocket control frames and fragmentation.
Poco::Net::WebSocket is not compatible with non-blocking sockets, so a reactor cannot be used!
Two threads can be used to simultaneously receive and send.
*/
class ApplicationWebSocket : public Poco::Net::WebSocket
{
public:
    // TODO inheriting constructors
    ApplicationWebSocket(Poco::Net::HTTPClientSession& session, Poco::Net::HTTPRequest& request, Poco::Net::HTTPResponse& response);

    void setMaxFrameSizeRecv(int maxFrameSize);
    void setMaxFrameSizeSend(int maxFrameSize);

    void shutdown();
    void shutdown(Poco::UInt16 statusCode, const std::string& statusMessage = "");

    int sendMessage(const void *buffer, int length);

    // Keep the buffer between calls to avoid big allocations.
    int receiveMessage(std::vector<char>& buffer);

private:
    int m_maxFrameSizeRecv = 0x100000;
    int m_maxFrameSizeSend = 0x10000;
    bool m_closeSentByUs = false;
    std::mutex m_sendMutex;

};

#endif