#include "replay/backend/ApplicationWebSocket.h"


ApplicationWebSocket::ApplicationWebSocket(Poco::Net::HTTPClientSession& session, Poco::Net::HTTPRequest& request, Poco::Net::HTTPResponse& response)
    : Poco::Net::WebSocket(session, request, response)
{
}


void ApplicationWebSocket::setMaxFrameSizeSend(int maxFrameSize)
{
    m_maxFrameSizeSend = maxFrameSize;
}

void ApplicationWebSocket::setMaxFrameSizeRecv(int maxFrameSize)
{
    m_maxFrameSizeRecv = maxFrameSize;
}

void ApplicationWebSocket::shutdown()
{
    shutdown(WS_NORMAL_CLOSE);
}

void ApplicationWebSocket::shutdown(Poco::UInt16 statusCode, const std::string& statusMessage)
{
    std::lock_guard<std::mutex> lock(m_sendMutex);
    WebSocket::shutdown(statusCode, statusMessage);
    m_closeSentByUs = true;
}

int ApplicationWebSocket::sendMessage(const void *buffer, int length)
{
    int numFrames = (length + m_maxFrameSizeSend - 1) / m_maxFrameSizeSend;
    for (int i = 0; i < numFrames; i++)
    {
        int sendSize = m_maxFrameSizeSend;
        int flags = 0x100;  // work around this fixed bug: https://github.com/pocoproject/poco/commit/b83c8273db7963999198e0790419e23f9e8d3c5f
        if (i == 0)
        {
            flags |= FRAME_OP_TEXT;
        }
        if (i == numFrames - 1)
        {
            sendSize = length % m_maxFrameSizeSend;
            flags |= FRAME_FLAG_FIN;
        }
        std::lock_guard<std::mutex> lock(m_sendMutex);
        int bytesSent = sendFrame((const char*)buffer + i*m_maxFrameSizeSend, sendSize, flags);
        if (bytesSent <= 0)
        {
            return 0;
        }
    }

    return length;
}

int ApplicationWebSocket::receiveMessage(std::vector<char>& buffer)
{
    buffer.resize(0);

    while (true)
    {
        int flags;
        auto oldSize = buffer.size();
        buffer.resize(oldSize + m_maxFrameSizeRecv);
        int recvSize = receiveFrame(buffer.data() + oldSize, m_maxFrameSizeRecv, flags);
        if (recvSize <= 0)
        {
            return 0;
        }

        int frameOp = flags & FRAME_OP_BITMASK;

        // Control frames can arrive between fragments.
        switch (frameOp)
        {
        case FRAME_OP_CLOSE:
            if (!m_closeSentByUs)
            {
                std::lock_guard<std::mutex> lock(m_sendMutex);
                // If there is a body, echo the status code.
                sendFrame(buffer.data() + oldSize, recvSize >= 2 ? 2 : 0, FRAME_OP_CLOSE | FRAME_FLAG_FIN);
            }
            return 0;

        case FRAME_OP_PING:
            {
                std::lock_guard<std::mutex> lock(m_sendMutex);
                int sendSize = sendFrame(buffer.data() + oldSize, recvSize, FRAME_OP_PONG | FRAME_FLAG_FIN);
                if (sendSize <= 0)
                {
                    return 0;
                }
            }

            // Reset buffer size to last received fragment.
            buffer.resize(oldSize);
            break;

        case FRAME_OP_TEXT:
        case FRAME_OP_BINARY:
            if (oldSize != 0)
            {
                // Fragmented messages can only be interleaved with control frames.
                throw Poco::Net::WebSocketException("Invalid frame sequence");
            }

            buffer.resize(oldSize + recvSize);
            if (flags & FRAME_FLAG_FIN)
            {
                // Unfragmented message complete.
                return buffer.size();
            }
            break;

        case FRAME_OP_CONT:
            if (oldSize == 0)
            {
                // Must be preceded by text or binary opcode.
                throw Poco::Net::WebSocketException("Invalid frame sequence");
            }

            buffer.resize(oldSize + recvSize);
            if (flags & FRAME_FLAG_FIN)
            {
                // Fragmented message complete.
                return buffer.size();
            }
            break;

        default:
            throw Poco::Net::WebSocketException("Invalid opcode");
        }
    }
}