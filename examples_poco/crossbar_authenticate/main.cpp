#include "autobahn.h"
#include "Poco/ConsoleChannel.h"
#include "Poco/Net/SocketReactor.h"
#include <iostream>

int main()
{
    Poco::Net::initializeNetwork();
    Poco::Logger::get("autobahn").setChannel(new Poco::ConsoleChannel());
    Poco::Net::SocketReactor reactor;
    autobahn::session ws;

    std::thread th([&]{ reactor.run(); });

    try {
        if (!ws.start(Poco::Net::SocketAddress("localhost", 8080)))
        {
            throw std::runtime_error("could not start");
        }

        ws.join("realm1", "wampcra", "peter", "secret1").get();
        //ws.join("realm1", "wampcra", "joe", "secret2").get();

        printf("joined the realm\n");

        auto result = ws.call("com.example.add2", {2, 3}).get();

        printf("we got the result and it is: %i\n", static_cast<int>(result));
    }
    catch (std::exception& e)
    {
        printf("exc: %s\n", e.what());
    }

    std::cin.ignore();
    reactor.stop();
    th.join();
}
