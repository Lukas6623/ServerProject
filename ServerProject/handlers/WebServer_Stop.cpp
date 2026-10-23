
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "../Platform.h"
#include "../WebServer.h"

#include <iostream>
#include <mutex>

void WebServer::stop()
{
    bool expected = true;

    if (!running.compare_exchange_strong(expected, false))
    {
        return;
    }

    // Stop listening and wake the thread blocked on the server socket.
    SOCKET socketToClose = serverSocket.exchange(INVALID_SOCKET);

    if (socketToClose != INVALID_SOCKET)
    {
        plat::shutdownBoth(socketToClose);
        closesocket(socketToClose);
    }

    // Wait until the listening thread has finished.
    if (serverThread.joinable())
    {
        serverThread.join();
    }

    // Interrupt active client connections.
    {
        std::lock_guard<std::mutex> lock(clientsMutex);

        for (SOCKET client : clients)
        {
            plat::shutdownBoth(client);
            closesocket(client);
        }
    }

    // Wait for client handlers to remove their sockets from the set.
    {
        std::unique_lock<std::mutex> lock(clientsMutex);

        clientsCv.wait(
            lock,
            [this]()
            {
                return clients.empty();
            }
        );
    }

    // Calls WSACleanup on Windows; does nothing on Linux.
    plat::cleanupNetwork();

    std::cout << "[WebServer] Stopped" << std::endl;
}
