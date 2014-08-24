#ifndef SHA256ENGINE_H
#define SHA256ENGINE_H

#include <Poco/DigestEngine.h>
#include <Poco/Crypto/DigestEngine.h>


namespace util
{
    class SHA256Engine : public Poco::DigestEngine
    {
    public:
        enum
        {
            BLOCK_SIZE = 64,
            DIGEST_SIZE = 32
        };

        SHA256Engine();

        std::size_t digestLength() const override;
        void reset() override;
        const Poco::DigestEngine::Digest& digest() override;

    protected:
        void updateImpl(const void* data, std::size_t length) override;

    private:
        Poco::Crypto::DigestEngine m_engine;

        SHA256Engine(const SHA256Engine&);
        SHA256Engine& operator = (const SHA256Engine&);

    };
}

#endif