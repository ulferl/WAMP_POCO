#include "util/SHA256Engine.h"

using namespace util;


SHA256Engine::SHA256Engine() : m_engine("SHA256")
{

}


std::size_t SHA256Engine::digestLength() const
{
    return m_engine.digestLength();
}

void SHA256Engine::reset()
{
    m_engine.reset();
}

const Poco::DigestEngine::Digest& SHA256Engine::digest()
{
    return m_engine.digest();
}

void SHA256Engine::updateImpl(const void* data, std::size_t length)
{
    m_engine.update(data, length);
}