#ifndef CONTINUATION_H
#define CONTINUATION_H

#include <future>


namespace detail {

    template<typename F, typename W, typename R>
    struct helper
    {
        F f;
        W w;

        helper(F f, W w)
            : f(std::move(f))
            , w(std::move(w))
        {
        }

        helper(const helper& other)
            : f(std::move(const_cast<helper&>(other).f))
            , w(other.w)
        {
        }

        helper(helper&& other)
            : f(std::move(other.f))
            , w(std::move(other.w))
        {
        }

        helper& operator=(helper other)
        {
            f = std::move(other.f);
            w = std::move(other.w);
            return *this;
        }

        R operator()()
        {
            f.wait();
            return w(std::move(f));
        }
    };

}

namespace util
{
    template<typename F, typename W>
    auto then(F f, W w) -> std::future<decltype(w(std::move(f)))>
    {
        return std::async(std::launch::async, detail::helper<F, W, decltype(w(std::move(f)))>(std::move(f), std::move(w)));
    }
}

#endif