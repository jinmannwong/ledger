#ifndef MATH_LOG_HPP
#define MATH_LOG_HPP
#include<cmath>

namespace fetch {
namespace math {

// TODO: place holder for more efficient implementation.
class Log {
public:
  double operator()(double const &x) {
    return std::log(x);
  }
};
  
};
};

#endif