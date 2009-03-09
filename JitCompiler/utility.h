#ifndef UTILITY_HPP_20080309
#define UTILITY_HPP_20080309

#include "llvm.h"
#include <vector>

// Poor man's Boost.Assign
namespace detail {
  template<typename T>
  struct vector_builder {
    typedef std::vector<T> container_type;
    
    vector_builder<T>& operator()(T val) {
      v_.push_back(val);
      return *this;
    }

    operator container_type() const {
      return v_;
    }
    
    container_type move() { // use RVO
      container_type res;
      res.swap(v_);
      return res;
    }
    
  private:
    container_type v_;
  };
}

template<typename T>
detail::vector_builder<T> vector_of(T val) {
  return detail::vector_builder<T>()(val);
}

// Syntactic sugar for LLVM constructors

llvm::ConstantInt* constant(int n) 
{
  using namespace llvm;
  return ConstantInt::get(APInt(32, n));
}

template<typename Builder>
llvm::Value* is_zero(Builder& builder, llvm::Value* val) {
  return builder.CreateICmpEQ(val, constant(0));
}

#endif
