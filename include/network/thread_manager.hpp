#ifndef NETWORK_THREAD_MANAGER_HPP
#define NETWORK_THREAD_MANAGER_HPP
#include "assert.hpp"
#include "mutex.hpp"
#include "logger.hpp"

#include <asio.hpp>
#include <functional>
#include <map>
namespace fetch {
namespace network {

class ThreadManager {
public:
  typedef std::function< void() > event_function_type;
  typedef uint32_t event_handle_type;
  
  ThreadManager(std::size_t threads=1) :
    number_of_threads_(threads)
  {
    fetch::logger.Debug("Creating thread manager");    
  }

  ~ThreadManager() 
  {
    fetch::logger.Debug("Destroying thread manager");
    Stop();    
  }
  
  virtual void Start()
  {
    if (threads_.size() == 0)
    {
      fetch::logger.Info("Starting thread manager");
      
      on_mutex_.lock();      
      for(auto &obj: on_before_start_)
      {
        obj.second();        
      }
      on_mutex_.unlock();      

      for(std::size_t i =0 ; i < number_of_threads_; ++i) {
        threads_.push_back( new std::thread(
            [this]()
            {
              io_service_.run();
            })
          );
      }
      
      on_mutex_.lock();
      for(auto &obj: on_after_start_)
      {
        obj.second();        
      }
      on_mutex_.unlock();      
    }
  }

  virtual void Stop() {
    if (threads_.size() != 0)
    {
      fetch::logger.Info("Stopping thread manager");
      on_mutex_.lock();      
      for(auto &obj: on_before_stop_)
      {
        obj.second();        
      }
      on_mutex_.unlock();      
      
      io_service_.stop();
      
      for(auto &thread: threads_) {
        thread->join();
        delete thread;        
      }
      
      threads_.clear();      

      on_mutex_.lock();
      for(auto &obj: on_after_stop_)
      {
        obj.second();        
      }
      on_mutex_.unlock();      
    }
  }  
  
  asio::io_service& io_service() 
  {
    return io_service_;
  }

  event_handle_type OnBeforeStart(event_function_type const &fnc) 
  {
    std::lock_guard< fetch::mutex::Mutex > lock( on_mutex_ );
    fetch::logger.Debug("Adding BeforeStart event listener ",next_id_, " from thread manager ");            
    on_before_start_[next_id_] = fnc;
    return next_id_++;    
  }
  
  event_handle_type OnAfterStart(event_function_type const &fnc) 
  {
    std::lock_guard< fetch::mutex::Mutex > lock( on_mutex_ );
    fetch::logger.Debug("Adding AfterStart event listener ",next_id_, " from thread manager ");            
    on_after_start_[next_id_] = fnc;
    return next_id_++;    
  }

  event_handle_type OnBeforeStop(event_function_type const &fnc) 
  {
    std::lock_guard< fetch::mutex::Mutex > lock( on_mutex_ );
    fetch::logger.Debug("Adding BeforeStop event listener ",next_id_, " from thread manager ");            
    on_before_stop_[next_id_] = fnc;
    return next_id_++;    
  }

  event_handle_type OnAfterStop(event_function_type const &fnc) 
  {
    fetch::logger.Debug("Adding AfterStop event listener ",next_id_, " from thread manager ");        
    std::lock_guard< fetch::mutex::Mutex > lock( on_mutex_ );
    on_after_stop_[next_id_] = fnc;
    return next_id_++;
  }

  void Off(event_handle_type handle) 
  {

    fetch::logger.Debug("Removing event listener ",handle, " from thread manager ");
//    std::lock_guard< fetch::mutex::Mutex > lock( on_mutex_ );
    
    if(on_before_start_.find( handle ) != on_before_start_.end() )
    {
      on_before_start_.erase( handle );
    }

    if(on_after_start_.find( handle ) != on_after_start_.end() )
    {
      on_after_start_.erase( handle );
    }

    if(on_before_stop_.find( handle ) != on_before_stop_.end() )
    {
      on_before_stop_.erase( handle );
    }        

    if(on_after_stop_.find( handle ) != on_after_stop_.end() )
    {
      on_after_stop_.erase( handle );
    }        
        
  }
  
private:
  std::size_t number_of_threads_ = 1;
  std::vector< std::thread* > threads_;  
  asio::io_service io_service_;
  std::map< event_handle_type, event_function_type > on_before_start_;
  std::map< event_handle_type, event_function_type > on_after_start_;  
  
  std::map< event_handle_type, event_function_type > on_before_stop_;
  std::map< event_handle_type, event_function_type > on_after_stop_;    
  event_handle_type next_id_ = 0;
  fetch::mutex::Mutex on_mutex_;  
};

};
};

#endif
