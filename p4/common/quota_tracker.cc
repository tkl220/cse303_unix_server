// http://www.cplusplus.com/reference/ctime/time/ is helpful here
#include <deque>
#include <shared_mutex>
#include <mutex>
#include <thread>
#include <atomic>
#include <utility>
#include <time.h>

#include "quota_tracker.h"

/// quota_tracker::Internal is the class that stores all the members of a
/// quota_tracker object. To avoid pulling too much into the .h file, we are
/// using the PIMPL pattern
/// (https://www.geeksforgeeks.org/pimpl-idiom-in-c-with-examples/)
struct quota_tracker::Internal {
  /// An event is a timestamped amount.  We don't care what the amount
  /// represents, because the code below will only sum the amounts in a
  /// collection of events and compare it against a quota.
  struct event {
    /// The time at which the request was made
    time_t when;

    /// The amount of resource consumed at the above time
    size_t amnt;
  };
  mutable std::shared_mutex mtx;
  std::deque<quota_tracker::Internal::event> events;
  size_t q_amt;
  size_t max;
  double dur;

  /// Construct the Internal object
  ///
  /// @param amount   The maximum amount of service
  /// @param duration The time during the service maximum can be spread out
  Internal(size_t amount, double duration) : max(amount), dur(duration){}
};

/// Construct an object that limits usage to quota_amount per quota_duration
/// seconds
///
/// @param amount   The maximum amount of service
/// @param duration The time during the service maximum can be spread out
quota_tracker::quota_tracker(size_t amount, double duration)
    : fields(new Internal(amount, duration)) {}

/// Construct a quota_tracker from another quota_tracker
///
/// @param other The quota tracker to use to build a new quota tracker
quota_tracker::quota_tracker(const quota_tracker &other) : fields(new Internal(other.fields->max, other.fields->dur)) {
  // TODO: You'll want to figure out how to make a copy constructor for this
  other.fields->mtx.lock_shared();
  // do we need to copy the actual events? or is this okay?
  this->fields->events = other.fields->events;
  other.fields->mtx.unlock();
}

/// Destruct a quota tracker
quota_tracker::~quota_tracker() = default;

/// Decides if a new event is permitted.  The attempt is allowed if it could
/// be added to events, while ensuring that the sum of amounts for all events
/// with (time > now-q_dur), is less than q_amnt.
///
/// @param amount The amount of the new request
///
/// @returns True if the amount could be added without violating the quota
bool quota_tracker::check(size_t amount) {
  this->fields->mtx.lock();
  time_t cur_time;
  time(&cur_time);
  for (size_t i = 0; i < this->fields->events.size(); i++) {
    if (difftime(cur_time, this->fields->events[i].when) > this->fields->dur) {
      this->fields->events.erase(this->fields->events.begin() + i--);
    }
  }
  if(this->fields->q_amt + amount > this->fields->max) {
    this->fields->mtx.unlock();
    return false;
  }
  this->fields->mtx.unlock();
  return true;
}

/// Actually add a new event to the quota tracker
void quota_tracker::add(size_t amount) {
  //if(!check(amount)) return;
  this->fields->mtx.lock();
  this->fields->q_amt += amount;
  time_t t;
  time(&t);
  quota_tracker::Internal::event evnt = {t, amount};
  this->fields->events.push_back(evnt);
  this->fields->mtx.unlock();
}