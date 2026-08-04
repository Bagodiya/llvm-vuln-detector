#ifndef VULNDETECT_LATTICES_H
#define VULNDETECT_LATTICES_H

#include <cstdint>

namespace vuln {

// Per-location lattice for the free-state analysis. Unknown is the top element
// (nothing established yet); MaybeFreed is the danger-sticky join of Freed with
// anything else.
enum class FreeState : uint8_t {
  Unknown,
  Allocated,
  Freed,
  MaybeFreed,
};

// Per-location lattice for the null-state analysis. Same shape: Unknown on top,
// MaybeNull as the sticky join so a null on one path is never silently dropped.
enum class NullState : uint8_t {
  Unknown,
  NonNull,
  Null,
  MaybeNull,
};

inline FreeState meet(FreeState a, FreeState b) {
  if (a == b)
    return a;
  if (a == FreeState::MaybeFreed || b == FreeState::MaybeFreed)
    return FreeState::MaybeFreed;
  // Freed joined with anything else means "freed on at least one path".
  if (a == FreeState::Freed || b == FreeState::Freed)
    return FreeState::MaybeFreed;
  // Remaining cases pair Allocated with Unknown; neither path freed it.
  return FreeState::Allocated;
}

inline NullState meet(NullState a, NullState b) {
  if (a == b)
    return a;
  if (a == NullState::MaybeNull || b == NullState::MaybeNull)
    return NullState::MaybeNull;
  // Null joined with anything else means "null on at least one path", and is
  // downgraded from certain to possible.
  if (a == NullState::Null || b == NullState::Null)
    return NullState::MaybeNull;
  // Remaining cases pair NonNull with Unknown. Unknown is the absence of a
  // fact, so the join must not invent one: a pointer nobody has said anything
  // about does not become suspicious just by being merged with a pointer that
  // is known good. This mirrors meet(Allocated, Unknown) above.
  return NullState::NonNull;
}

} // namespace vuln

#endif
