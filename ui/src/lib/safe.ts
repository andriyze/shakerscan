// Coerce a value that may be undefined / null / a non-array (e.g. a malformed or
// version-skewed API response) into an array, so a `.map()` in a render can never
// turn a bad response into a whole-page crash. See ui/src/lib/safe.test.mjs.
export function asArray<T>(value: T[] | null | undefined): T[] {
  return Array.isArray(value) ? value : []
}
